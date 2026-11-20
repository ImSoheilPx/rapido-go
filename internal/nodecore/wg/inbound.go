// Package wg is a fully-userspace WireGuard inbound: real WireGuard
// peers terminated by wireguard-go over a gVisor network stack, entirely
// in process - no kernel module, no tun device, no NET_ADMIN, so a node
// in an unprivileged container serves it exactly as well as a host
// install (the architectural claim; see internal/nodecore/wg/transport's
// own doc comment for where the stack came from).
//
// Model (plan §2, vpn-ui parity):
//   - one inbound = one UDP port = one subnet (default 10.7.0.0/24);
//     multi-port is refused at the panel, and the node builder only ever
//     hands this inbound one port
//   - server = subnet's first usable host (.1); each user gets a /32
//     DERIVED from the panel's users.id: addr = subnet.Addr() | Index.
//     Derived, never stored - proxies.settings stays inbound-agnostic
//     (two wireguard inbounds with different subnets share the same
//     per-user key material), and users.id is unique and stable across
//     renames, so the address is too
//   - per-user credential = a Curve25519 keypair in proxies.settings
//     (proxysettings.WireguardSettings); the public key IS the WireGuard
//     peer public key
//
// Data path: wireguard-go decrypts peer packets into the gVisor stack,
// whose forwarders hand each TCP/UDP/ICMP flow to this inbound's Handler
// implementation with source = the peer's tunnel IP. The rapido delta
// over sing-box's own endpoint handler is one line: source.Addr is looked
// up in the byAddr table and stamped onto metadata.User before
// RouteConnectionEx, so Core Config routing rules see the peer's owner
// like any inbound's authenticated user.
//
// Accounting is NOT per-conn (there are no per-user conns to wrap - the
// userspace tunnel is one encrypted UDP socket): a poller reads the
// device's IpcGet() every 30s and feeds per-peer counter deltas to
// traffic.Manager (rx_bytes = bytes received FROM the peer = upload,
// tx_bytes = bytes sent TO the peer = download - verified against
// wireguard-go's receive.go/send paths). A re-added peer's counters
// restart at zero; a delta that goes backwards is taken at face value
// (new < old -> use new), which both handles that reset and keeps a
// device restart from double-billing.
//
// Hot UpdateUsers = IpcSet add/remove/replace_allowed_ips diffs on the
// live device. Removing a peer destroys its key material: the peer's
// in-flight flows die with it and it can never handshake again - that IS
// the hard revoke, the same semantics every other forked inbound here
// gives a removed user.
package wg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/legendary1205/rapido-go/internal/nodecore/traffic"
	"github.com/legendary1205/rapido-go/internal/nodecore/userkey"
	"github.com/legendary1205/rapido-go/internal/nodecore/wg/transport"
)

// TypeWireguard is the registry type string. The PANEL's protocol string
// is "wireguard"; the registry string says wgvpn because sing-box's own
// constants namespace has TypeWireGuard ("wireguard") reserved for the
// endpoint/outbound, and a registry collision would make an inbound
// options blob parse as the wrong shape.
const TypeWireguard = "wgvpn"

// DefaultSubnet is the panel-default tunnel space (10.7.0.0/24 - vpn-ui's
// wg base; awg will take 10.8.0.0.24-style space of its own).
const DefaultSubnet = "10.7.0.0/24"

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, TypeWireguard, NewInbound)
}

// InboundOptions is the node-side shape built by cmd/node's buildOptions.
type InboundOptions struct {
	option.ListenOptions
	Users      []WgUser
	Subnet     string `json:"subnet,omitempty"`
	MTU        uint32 `json:"mtu,omitempty"`
	PrivateKey string `json:"private_key"`
}

// WgUser: Name is the panel account name (the traffic.Manager key),
// PublicKey the peer's WireGuard public key (base64 std, 32 bytes),
// PresharedKey optional, Index the stable per-user integer (panel
// users.id) the /32 is derived from.
type WgUser struct {
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Index        uint32 `json:"index"`
}

// userList is one immutable published generation (sshvpn/mtproto shape).
type userList struct {
	byAddr map[netip.Addr]string  // tunnel IP -> user label
	byPub  map[string]userkeyCred // pubkey hex -> credential
	order  []string
	list   []WgUser
}

type userkeyCred struct {
	key   *userkey.Key
	label string
}

// Inbound is the wireguard endpoint plus rapido's user accounting.
type Inbound struct {
	inbound.Adapter
	ctx            context.Context
	router         adapter.ConnectionRouterEx
	logger         logger.ContextLogger
	trafficMgr     *traffic.Manager
	conns          *traffic.ConnGroup
	endpoint       *transport.Endpoint
	users          atomic.Pointer[userList]
	updateMu       sync.Mutex
	lastCounters   map[string]peerCounters
	pollStop       chan struct{}
	pollDone       chan struct{}
	subnet         netip.Prefix
	mtu            uint32
	localAddresses []netip.Prefix
}

// peerCounters is one poller snapshot per peer.
type peerCounters struct {
	rx, tx uint64
}

// AddrForIndex derives user Index's tunnel IP inside subnet: the network
// address OR'd with the index (10.7.0.0/24 + 5 -> 10.7.0.5). Panel and
// node both compute the address with this same function - the panel for
// links/wg-conf, the node for allowed_ip and user attribution - so they
// can never disagree.
func AddrForIndex(subnet netip.Prefix, index uint32) netip.Addr {
	base := subnet.Addr().As4()
	base[3] |= byte(index)
	base[2] |= byte(index >> 8)
	return netip.AddrFrom4(base)
}

// HostsOfSubnet is how many addresses fit in the subnet minus network and
// broadcast: the /24 the panel defaults to gives 254, of which .1 is the
// server and .2.. .253 are users (Index validated 2..hosts-1).
func HostsOfSubnet(subnet netip.Prefix) uint32 {
	bits := 32 - subnet.Bits()
	if bits >= 32 {
		return 0
	}
	return (uint32(1) << bits) - 2
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	routerEx, ok := router.(adapter.ConnectionRouterEx)
	if !ok {
		return nil, E.New("wg: router does not implement ConnectionRouterEx")
	}
	if options.Subnet == "" {
		options.Subnet = DefaultSubnet
	}
	subnet, err := parseSubnet(options.Subnet)
	if err != nil {
		return nil, err
	}
	serverAddr := serverAddress(subnet)
	inb := &Inbound{
		Adapter:        inbound.NewAdapter(TypeWireguard, tag),
		ctx:            ctx,
		router:         routerEx,
		logger:         logger,
		trafficMgr:     traffic.FromContext(ctx),
		conns:          traffic.ConnGroupFromContext(ctx),
		lastCounters:   map[string]peerCounters{},
		pollStop:       make(chan struct{}),
		pollDone:       make(chan struct{}),
		subnet:         subnet,
		mtu:            options.MTU,
		localAddresses: []netip.Prefix{netip.PrefixFrom(serverAddr, 32)},
	}
	if err := inb.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	endpoint, err := transport.NewEndpoint(transport.EndpointOptions{
		Context:    ctx,
		Logger:     logger,
		Handler:    inb,
		UDPTimeout: C.UDPTimeout,
		Address:    inb.localAddresses,
		PrivateKey: options.PrivateKey,
		ListenPort: options.ListenOptions.ListenPort,
		MTU:        options.MTU,
	})
	if err != nil {
		return nil, err
	}
	inb.endpoint = endpoint
	return inb, nil
}

// parseSubnet enforces the IPv4 /16-/24 window the panel validates too.
func parseSubnet(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("wg: invalid subnet %q: %w", s, err)
	}
	if !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("wg: subnet %q must be IPv4", s)
	}
	if prefix.Bits() < 16 || prefix.Bits() > 24 {
		return netip.Prefix{}, fmt.Errorf("wg: subnet %q must be between /16 and /24", s)
	}
	return prefix.Masked(), nil
}

// serverAddress is the subnet's first usable host: the .1 a client's
// wg-quick conf points its AllowedIPs-adjacent traffic at.
func serverAddress(subnet netip.Prefix) netip.Addr {
	return AddrForIndex(subnet, 1)
}

// UpdateUsers replaces the peer set on the running device. Validation is
// all-or-nothing: one bad user fails the call with nothing applied.
func (h *Inbound) UpdateUsers(users []WgUser) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()

	shared := traffic.SharedList(h.conns, users)
	byAddr := make(map[netip.Addr]string, len(users))
	byPub := make(map[string]userkeyCred, len(users))
	order := make([]string, 0, len(users))
	peers := make([]transport.PeerConfig, 0, len(users))
	maxIndex := HostsOfSubnet(h.subnet)
	seenIndex := make(map[uint32]bool, len(users))
	for i, u := range users {
		if u.Name == "" {
			return fmt.Errorf("wg: user %d has no name", i)
		}
		if _, dup := byPub[u.PublicKey]; dup || u.PublicKey == "" {
			return fmt.Errorf("wg: user %q: missing or duplicate public key", u.Name)
		}
		if u.Index < 2 || u.Index > maxIndex {
			return fmt.Errorf("wg: user %q: index %d does not fit subnet %s (2..%d)", u.Name, u.Index, h.subnet, maxIndex)
		}
		if seenIndex[u.Index] {
			return fmt.Errorf("wg: user %q: duplicate index %d", u.Name, u.Index)
		}
		seenIndex[u.Index] = true
		addr := AddrForIndex(h.subnet, u.Index)
		label := u.Name
		key := shared.Keys[i]
		if key != nil && key.Label != "" {
			label = key.Label
		}
		peer, err := transport.NewPeerConfig(u.PublicKey, u.PresharedKey, []netip.Prefix{netip.PrefixFrom(addr, 32)})
		if err != nil {
			return fmt.Errorf("wg: user %q: %w", u.Name, err)
		}
		byAddr[addr] = label
		byPub[peer.PublicKeyHex()] = userkeyCred{key: key, label: label}
		order = append(order, label)
		peers = append(peers, peer)
	}

	next := &userList{byAddr: byAddr, byPub: byPub, order: order, list: users}

	// Hot path: diff against the previous generation. A removed peer's
	// counters die with it, so its lastCounters entry goes too (a re-add
	// starts from zero - the poller's new<old guard covers any race).
	if h.endpoint != nil && h.endpoint.Device() != nil {
		var ipc strings.Builder
		prev := h.users.Load()
		prevByPub := map[string]transport.PeerConfig{}
		if prev != nil {
			for _, u := range prev.list {
				if peer, err := transport.NewPeerConfig(u.PublicKey, u.PresharedKey, []netip.Prefix{netip.PrefixFrom(AddrForIndex(h.subnet, u.Index), 32)}); err == nil {
					prevByPub[peer.PublicKeyHex()] = peer
				}
			}
		}
		nextByPub := map[string]transport.PeerConfig{}
		for _, p := range peers {
			nextByPub[p.PublicKeyHex()] = p
		}
		for pub := range prevByPub {
			if _, keep := nextByPub[pub]; !keep {
				ipc.WriteString("\npublic_key=" + pub + "\nremove=true")
				delete(h.lastCounters, pub)
			}
		}
		for _, p := range peers {
			if _, existed := prevByPub[p.PublicKeyHex()]; !existed {
				ipc.WriteString(p.GenerateIpcLines())
			}
		}
		if ipc.Len() > 0 {
			if err := h.endpoint.Device().IpcSet(ipc.String()); err != nil {
				return fmt.Errorf("wg: apply users: %w", err)
			}
		}
		// Unchanged peers with a different address would need a
		// replace_allowed_ips re-issue; indexes are stable (users.id),
		// so the add/remove diff above is the whole story in practice.
	}

	h.users.Store(next)
	traffic.SetPolicy(h.conns, h.Tag(), shared.Policy)
	return nil
}

// Start brings the endpoint up, applies the peer set and starts the
// accounting poller.
func (h *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		if err := h.endpoint.Start(); err != nil {
			return err
		}
		if h.endpoint.Device() != nil {
			users := h.users.Load()
			if users != nil {
				peers := make([]transport.PeerConfig, 0, len(users.list))
				for _, u := range users.list {
					if peer, err := transport.NewPeerConfig(u.PublicKey, u.PresharedKey, []netip.Prefix{netip.PrefixFrom(AddrForIndex(h.subnet, u.Index), 32)}); err == nil {
						peers = append(peers, peer)
					}
				}
				if err := h.endpoint.ApplyPeers(peers, true); err != nil {
					return err
				}
			}
		}
		go h.pollCounters(h.ctx)
	}
	return nil
}

// Close stops the poller and tears the device down.
func (h *Inbound) Close() error {
	close(h.pollStop)
	<-h.pollDone
	return h.endpoint.Close()
}

// pollCounters feeds per-peer traffic deltas to the manager every 30s.
func (h *Inbound) pollCounters(ctx context.Context) {
	defer close(h.pollDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.pollStop:
			return
		case <-ticker.C:
			h.pollOnce()
		}
	}
}

// PollForTest runs one accounting poll now - the external test package's
// way past the 30s ticker (see nodecore.PollWireguardUsage).
func (h *Inbound) PollForTest() { h.pollOnce() }

// pollOnce is one accounting tick, split out so tests can drive it.
func (h *Inbound) pollOnce() {
	device := h.endpoint.Device()
	users := h.users.Load()
	if device == nil || users == nil {
		return
	}
	raw, err := device.IpcGet()
	if err != nil {
		h.logger.Error("wg: read counters: ", err)
		return
	}
	for pub, counters := range parseIpcGet(raw) {
		cred, known := users.byPub[pub]
		if !known || h.trafficMgr == nil {
			// Not one of ours (shouldn't happen) or nothing to
			// feed: still remember the snapshot so a later add
			// doesn't bill the peer's whole history.
			h.lastCounters[pub] = counters
			continue
		}
		prev := h.lastCounters[pub]
		up := delta(prev.rx, counters.rx)
		down := delta(prev.tx, counters.tx)
		if up > 0 || down > 0 {
			h.trafficMgr.Add(cred.label, up, down)
		}
		h.lastCounters[pub] = counters
	}
}

// delta returns new-old, or new when the counter restarted at zero.
func delta(old, new uint64) int64 {
	if new < old {
		return int64(new)
	}
	return int64(new - old)
}

// parseIpcGet splits IpcGet() output into per-peer counters, keyed by
// public key hex. Lines: public_key=, rx_bytes=, tx_bytes=, ... (verified
// against wireguard-go device/uapi.go IpcGetOperation).
func parseIpcGet(raw string) map[string]peerCounters {
	out := map[string]peerCounters{}
	var pub string
	var counters peerCounters
	flush := func() {
		if pub != "" {
			out[pub] = counters
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			flush()
			pub = value
			counters = peerCounters{}
		case "rx_bytes":
			fmt.Sscanf(value, "%d", &counters.rx)
		case "tx_bytes":
			fmt.Sscanf(value, "%d", &counters.tx)
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------------------
// tun.Handler implementation (the rapido delta: metadata.User from the
// source tunnel IP, then the router - copied from sing-box
// protocol/wireguard/endpoint.go:226-268 with the DNS leg dropped)
// ---------------------------------------------------------------------------

// JudgeFlow accepts everything: rapido has no tun flow accounting, and
// the router's own rules are applied per-connection below.
func (h *Inbound) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket is a no-op: DNS hijack is a tun feature this stack never
// triggers (JudgeFlow never returns ActionHijackDNS).
func (h *Inbound) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
}

// NewConnectionEx routes one decrypted TCP flow.
func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Network = N.NetworkTCP
	metadata.Source = source
	// THE rapido delta over sing-box's own endpoint handler: attribute
	// the flow to the peer's owner before the router sees it, the same
	// metadata.User every authenticated inbound stamps.
	if users := h.users.Load(); users != nil {
		if user, ok := users.byAddr[source.Addr]; ok {
			metadata.User = user
		}
	}
	for _, localPrefix := range h.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound wireguard connection from ", source, " as ", metadata.User)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

// NewPacketConnectionEx routes one decrypted UDP flow.
func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	if users := h.users.Load(); users != nil {
		if user, ok := users.byAddr[source.Addr]; ok {
			metadata.User = user
		}
	}
	for _, localPrefix := range h.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
			break
		}
	}
	h.logger.InfoContext(ctx, "inbound wireguard packet connection from ", source, " as ", metadata.User)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
