// Package transport is the userspace WireGuard data path this panel's
// wireguard inbound is built on: a fork of sing-box v1.14.0's
// transport/wireguard stack device plus the sing-tun gVisor forwarders it
// leans on, re-homed here so the node binary gets them WITHOUT a build
// tag.
//
// Why a fork instead of importing upstream: sing-box gates its whole
// userspace stack behind `with_gvisor`, and this repo's node binaries are
// built with -tags with_utls only (docker/Dockerfile.panel) - importing
// sing-box/transport/wireguard would compile, then fail at runtime with
// tun.ErrGVisorNotIncluded. The gVisor packages themselves
// (github.com/sagernet/gvisor) are plain Go with no build tag, so the fork
// simply drops the tags. The alternative - adding with_gvisor to every
// build - would silently change what the panel and node binaries embed
// for a feature only this inbound needs.
//
// What was kept (upstream sing-box v1.14.0 transport/wireguard and
// sing-tun v0.9.0-beta.4, both under their own licenses - see
// LICENSES.md):
//   - device.go: the Device interface and System:false stack selection
//   - device_stack.go: the gVisor stack device (tun.Device-shaped; the
//     decrypted packet path Write() feeds into a gVisor stack whose
//     forwarders hand TCP/UDP/ICMP flows to a Handler)
//   - device_stack_gonet.go: DialTCPWithBind (client-mode dial through
//     the stack - used by the inbound's tests and by amnezia later)
//   - sing-tun's TCPForwarder/UDPForwarder/ICMPForwarder bodies, minus
//     the parts tied to a real tun (loopback rewrite, egress pool)
//
// What was changed beyond the re-home (each marked "rapido:" at the site):
//   - the stack device keeps its own copy of newGVisorStack rather than
//     calling tun.NewGVisorStackWithOptions, which is behind the same tag
//   - the handler type is this package's Handler (JudgeFlow accepts
//     everything; NewDNSPacket is a no-op - DNS hijack is a tun feature)
//   - endpoint.go adds Device() and ApplyPeers(): hot per-peer updates
//     through wireguard-go's public IpcSet, which upstream never exposes
//
// Kernel WireGuard (System:true) is deliberately NOT ported: a node in a
// container has no /dev/wg or CAP_NET_ADMIN, and the userspace path is
// the whole point of this inbound (see internal/nodecore/wg's own doc
// comment).
package transport

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

// defaultNIC is sing-tun's defaultNIC (1), restated because the
// constant itself lives in a with_gvisor-gated file upstream.
const defaultNIC tcpip.NICID = 1

// Handler receives the flows the gVisor stack pulls out of decrypted
// WireGuard packets. A trimmed copy of sing-tun's tun.Handler: the DNS
// hijack leg is a tun-only feature (JudgeFlow never returns
// ActionHijackDNS here, and NewDNSPacket is never called), so it stays in
// the interface only to keep the copied forwarder bodies verbatim.
type Handler interface {
	JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict
	NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter)
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

// stackDevice is sing-box's userspace "tun": wireguard-go's device hands
// it encrypted-side packets via Write, and it plays them into a gVisor
// stack whose transport handlers forward flows to Handler. No kernel tun,
// no NET_ADMIN - the architectural claim of this inbound.
type stackDevice struct {
	stack          *stack.Stack
	mtu            uint32
	events         chan wgTun.Event
	outbound       chan *stack.PacketBuffer
	packetOutbound chan *buf.Buffer
	done           chan struct{}
	closeOnce      sync.Once
	dispatcher     stack.NetworkDispatcher
	inet4Address   netip.Addr
	inet6Address   netip.Addr
	icmpForwarder  *icmpForwarder
	udpForwarder   *udpForwarder
}

func newStackDevice(options DeviceOptions) (*stackDevice, error) {
	tunDevice := &stackDevice{
		mtu:            options.MTU,
		events:         make(chan wgTun.Event, 1),
		outbound:       make(chan *stack.PacketBuffer, 256),
		packetOutbound: make(chan *buf.Buffer, 256),
		done:           make(chan struct{}),
	}
	// rapido: upstream calls tun.NewGVisorStackWithOptions, which is
	// behind with_gvisor; this is that function's body (sing-tun
	// stack_gvisor.go newGVisorStack, non-iOS branch) with the tag
	// dropped and the raw-endpoint/loopback options this device never
	// uses left out.
	//
	// rapido: AllowExternalLoopbackTraffic is enabled on both IP
	// protocols (upstream keeps it off). A peer's decrypted packet may
	// legitimately target 127.0.0.0/8 - e.g. split-tunnel clients
	// routing "everything" through the tunnel and panels co-hosting
	// services on loopback - and gVisor would otherwise drop those as
	// martian the moment they leave the WireGuard NIC, before the
	// forwarders ever see the flow. The server dials the destination
	// itself afterward, so this only stops the false-positive drop; it
	// does not grant the peer any new reachability.
	stackOptions := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	}
	ipStack := stack.New(stackOptions)
	if err := ipStack.CreateNICWithOptions(defaultNIC, (*wireEndpoint)(tunDevice), stack.NICOptions{}); err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	ipStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: defaultNIC},
	})
	if err := ipStack.SetSpoofing(defaultNIC, true); err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	if err := ipStack.SetPromiscuousMode(defaultNIC, true); err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultReceiveBufferSize,
		Max:     8 << 20,
	}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt); err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultSendBufferSize,
		Max:     6 << 20,
	}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt); err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	for _, prefix := range options.Address {
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addressFromAddr(prefix.Addr()),
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			tunDevice.inet4Address = prefix.Addr()
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			tunDevice.inet6Address = prefix.Addr()
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		if gErr := ipStack.AddProtocolAddress(defaultNIC, protoAddr, stack.AddressProperties{}); gErr != nil {
			return nil, E.New("parse local address ", protoAddr.AddressWithPrefix, ": ", gErr.String())
		}
	}
	tunDevice.stack = ipStack
	if options.Handler != nil {
		ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, newTCPForwarder(options.Context, ipStack, options.Handler).HandlePacket)
		udpFwd := newUDPForwarder(options.Context, ipStack, options.Handler, tun.UDPNatOptions{
			Timeout:   options.UDPTimeout,
			Shared:    true,
			Mapping:   options.UDPMapping,
			Filtering: options.UDPFiltering,
			MaxSize:   options.UDPNATMax,
		})
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
		tunDevice.udpForwarder = udpFwd
		icmpFwd := newICMPForwarder(ipStack, options.Handler, options.Logger)
		ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpFwd.HandlePacket)
		ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpFwd.HandlePacket)
		tunDevice.icmpForwarder = icmpFwd
	}
	return tunDevice, nil
}

// DialContext dials TCP (or UDP) from inside the stack - the client-mode
// half of the fork, used by the inbound's tests and by a future amnezia
// slice to exercise the server data path with a real wireguard-go peer.
func (w *stackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	addr := tcpip.FullAddress{
		NIC:  defaultNIC,
		Port: destination.Port,
		Addr: addressFromAddr(destination.Addr),
	}
	bind := tcpip.FullAddress{NIC: defaultNIC}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !w.inet4Address.IsValid() {
			return nil, E.New("missing IPv4 local address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = addressFromAddr(w.inet4Address)
	} else {
		if !w.inet6Address.IsValid() {
			return nil, E.New("missing IPv6 local address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = addressFromAddr(w.inet6Address)
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return DialTCPWithBind(ctx, w.stack, bind, addr, networkProtocol)
	case N.NetworkUDP:
		udpConn, err := gonet.DialUDP(w.stack, &bind, &addr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// ListenPacket binds a UDP socket inside the stack (client mode).
func (w *stackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind := tcpip.FullAddress{NIC: defaultNIC}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !w.inet4Address.IsValid() {
			return nil, E.New("missing IPv4 local address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = addressFromAddr(w.inet4Address)
	} else {
		if !w.inet6Address.IsValid() {
			return nil, E.New("missing IPv6 local address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = addressFromAddr(w.inet6Address)
	}
	return gonet.DialUDP(w.stack, &bind, nil, networkProtocol)
}

func (w *stackDevice) Inet4Address() netip.Addr { return w.inet4Address }
func (w *stackDevice) Inet6Address() netip.Addr { return w.inet6Address }

func (w *stackDevice) SetDevice(device *device.Device) {}

func (w *stackDevice) Start() error {
	if w.udpForwarder != nil {
		if err := w.udpForwarder.Start(); err != nil {
			return err
		}
	}
	w.events <- wgTun.EventUp
	return nil
}

func (w *stackDevice) File() *os.File { return nil }

func (w *stackDevice) Read(bufs [][]byte, sizes []int, offset int) (count int, err error) {
	select {
	case packet, ok := <-w.outbound:
		if !ok {
			return 0, os.ErrClosed
		}
		defer packet.DecRef()
		var copyN int
		for _, view := range packet.AsSlices() {
			copyN += copy(bufs[0][offset+copyN:], view)
		}
		sizes[0] = copyN
		return 1, nil
	case packet := <-w.packetOutbound:
		defer packet.Release()
		sizes[0] = copy(bufs[0][offset:], packet.Bytes())
		return 1, nil
	case <-w.done:
		return 0, os.ErrClosed
	}
}

func (w *stackDevice) Write(bufs [][]byte, offset int) (count int, err error) {
	for _, b := range bufs {
		b = b[offset:]
		if len(b) == 0 {
			continue
		}
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(b) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(b),
		})
		// rapido: wireguard-go's per-peer receiver routines race device
		// Close() - a packet decrypted in flight can reach Write after the
		// stack is torn down and the dispatcher detached. Drop it instead
		// of nil-dereferencing (upstream never sees this because a real
		// tun device outlives the stack).
		if w.dispatcher != nil {
			w.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
		}
		packetBuffer.DecRef()
		count++
	}
	return
}

func (w *stackDevice) Flush() error { return nil }

func (w *stackDevice) MTU() (int, error) { return int(w.mtu), nil }

func (w *stackDevice) Name() (string, error) { return "rapido-wg", nil }

func (w *stackDevice) Events() <-chan wgTun.Event { return w.events }

func (w *stackDevice) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		close(w.events)
		// rapido: detach before tearing the stack down; late decrypted
		// packets then take the nil-guard in Write instead of racing a
		// dying dispatcher.
		(*wireEndpoint)(w).Detach()
		if w.icmpForwarder != nil {
			w.icmpForwarder.Close()
		}
		if w.udpForwarder != nil {
			_ = w.udpForwarder.Close()
		}
		w.stack.Close()
		for _, endpoint := range w.stack.CleanupEndpoints() {
			endpoint.Abort()
		}
		w.stack.Wait()
	})
	return nil
}

func (w *stackDevice) BatchSize() int { return 1 }

var _ stack.LinkEndpoint = (*wireEndpoint)(nil)

type wireEndpoint stackDevice

func (ep *wireEndpoint) MTU() uint32 { return ep.mtu }

func (ep *wireEndpoint) SetMTU(mtu uint32) {}

func (ep *wireEndpoint) MaxHeaderLength() uint16 { return 0 }

func (ep *wireEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (ep *wireEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

func (ep *wireEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *wireEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

// rapido: Close() nulls the dispatcher so a late Write from a wireguard-go
// receiver routine drops the packet instead of using a dead dispatcher (see
// stackDevice.Write).
func (ep *wireEndpoint) Detach() {
	ep.dispatcher = nil
}

func (ep *wireEndpoint) IsAttached() bool { return ep.dispatcher != nil }

func (ep *wireEndpoint) Wait() {}

func (ep *wireEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *wireEndpoint) AddHeader(buffer *stack.PacketBuffer) {}

func (ep *wireEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool { return true }

func (ep *wireEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		packetBuffer.IncRef()
		select {
		case <-ep.done:
			return 0, &tcpip.ErrClosedForSend{}
		case ep.outbound <- packetBuffer:
		}
	}
	return list.Len(), nil
}

func (ep *wireEndpoint) Close() {}

func (ep *wireEndpoint) SetOnCloseAction(f func()) {}

// Device is the tun.Device-shaped handle wireguard-go needs (upstream
// sing-box device.go, System:false arm only).
type Device interface {
	wgTun.Device
	N.Dialer
	Start() error
	SetDevice(device *device.Device)
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
}

// DeviceOptions mirrors upstream's, minus every field the userspace path
// never reads (InterfaceFinder/CreateDialer/NetworkMonitor are for the
// kernel path and the egress pool).
type DeviceOptions struct {
	Context      context.Context
	Logger       HandlerLogger
	Handler      Handler
	UDPTimeout   time.Duration
	ICMPTimeout  time.Duration
	UDPMapping   tun.NATMapping
	UDPFiltering tun.NATFiltering
	UDPNATMax    uint32
	Name         string
	MTU          uint32
	Address      []netip.Prefix
}

// HandlerLogger is the one method of sing's logger.Logger the ICMP
// forwarder body needs; satisfied by sing-box's log.ContextLogger (whose
// Error takes ...any, same as this).
type HandlerLogger interface {
	Error(msg ...any)
}
