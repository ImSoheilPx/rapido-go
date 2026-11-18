// Package sshvpn is an SSH-server inbound: an SSH transport
// (golang.org/x/crypto/ssh, already a dependency for this panel's own node
// management, internal/sshexec) whose authenticated channels carry proxy
// traffic - TCP through RFC 4254 "direct-tcpip" channels, UDP through the
// same session over a per-client local UDP listener the client's SOCKS
// layer talks to (the model ssh -D dynamic forwarding established: a
// "forwarded-tcpip" channel to the well-known UDP relay port below).
//
// Unlike every other package under internal/nodecore this is NOT a fork of
// a sing-box inbound - sing-box itself has no SSH server at all, only a
// client outbound (protocol/ssh/outbound.go, which cannot even carry UDP:
// its ListenPacket returns os.ErrInvalid). So this package owns its whole
// protocol surface:
//
//   - TCP: a client opens a direct-tcpip channel per connection; the
//     channel is routed exactly like a trojan connection is.
//
//   - UDP: a client that wants UDP opens ONE direct-tcpip channel to
//     udpRelayLocalAddr (127.0.0.2:1 - never routable from outside the
//     SSH session itself). The channel then speaks the sing-box UoT
//     wire format (github.com/sagernet/sing/common/uot: a short request
//     header followed by length-framed packets), the same format
//     sing-box clients already speak for every TCP-carried UDP relay -
//     so a sing-box/NekoBox client with a "uot" toggle and an OpenSSH
//     client through a UoT-aware SOCKS shim both land on one
//     implementation, with no second protocol to maintain.
//
// Host keys: generated per inbound at Start, never persisted - a node
// restart changes the server's host key, which is exactly what a real
// SSH server behind a load balancer without a shared host key behaves
// like. Clients that pin host keys will need the new fingerprint; the
// subscription never carries one (matching the sing-box outbound's own
// empty-host-key-list behaviour, which accepts any host key).
//
// Users: the standard three additions every fork in this package makes -
// UpdateUsers on a running listener (an atomically swapped map checked
// per authentication attempt; established channels are unaffected until
// they end), per-user byte counting on every channel, and userkey.Key
// identities so a mid-session user-list swap can never bill a channel to
// the wrong user.
//
// Re-sync golang.org/x/crypto/ssh on every dependency upgrade; the wire
// surface used here (direct-tcpip, PasswordCallback, channel accept
// loop) has been stable across every x/crypto release to date.
package sshvpn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/ssh"

	"github.com/legendary1205/rapido-go/internal/nodecore/traffic"
	"github.com/legendary1205/rapido-go/internal/nodecore/userkey"
)

const TypeSSHVPN = "sshvpn"

// udpRelayAddr is the in-session address a client's UDP-over-SSH channel
// targets. 127.0.0.2:1 - a loopback address nothing outside the SSH session
// can ever route to, so the only way to reach this branch is an
// authenticated channel that explicitly named it. A direct-tcpip channel to
// any other address is an ordinary TCP proxy request.
var udpRelayAddr = M.ParseSocksaddr("127.0.0.2:1")

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, TypeSSHVPN, NewInbound)
}

// InboundOptions is this package's own options shape (see the package doc
// comment for why there is no sing-box upstream type to mirror): the shared
// ListenOptions every inbound takes, plus the per-user credential list.
type InboundOptions struct {
	option.ListenOptions
	Users []option.TrojanUser
}

// credential is one user of one UpdateUsers generation. Passwords here are
// the panel-issued random secrets (proxysettings.SSHSettings), verified with
// a constant-time compare per authentication attempt.
type credential struct {
	key      *userkey.Key
	password string
}

// userList is an immutable published generation: built once, never edited,
// swapped atomically by UpdateUsers. authFn is what ssh.ServerConfig's
// PasswordCallback closes over.
type userList struct {
	byName map[string]credential
}

func (l *userList) lookup(name string) (credential, bool) {
	c, ok := l.byName[name]
	return c, ok
}

type Inbound struct {
	inbound.Adapter
	ctx        context.Context
	router     adapter.ConnectionRouterEx
	logger     logger.ContextLogger
	listener   *listener.Listener
	sshConfig  *ssh.ServerConfig
	users      atomic.Pointer[userList]
	hostKey    ssh.Signer
	trafficMgr *traffic.Manager
	conns      *traffic.ConnGroup
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	routerEx, ok := router.(adapter.ConnectionRouterEx)
	if !ok {
		return nil, E.New("sshvpn: router does not implement ConnectionRouterEx")
	}
	inb := &Inbound{
		Adapter:    inbound.NewAdapter(TypeSSHVPN, tag),
		ctx:        ctx,
		router:     routerEx,
		logger:     logger,
		trafficMgr: traffic.FromContext(ctx),
		conns:      traffic.ConnGroupFromContext(ctx),
	}
	inb.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inb,
	})
	if err := inb.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	return inb, nil
}

// UpdateUsers replaces the inbound's user list in place, on the
// already-running listener. Authentication attempts resolve against the
// latest generation; channels already established keep running untouched
// (an SSH password is only presented at session setup, never re-checked).
//
// A zero-length list publishes an empty map - every authentication attempt
// then fails, which is what "no users configured" must mean (the same
// no-users stance every other fork here takes).
func (h *Inbound) UpdateUsers(users []option.TrojanUser) error {
	for i, u := range users {
		if u.Password == "" {
			return E.New("sshvpn: missing password for user ", i)
		}
	}
	byName := make(map[string]credential, len(users))
	list := traffic.SharedList(h.conns, users)
	for i, u := range users {
		byName[u.Name] = credential{key: list.Keys[i], password: u.Password}
	}
	h.users.Store(&userList{byName: byName})
	traffic.SetPolicy(h.conns, h.Tag(), list.Policy)
	return nil
}

// Start generates the host key (first start only - a restart keeps it for
// the inbound's lifetime so established clients' known_hosts stay valid
// across user-list changes, which never rebuild the listener) and starts
// the TCP listener.
func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.hostKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return E.Cause(err, "sshvpn: generate host key")
		}
		der := x509.MarshalPKCS1PrivateKey(key)
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
		signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			return E.Cause(err, "sshvpn: parse host key")
		}
		h.hostKey = signer
	}
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.0",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			users := h.users.Load()
			if users == nil {
				return nil, E.New("sshvpn: no users configured")
			}
			cred, ok := users.lookup(conn.User())
			if !ok || !constantTimeEquals(cred.password, string(password)) {
				h.logger.WarnContext(h.ctx, "sshvpn: failed authentication for user ", conn.User(), " from ", conn.RemoteAddr())
				return nil, ssh.ErrNoAuth
			}
			perm := &ssh.Permissions{}
			// The user's identity rides the session through permissions -
			// the only per-session field x/crypto/ssh carries to the
			// channel layer. Extensions hold the key fields as strings.
			perm.Extensions = map[string]string{
				"user":        cred.key.Label,
				"name":        cred.key.Name,
				"fingerprint": fingerprintHex(cred.key.Fingerprint),
			}
			return perm, nil
		},
	}
	config.AddHostKey(h.hostKey)
	h.sshConfig = config
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

// NewConnection is the listener's ConnectionHandler entry: one TCP
// connection = one SSH session = many channels.
func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer traffic.CloseOnPanic(ctx, h.logger, conn, onClose)
	h.serve(ctx, conn, metadata, onClose)
}

func (h *Inbound) serve(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, h.sshConfig)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "sshvpn: connection closed: ", err)
		} else {
			h.logger.DebugContext(ctx, "sshvpn: ssh handshake failed from ", metadata.Source, ": ", err)
		}
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	perm := sconn.Permissions
	user := perm.Extensions["user"]
	name := perm.Extensions["name"]
	var fingerprint [32]byte
	if fp := perm.Extensions["fingerprint"]; fp != "" {
		decodeFingerprint(fp, &fingerprint)
	}

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		var req directTCPIPRequest
		if err := ssh.Unmarshal(newChan.ExtraData(), &req); err != nil {
			newChan.Reject(ssh.Prohibited, "invalid direct-tcpip request")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			h.logger.DebugContext(ctx, "sshvpn: channel accept failed: ", err)
			continue
		}
		go ssh.DiscardRequests(requests)
		destination := M.ParseSocksaddrHostPort(req.Host, uint16(req.Port))
		chanMeta := metadata
		chanMeta.Inbound = h.Tag()
		chanMeta.InboundType = h.Type()
		chanMeta.Destination = destination
		if name != "" {
			chanMeta.User = name
		}
		go h.serveChannel(ctx, channel, req.OriginatorPort, chanMeta, user, fingerprint)
	}
	// The SSH session ended: every channel it opened has already been
	// closed by x/crypto/ssh itself (a closed conn closes its channels),
	// and each channel's own onClose has run by now or will when its
	// router relay notices the EOF.
	if onClose != nil {
		onClose(err)
	}
}

// directTCPIPRequest is RFC 4254 section 7.2's channel open payload.
type directTCPIPRequest struct {
	Host           string
	Port           uint32
	OriginatorIP   string
	OriginatorPort uint32
}

func (h *Inbound) serveChannel(ctx context.Context, channel ssh.Channel, originatorPort uint32, metadata adapter.InboundContext, user string, fingerprint [32]byte) {
	chanConn := &channelConn{Channel: channel}
	source := metadata.Source
	if !source.IsValid() || !source.Addr.IsValid() {
		source = M.ParseSocksaddr("127.0.0.1:0")
	}
	source.Port = uint16(originatorPort)
	metadata.Source = source

	if metadata.Destination.Addr == udpRelayAddr.Addr && metadata.Destination.Port == udpRelayAddr.Port {
		h.logger.InfoContext(ctx, "[", user, "] inbound UoT packet connection")
		h.serveUoTChannel(ctx, chanConn, metadata, user, fingerprint)
		return
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	onClose := func(err error) { channel.Close() }
	onClose = h.conns.TrackAuthenticated(h.Tag(), user, fingerprint, chanConn, onClose)
	if h.trafficMgr != nil {
		onClose = h.trafficMgr.TrackClose(user, chanConn, h.listener.ListenOptions().ListenPort, onClose)
		chanConn = &channelConn{Channel: channel, wrapped: traffic.WrapConn(chanConn, user, h.trafficMgr)}
	}
	h.router.RouteConnectionEx(ctx, chanConn, metadata, onClose)
}

// channelConn adapts an ssh.Channel to net.Conn. SSH channels have no
// deadlines - the same limitation sing-box's own SSH outbound documents
// (chanConnWrapper) - so deadline calls return os.ErrInvalid rather than
// pretending.
type channelConn struct {
	ssh.Channel
	wrapped net.Conn
}

func (c *channelConn) Read(b []byte) (int, error) {
	if c.wrapped != nil {
		return c.wrapped.Read(b)
	}
	return c.Channel.Read(b)
}

func (c *channelConn) Write(b []byte) (int, error) {
	if c.wrapped != nil {
		return c.wrapped.Write(b)
	}
	return c.Channel.Write(b)
}

func (c *channelConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *channelConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

// SSH channels have no deadlines - the same stance sing-box's own SSH
// outbound takes (chanConnWrapper). Returning os.ErrInvalid rather than
// pretending keeps callers honest.
func (c *channelConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (c *channelConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (c *channelConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }

// constantTimeEquals compares two secrets without leaking length or prefix
// information - crypto/subtle's ConstantTimeCompare with a length guard.
func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

const hexDigits = "0123456789abcdef"

func fingerprintHex(fp [32]byte) string {
	out := make([]byte, 64)
	for i, b := range fp {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}

func decodeFingerprint(hex string, out *[32]byte) {
	if len(hex) != 64 {
		return
	}
	for i := 0; i < 32; i++ {
		hi := hexDigit(hex[i*2])
		lo := hexDigit(hex[i*2+1])
		if hi < 0 || lo < 0 {
			return
		}
		out[i] = byte(hi<<4 | lo)
	}
}

func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
