// Package sshvpn is an SSH-server inbound whose TCP channels carry proxy
// traffic through RFC 4254 direct-tcpip - rebuilt around one lesson every
// comparable project converged on (slipgate's StunTLS, serve2d, the
// ssh-plan writeups): a bare SSH listener puts the cleartext "SSH-2.0-"
// banner on the wire, which is a first-class DPI fingerprint, and Iranian
// operators in particular throttle recognized SSH flows. So this inbound
// serves TWO shapes on one port and picks per connection by peeking the
// first bytes, exactly like serve2d/sslh do:
//
//   - TLS ClientHello (0x16 0x03 ...) -> SSH-over-TLS: a real crypto/tls
//     server, the SSH session runs inside it. The banner never appears in
//     the clear; the flow is an ordinary TLS stream. SlipNet/HTTP
//     Injector/NetMod's "SSH over TLS / StunTLS" modes land here.
//
//   - cleartext "SSH-" banner -> plain SSH, for clients with no TLS mode
//     (and for the panel's own E2E tests). A DPI that recognizes it gets
//     exactly what it would get from any other SSH server - no worse.
//
// UDP is deliberately gone: the two UDP-over-SSH dialects this package
// once carried (badvpn udpgw and sing UoT) were the least stable part of
// the protocol on lossy Iranian paths - an SSH channel is a TCP stream,
// and tunneling UDP semantics over a throttled TCP flow compounds the
// loss. Clients that need UDP should use a QUIC-native protocol
// (hysteria2/tuic, both served by this panel) rather than this one.
//
// Everything else follows the standard fork pattern in this package:
// UpdateUsers hot-swap (an atomically replaced map consulted at each
// authentication attempt; established sessions untouched), per-user byte
// counting on every channel, userkey.Key identities so a mid-session
// user-list swap can never bill the wrong user, and an ephemeral
// per-inbound RSA-3072 host key (plus a self-signed TLS certificate when
// security=tls) that never touches disk.
//
// Re-sync golang.org/x/crypto/ssh on every dependency upgrade; the wire
// surface used here (direct-tcpip, PasswordCallback, channel accept
// loop) has been stable across every x/crypto release to date.
package sshvpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, TypeSSHVPN, NewInbound)
}

// InboundOptions is this package's own options shape (sing-box has no SSH
// server type to mirror): the shared ListenOptions, the per-user
// credential list, and the inbound's TLS material when security=tls.
type InboundOptions struct {
	option.ListenOptions
	Users []option.TrojanUser
	// Certificate/Key are PEM strings; empty means generate a self-signed
	// pair at first start (clients of this protocol expect and accept a
	// self-signed cert - they pin nothing).
	Certificate string
	Key         string
}

// credential is one user of one UpdateUsers generation. Passwords are the
// panel-issued random secrets, verified with a constant-time compare.
type credential struct {
	key      *userkey.Key
	password string
}

// userList is an immutable published generation: built once, never
// edited, swapped atomically by UpdateUsers.
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
	tlsConfig  *tls.Config
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
	if err := inb.initKeys(options); err != nil {
		return nil, err
	}
	return inb, nil
}

// initKeys generates (once) the SSH host key and the TLS material: the
// caller's PEM pair when given, else a self-signed certificate over the
// host key. Both live for the inbound's lifetime; user-list changes
// never rebuild them.
func (h *Inbound) initKeys(options InboundOptions) error {
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

	var tlsCert tls.Certificate
	if options.Certificate != "" && options.Key != "" {
		tlsCert, err = tls.X509KeyPair([]byte(options.Certificate), []byte(options.Key))
		if err != nil {
			return E.Cause(err, "sshvpn: parse TLS certificate/key")
		}
	} else {
		tlsCert, err = selfSignedCert(key)
		if err != nil {
			return E.Cause(err, "sshvpn: generate TLS certificate")
		}
	}
	h.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	return nil
}

// selfSignedCert mints a fresh leaf certificate over the host key. A
// CN/SAN of "localhost" is deliberate: clients of this transport pin
// nothing (SSH validates the SERVER's host key, not the TLS cert - the
// TLS layer is camouflage against DPI), and a name that resolves nowhere
// avoids telling a passive observer anything about this deployment.
func selfSignedCert(key *rsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// UpdateUsers replaces the inbound's user list in place, on the
// already-running listener. Authentication attempts resolve against the
// latest generation; channels already established keep running untouched
// (an SSH password is only presented at session setup, never re-checked).
// A zero-length list publishes an empty map - every attempt fails, which
// is what "no users configured" must mean.
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

// Start builds the SSH server config and starts the TCP listener.
func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.sshConfig = &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.0",
		// AEAD ciphers first: aes128-gcm is ~2x aes128-ctr in this
		// library (GCM gets the AES-NI hardware path, CTR does not) -
		// the live-path benchmark that motivated this measured 807 vs
		// 435 MB/s loopback. Order is a preference list; a client
		// without GCM still negotiates its best.
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes256-ctr",
			},
		},
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
	h.sshConfig.AddHostKey(h.hostKey)
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

// NewConnection is the listener's ConnectionHandler entry and the whole
// point of the redesign: one port, protocol picked per connection by the
// first bytes on the wire.
//
//	0x16 0x03 ...      TLS ClientHello -> SSH inside TLS (DPI-safe)
//	"S" "S" "H" "-"    cleartext banner -> plain SSH (legacy clients)
func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer traffic.CloseOnPanic(ctx, h.logger, conn, onClose)

	// Peek enough bytes to tell a TLS record from an SSH banner. A TLS
	// ClientHello always starts 0x16 (handshake) 0x03 (version major);
	// an SSH banner always starts "SSH-". Both fit in 4 bytes.
	br := bufio.NewReaderSize(conn, 4096)
	first, err := br.Peek(4)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	peeked := &peekedConn{Reader: br, Conn: conn}
	if first[0] == 0x16 && first[1] == 0x03 {
		h.logger.DebugContext(ctx, "sshvpn: TLS-wrapped SSH connection from ", metadata.Source)
		h.serve(ctx, tls.Server(peeked, h.tlsConfig), metadata, onClose)
		return
	}
	h.serve(ctx, peeked, metadata, onClose)
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
	if onClose != nil {
		onClose(nil)
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

	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	onClose := func(err error) { channel.Close() }
	onClose = h.conns.TrackAuthenticated(h.Tag(), user, fingerprint, chanConn, onClose)
	if h.trafficMgr != nil {
		onClose = h.trafficMgr.TrackClose(user, chanConn, h.listener.ListenOptions().ListenPort, onClose)
		chanConn = &channelConn{Channel: channel, wrapped: traffic.WrapConn(chanConn, user, h.trafficMgr)}
	}
	h.router.RouteConnectionEx(ctx, chanConn, metadata, onClose)
}

// peekedConn serves the buffered bytes first, then the raw connection -
// the standard trick for protocol sniffing without consuming the stream.
type peekedConn struct {
	*bufio.Reader
	net.Conn
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

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

func (c *channelConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (c *channelConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (c *channelConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }

// constantTimeEquals compares two secrets without leaking length or
// prefix information - crypto/subtle's ConstantTimeCompare with a
// length guard.
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
