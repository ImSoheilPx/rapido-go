// Package mtproto is a FakeTLS-camouflaged MTProto proxy inbound built on
// the vendored mtg (third_party/mtg, upstream github.com/9seconds/mtg/v2
// plus the TryDispatch patch - see that tree's PATCHES.md). It is a pure
// userspace TCP relay: no tunnel IPs, no UDP, no kernel anything - the
// smallest inbound surface this panel serves, and the only one whose
// client is the Telegram app itself rather than a generic proxy client.
//
// One inbound = one TCP port = N users, each user one 16-byte secret
// stored as 32 hex chars in proxies.settings (the "ee"/domain composition
// happens at link time, see subscription.mtprotoLink). Upstream mtg's
// Proxy is single-secret by construction, so this inbound owns one
// mtglib.Proxy PER USER - all sharing one Network, one AntiReplayCache and
// one event stream - and picks the user per connection with
// mtglib.TryDispatch, which replays the ClientHello bytes to each
// candidate key's HMAC check and hands back a rewound conn the matched
// Proxy's own ServeConn consumes untouched.
//
// Everything else follows the standard fork pattern (see
// internal/nodecore/sshvpn): UpdateUsers hot-swap with established streams
// untouched, per-user byte counting on the client-side conn (covering
// FakeTLS + obfuscated2 + relay payload - exactly the bytes telemt's
// user_octets_from_client/_to_client counted in the panel this codebase
// replaced), userkey.Key identities, and a hard revoke: a removed user's
// secret is dropped from the dispatch table, so it can never handshake
// again, while its established relay runs to completion.
//
// v1 dials Telegram DCs directly through mtg's own Network (same as mtg
// standalone). Routing those dials through Core Config outbounds is a
// documented follow-up; the Network interface is the seam.
package mtproto

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/ipblocklist"
	mtglogger "github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/legendary1205/rapido-go/internal/nodecore/traffic"
	"github.com/legendary1205/rapido-go/internal/nodecore/userkey"
)

const TypeMtproto = "mtproto"

// DefaultTlsDomain is the FakeTLS SNI a listener emulates when the panel
// left mtproto_tls_domain NULL - vpn-ui parity (its tlsDomain default).
const DefaultTlsDomain = "www.google.com"

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, TypeMtproto, NewInbound)
}

// InboundOptions is this package's own options shape: sing-box has no
// MTProto server to mirror. TlsDomain is the FakeTLS SNI the whole
// listener emulates - every user's secret composes with the same host at
// link time ("ee" + secret + hex(domain)), and every ClientHello must
// carry it in its SNI list or the digest check never even runs.
type InboundOptions struct {
	option.ListenOptions
	Users     []MtprotoUser
	TlsDomain string
}

// MtprotoUser: Name is the panel account name (the traffic.Manager key),
// Secret is 32 lowercase hex chars (16 bytes) stored verbatim in
// proxies.settings - inbound-independent, unlike a tunnel IP.
type MtprotoUser struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// credential is one user of one UpdateUsers generation.
type credential struct {
	key    *userkey.Key
	secret mtglib.Secret
}

// userList is an immutable published generation: built once, never edited,
// swapped atomically by UpdateUsers.
type userList struct {
	byName  map[string]credential
	secrets map[string]mtglib.Secret // dispatch table: user -> secret
	keys    map[string]*userkey.Key  // user -> identity
	order   []string                 // stable iteration for buildProxies
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
	users      atomic.Pointer[userList]
	proxies    atomic.Pointer[map[string]*mtglib.Proxy]
	updateMu   sync.Mutex
	trafficMgr *traffic.Manager
	conns      *traffic.ConnGroup
	network    mtgNetwork
	antiReplay mtglib.AntiReplayCache
	tlsDomain  string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	routerEx, ok := router.(adapter.ConnectionRouterEx)
	if !ok {
		return nil, E.New("mtproto: router does not implement ConnectionRouterEx")
	}
	// Asserted (and kept) for the same reason sshvpn keeps it: the data
	// path dials DCs via mtg's own Network in v1, but a future routed
	// dialer drops in at this seam without touching the handler.
	inb := &Inbound{
		Adapter:    inbound.NewAdapter(TypeMtproto, tag),
		ctx:        ctx,
		router:     routerEx,
		logger:     logger,
		trafficMgr: traffic.FromContext(ctx),
		conns:      traffic.ConnGroupFromContext(ctx),
		network:    mtgNetwork{},
		antiReplay: antireplay.NewStableBloomFilter(0, -1),
		tlsDomain:  options.TlsDomain,
	}
	if inb.tlsDomain == "" {
		inb.tlsDomain = DefaultTlsDomain
	}
	if err := inb.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	inb.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inb,
	})
	return inb, nil
}

// buildProxies mints one mtglib.Proxy per user. All proxies share the
// inbound's Network, AntiReplayCache (session IDs are global - one cache
// shared across every secret, same as one mtg process fronting many conns),
// event stream and logger; only the Secret differs. A Proxy is stateless
// between connections, so dropping one (a removed user) cancels only its
// idle machinery - established relays run to completion.
func (h *Inbound) buildProxies(users *userList) (map[string]*mtglib.Proxy, error) {
	proxies := make(map[string]*mtglib.Proxy, len(users.order))
	for _, name := range users.order {
		cred := users.byName[name]
		proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
			Secret:          cred.secret,
			Network:         h.network,
			AntiReplayCache: h.antiReplay,
			IPBlocklist:     ipblocklist.NewNoop(),
			IPAllowlist:     ipblocklist.NewNoop(),
			EventStream:     events.NewNoopStream(),
			Logger:          mtglogger.NewNoopLogger(),
			// 0 = mtg's own DefaultConcurrency (4096): per-user caps
			// are not a rapido concept yet.
			Concurrency: 0,
			// mtg defaults: survive mobile sleep periods, full
			// handshake within 10s, FakeTLS timestamp window.
			IdleTimeout:          mtglib.DefaultIdleTimeout,
			HandshakeTimeout:     mtglib.DefaultHandshakeTimeout,
			TolerateTimeSkewness: mtglib.DefaultTolerateTimeSkewness,
			PreferIP:             mtglib.DefaultPreferIP,
		})
		if err != nil {
			return nil, E.Cause(err, "mtproto: build proxy for user ", name)
		}
		proxies[name] = proxy
	}
	return proxies, nil
}

// UpdateUsers replaces the inbound's user list in place, on the
// already-running listener. The dispatch table resolves against the latest
// generation; relays already established keep running untouched (a secret
// is only consulted at FakeTLS handshake time, never re-checked). A
// zero-length list publishes an empty table - every attempt fails, which
// is what "no users configured" must mean.
func (h *Inbound) UpdateUsers(users []MtprotoUser) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()

	byName := make(map[string]credential, len(users))
	secrets := make(map[string]mtglib.Secret, len(users))
	keys := make(map[string]*userkey.Key, len(users))
	order := make([]string, 0, len(users))
	shared := traffic.SharedList(h.conns, users)
	for i, u := range users {
		keyBytes, err := hex.DecodeString(u.Secret)
		if err != nil || len(keyBytes) != mtglib.SecretKeyLength {
			return fmt.Errorf("mtproto: user %q: secret must be %d hex chars (16 bytes)", u.Name, mtglib.SecretKeyLength*2)
		}
		if _, dup := byName[u.Name]; dup {
			return fmt.Errorf("mtproto: duplicate user %q", u.Name)
		}
		cred := credential{
			key: shared.Keys[i],
			secret: mtglib.Secret{
				Key:  [mtglib.SecretKeyLength]byte(keyBytes),
				Host: h.tlsDomain,
			},
		}
		byName[u.Name] = cred
		secrets[u.Name] = cred.secret
		keys[u.Name] = cred.key
		order = append(order, u.Name)
	}

	newUsers := &userList{byName: byName, secrets: secrets, keys: keys, order: order}
	proxies, err := h.buildProxies(newUsers)
	if err != nil {
		return err // running list unchanged
	}

	h.users.Store(newUsers)
	h.proxies.Store(&proxies)
	traffic.SetPolicy(h.conns, h.Tag(), shared.Policy)
	return nil
}

// Start opens the TCP listener; the per-user proxies are lazy - each
// ServeConn runs on demand from NewConnection.
func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

// Close stops the listener and shuts every per-user proxy down.
func (h *Inbound) Close() error {
	err := h.listener.Close()
	if proxies := h.proxies.Load(); proxies != nil {
		for _, p := range *proxies {
			p.Shutdown()
		}
	}
	return err
}

// NewConnection is the listener's ConnectionHandler entry: dispatch the
// FakeTLS ClientHello to a user, then hand the rewound conn to that user's
// proxy. Byte counting and presence ride the CLIENT side of the relay -
// the bytes a Telegram app actually sent and received, which is what the
// panel's usage table means (telemt parity).
func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer traffic.CloseOnPanic(ctx, h.logger, conn, onClose)

	users := h.users.Load()
	if users == nil || len(users.order) == 0 {
		N.CloseOnHandshakeFailure(conn, onClose, E.New("mtproto: no users configured"))
		return
	}

	dispatch, ok := mtglib.TryDispatch(essentials.WrapNetConn(conn), users.secrets, mtglib.DefaultTolerateTimeSkewness)
	if !ok {
		// No candidate key validated the hello: not one of our users.
		// v1 closes (domain-fronting the probe away is a follow-up).
		h.logger.DebugContext(ctx, "mtproto: no secret matched from ", metadata.Source)
		N.CloseOnHandshakeFailure(conn, onClose, E.New("mtproto: unknown secret"))
		return
	}

	proxies := h.proxies.Load()
	proxy, ok := (*proxies)[dispatch.User]
	if !ok {
		// A concurrent UpdateUsers dropped the user between dispatch
		// and here; treat as revoked.
		N.CloseOnHandshakeFailure(conn, onClose, E.New("mtproto: user revoked mid-handshake"))
		return
	}
	users = h.users.Load()
	cred, ok := users.lookup(dispatch.User)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, E.New("mtproto: user revoked mid-handshake"))
		return
	}

	h.logger.InfoContext(ctx, "[", dispatch.User, "] mtproto stream from ", metadata.Source)

	// Presence first (the connection IS an authenticated user's stream
	// from here until it ends), then byte counting wrapped AROUND the
	// replay conn so the hello bytes themselves bill to the user too.
	tracked := dispatch.Conn
	trackedOnClose := onClose
	if h.conns != nil {
		trackedOnClose = h.conns.TrackAuthenticated(h.Tag(), dispatch.User, cred.key.Fingerprint, conn, onClose)
	}
	if h.trafficMgr != nil {
		// dispatch.Conn (an essentials.Conn) already satisfies
		// net.Conn; counting wraps it directly, and the counted
		// net.Conn re-enters the essentials world for ServeConn.
		// CloseRead/CloseWrite still reach the real TCP conn through
		// both wrappers (each falls back to the embedded conn).
		tracked = essentials.WrapNetConn(traffic.WrapConn(dispatch.Conn, dispatch.User, h.trafficMgr))
	}
	proxy.ServeConn(tracked)
	if trackedOnClose != nil {
		trackedOnClose(nil)
	}
}

// mtgNetwork implements mtg's mtglib.Network over a plain net.Dialer: v1
// dials Telegram DCs directly, the same as mtg standalone. MakeHTTPClient
// exists only for the public-config auto-updater (this inbound never
// enables AutoUpdate) and the doppelganger scout (never configured with
// URLs), so a stock client satisfies both without behavior anyone can
// observe.
type mtgNetwork struct{}

func (mtgNetwork) Dial(network, address string) (essentials.Conn, error) {
	conn, err := (&net.Dialer{Timeout: mtgDialTimeout}).Dial(network, address)
	if err != nil {
		return nil, err //nolint:wrapcheck // mtg wraps its own context around it
	}
	return essentials.WrapNetConn(conn), nil
}

func (mtgNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	conn, err := (&net.Dialer{Timeout: mtgDialTimeout}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err //nolint:wrapcheck
	}
	return essentials.WrapNetConn(conn), nil
}

func (mtgNetwork) MakeHTTPClient(_ func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: mtgDialTimeout}).DialContext}}
}

func (mtgNetwork) NativeDialer() *net.Dialer { return &net.Dialer{Timeout: mtgDialTimeout} }

// mtgDialTimeout bounds a single DC dial. mtg standalone leaves this to
// its own dialer default; 10s matches the handshake budget so a blackholed
// DC address cannot hold a stream slot forever.
const mtgDialTimeout = 10 * time.Second
