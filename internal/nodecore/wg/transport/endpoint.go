// endpoint.go is a fork of sing-box v1.14.0's transport/wireguard/endpoint.go,
// reduced to the server (listen) half: no client bind, no egress pool, no
// pause manager, no power-report attribution, no domain-peer resolver - a
// rapido node's WireGuard device is a listener that peers dial INTO, never
// a dialer. See the package doc comment for the full fork map.
package transport

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
)

// DefaultMTU is sing-box's own userspace-stack default (1408 - 1420 costs
// gVisor header room; verified against upstream endpoint.go's MTU==0 arm).
const DefaultMTU = 1408

// EndpointOptions is upstream's, minus the dialer/egress/pause fields the
// listen-only path never reads.
type EndpointOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	Handler      Handler
	UDPTimeout   time.Duration
	ICMPTimeout  time.Duration
	UDPMapping   tun.NATMapping
	UDPFiltering tun.NATFiltering
	UDPNATMax    uint32

	Name       string
	MTU        uint32
	Address    []netip.Prefix
	PrivateKey string
	ListenPort uint16
	Workers    int
}

// Endpoint owns the wireguard-go device plus the stack device under it.
type Endpoint struct {
	options   EndpointOptions
	ipcConf   string
	tunDevice *stackDevice
	device    *device.Device
	started   bool
}

// NewEndpoint validates the key, builds the userspace stack device and
// pre-renders the device-level UAPI (private_key + listen_port). Peers are
// NOT applied here - Start does that, so an UpdateUsers before start is
// just a stored list (upstream applies its option-baked peers at Start for
// the same reason: the device does not exist yet).
func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	if len(privateKeyBytes) != 32 {
		return nil, E.New("private key must be 32 bytes, got ", len(privateKeyBytes))
	}
	ipcConf := "private_key=" + hex.EncodeToString(privateKeyBytes)
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	if options.MTU == 0 {
		options.MTU = DefaultMTU
	}
	tunDevice, err := newStackDevice(DeviceOptions{
		Context:      options.Context,
		Logger:       options.Logger,
		Handler:      options.Handler,
		UDPTimeout:   options.UDPTimeout,
		ICMPTimeout:  options.ICMPTimeout,
		UDPMapping:   options.UDPMapping,
		UDPFiltering: options.UDPFiltering,
		UDPNATMax:    options.UDPNATMax,
		Name:         options.Name,
		MTU:          options.MTU,
		Address:      options.Address,
	})
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	return &Endpoint{options: options, ipcConf: ipcConf, tunDevice: tunDevice}, nil
}

// Start brings the device up: opens the UDP bind (listen_port), starts the
// wireguard-go workers and applies the device-level UAPI. Idempotent.
func (e *Endpoint) Start() error {
	if e.started {
		return nil
	}
	if err := e.tunDevice.Start(); err != nil {
		return err
	}
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	bind := conn.NewStdNetBind(nil)
	wgDevice := device.NewDevice(e.options.Context, e.tunDevice, bind, wgLogger, e.options.Workers)
	e.tunDevice.SetDevice(wgDevice)
	if err := wgDevice.IpcSet(e.ipcConf); err != nil {
		wgDevice.Close()
		return E.Cause(err, "setup wireguard device")
	}
	if err := wgDevice.Up(); err != nil {
		wgDevice.Close()
		return E.Cause(err, "bring wireguard device up")
	}
	e.device = wgDevice
	e.started = true
	return nil
}

// Device exposes the live wireguard-go device for IpcSet/IpcGet - the
// rapido addition this whole fork exists for (upstream keeps it private).
// Nil before Start.
func (e *Endpoint) Device() *device.Device { return e.device }

// MTU is the stack's MTU (after the default was applied).
func (e *Endpoint) MTU() uint32 { return e.options.MTU }

// ApplyPeers (re)configures the peer set on a STARTED device via one
// IpcSet: full replace when replaceAll (replace_peers=true then re-add
// every peer), else an incremental diff - removed public keys get
// "remove=true", added or changed peers get a full section with
// replace_allowed_ips=true. Established data-path flows survive both
// shapes in wireguard-go: replace_peers rebuilds the peer table but a live
// keypair's goroutines keep draining until their timers expire, and an
// incremental remove kills exactly the removed peer's flows (which IS the
// hard revoke the inbound wants).
func (e *Endpoint) ApplyPeers(peers []PeerConfig, replaceAll bool) error {
	if e.device == nil {
		return E.New("wireguard device is not started")
	}
	var ipc strings.Builder
	if replaceAll {
		// No trailing newline: every peer section below STARTS with
		// \n, and a blank line terminates an IpcSet operation early -
		// replace_peers=true\n\npublic_key=... would drop every peer.
		ipc.WriteString("replace_peers=true")
	}
	for _, peer := range peers {
		ipc.WriteString(peer.GenerateIpcLines())
	}
	return e.device.IpcSet(ipc.String())
}

// Close tears the device down.
func (e *Endpoint) Close() error {
	if e.device != nil {
		e.device.Down()
		e.device.Close()
		e.device = nil
		e.started = false
		return nil
	}
	return e.tunDevice.Close()
}

// PeerConfig is upstream's peerConfig made exported (rapido): the inbound
// builds the peer set panel-side and hands it to ApplyPeers. Server peers
// set only PublicKey/PreSharedKey/AllowedIPs.
type PeerConfig struct {
	destination     string // unused server-side; kept for body parity
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
}

// NewPeerConfig validates and packs one peer. publicKey is base64 std
// (32 bytes); preSharedKey, when non-empty, base64 std (32 bytes);
// allowedIPs are the peer's /32s (or whatever the caller derived).
func NewPeerConfig(publicKey, preSharedKey string, allowedIPs []netip.Prefix) (PeerConfig, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return PeerConfig{}, E.Cause(err, "decode public key")
	}
	if len(publicKeyBytes) != 32 {
		return PeerConfig{}, E.New("public key must be 32 bytes, got ", len(publicKeyBytes))
	}
	peer := PeerConfig{publicKeyHex: hex.EncodeToString(publicKeyBytes), allowedIPs: allowedIPs}
	if preSharedKey != "" {
		preSharedKeyBytes, err := base64.StdEncoding.DecodeString(preSharedKey)
		if err != nil {
			return PeerConfig{}, E.Cause(err, "decode pre-shared key")
		}
		if len(preSharedKeyBytes) != 32 {
			return PeerConfig{}, E.New("pre-shared key must be 32 bytes, got ", len(preSharedKeyBytes))
		}
		peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
	}
	if len(allowedIPs) == 0 {
		return PeerConfig{}, E.New("missing allowed ips for peer")
	}
	return peer, nil
}

// PublicKeyHex is the peer's public key as wireguard-go's UAPI wants it.
func (c PeerConfig) PublicKeyHex() string { return c.publicKeyHex }

// GenerateIpcLines is upstream's, minus the endpoint line (server peers
// roam; the endpoint is learned from the peer's own handshake) and with
// replace_allowed_ips always set so a re-applied peer's allowed_ips are
// exactly what this panel says (rapido).
func (c PeerConfig) GenerateIpcLines() string {
	var ipcLines strings.Builder
	ipcLines.WriteString("\npublic_key=" + c.publicKeyHex)
	if c.preSharedKeyHex != "" {
		ipcLines.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	ipcLines.WriteString("\nreplace_allowed_ips=true")
	for _, allowedIP := range c.allowedIPs {
		ipcLines.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if c.keepalive > 0 {
		ipcLines.WriteString("\npersistent_keepalive_interval=" + F.ToString(c.keepalive))
	}
	return ipcLines.String()
}
