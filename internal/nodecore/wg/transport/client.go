// client.go: the fork's userspace stack in CLIENT mode - the same gVisor
// stack the server side runs, but with no transport forwarders (nothing
// to route: every decrypted packet belongs to this device's own
// address), and a UDP dial-out bind so a test peer (or a future amnezia
// slice) can reach a real endpoint. Exists so the inbound's tests can
// exercise the server data path with a genuine wireguard-go peer instead
// of a mock - the same fork, worn from the other side.
package transport

import (
	"context"
	"net/netip"
)

// ClientStack is a stack.Device with no handler installed: a WireGuard
// client's tun. DialContext/ListenPacket (inherited from the same
// stackDevice the server uses) place sockets inside the tunnel.
type ClientStack = stackDevice

// NewClientStack builds the client-side device: one local address (the
// client's /32 inside the server's subnet), default MTU 1408, no
// forwarders.
func NewClientStack(address netip.Addr) (*ClientStack, error) {
	return newStackDevice(DeviceOptions{
		Context: context.Background(),
		MTU:     DefaultMTU,
		Address: []netip.Prefix{netip.PrefixFrom(address, 32)},
	})
}
