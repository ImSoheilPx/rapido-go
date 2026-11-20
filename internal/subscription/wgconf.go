package subscription

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/legendary1205/rapido-go/internal/proxysettings"
)

// RenderWgConf renders one user's wg-quick-style configuration file for a
// wireguard host - the artifact a customer with the stock wireguard client
// (or wg-quick itself) pastes in. vpn-ui parity: [Interface] carries the
// user's own keypair and DERIVED tunnel address (Address = the /32 plus
// the subnet's /NN so route installation works both ways), [Peer] carries
// the inbound's derived public key, the server's real dial address/port,
// AllowedIPs 0.0.0.0/0 + ::/0 (full tunnel - a proxy, not a site-to-site
// link) and a 25s keepalive so NAT bindings survive.
//
// The tunnel address is derived here from the user's numeric id against
// the inbound's WgSubnet (AddrForIndex, the shared arithmetic), NOT
// stored anywhere - see internal/nodecore/wg's own doc comment.
func RenderWgConf(address string, in EffectiveInbound, s *proxysettings.WireguardSettings, userID int64) (string, error) {
	subnet, err := netip.ParsePrefix(in.WgSubnet)
	if err != nil {
		return "", fmt.Errorf("subscription: wireguard host has invalid subnet %q", in.WgSubnet)
	}
	if in.WgServerPublicKey == "" {
		return "", fmt.Errorf("subscription: wireguard host has no server public key")
	}
	tunnel := AddrForIndex(subnet, uint32(userID))
	server := AddrForIndex(subnet, 1)

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/32, %s\n", tunnel, subnet)
	fmt.Fprintf(&b, "DNS = %s\n", server)
	if in.WgMtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", in.WgMtu)
	}
	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", in.WgServerPublicKey)
	if s.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", s.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", address, in.Port)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	return b.String(), nil
}
