// wg_test.go: the inbound exercised end-to-end - a REAL wireguard-go
// peer (client_test.go) handshaking with a REAL node (nodecore.New +
// Start, the same path cmd/node drives), through the forked userspace
// stack, out to a plain TCP echo server - plus attribution, hot update,
// revocation and accounting, per plan §2.8.
package wg_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/legendary1205/rapido-go/internal/nodecore"
	"github.com/legendary1205/rapido-go/internal/nodecore/traffic"
	wg "github.com/legendary1205/rapido-go/internal/nodecore/wg"
)

// startTCPEcho runs a plain echo server; returns host and port.
func startTCPEcho(t *testing.T) (string, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// testNode is one running node with one wireguard inbound.
type testNode struct {
	node     *nodecore.Node
	mgr      *traffic.Manager
	privB64  string
	pubB64   string
	port     uint16
	echoHost string
	echoPort uint16
}

func startWGNode(t *testing.T, users ...wg.WgUser) *testNode {
	t.Helper()
	privB64, pubB64 := testKeyPair(t)
	port := freeUDPPort(t)
	echoHost, echoPort := startTCPEcho(t)
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	opts := option.Options{
		Inbounds: []option.Inbound{{
			Type: "wgvpn", Tag: "wg-in",
			Options: &wg.InboundOptions{
				ListenOptions: option.ListenOptions{Listen: &listen, ListenPort: port},
				Users:         users, Subnet: "10.7.0.0/24", PrivateKey: privB64,
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct-out", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct-out"},
	}
	mgr := traffic.NewManager()
	node, err := nodecore.New(context.Background(), opts, mgr)
	if err != nil {
		t.Fatalf("nodecore.New: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { node.Close() })
	return &testNode{node: node, mgr: mgr, privB64: privB64, pubB64: pubB64, port: port, echoHost: echoHost, echoPort: echoPort}
}

func (n *testNode) serverAddr() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(n.port)))
}

// wgUserOf mints a user with a fresh keypair at index idx.
func wgUserOf(t *testing.T, name string, idx uint32) (wg.WgUser, string) {
	t.Helper()
	priv, pub := testKeyPair(t)
	return wg.WgUser{Name: name, PublicKey: pub, Index: idx}, priv
}

// TestWireGuardHandshakeAndEcho: a real peer handshakes with the node and
// proxies a TCP echo through the tunnel (handshake + data path).
func TestWireGuardHandshakeAndEcho(t *testing.T) {
	alice, alicePriv := wgUserOf(t, "alice", 5)
	n := startWGNode(t, alice)

	client := startWGTestClient(t, n.serverAddr(), n.pubB64, alicePriv, wg.AddrForIndex(netip.MustParsePrefix("10.7.0.0/24"), 5))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.dialEcho(ctx, netip.MustParseAddr(n.echoHost), n.echoPort, "hello-through-wg"); err != nil {
		t.Fatalf("echo through tunnel: %v", err)
	}
}

// TestWireGuardAttributesTrafficToUser: bytes moved through the tunnel
// bill to the peer's owner once pollOnce runs (up = rx, down = tx).
func TestWireGuardAttributesTrafficToUser(t *testing.T) {
	alice, alicePriv := wgUserOf(t, "alice", 5)
	n := startWGNode(t, alice)
	client := startWGTestClient(t, n.serverAddr(), n.pubB64, alicePriv, wg.AddrForIndex(netip.MustParsePrefix("10.7.0.0/24"), 5))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.dialEcho(ctx, netip.MustParseAddr(n.echoHost), n.echoPort, "bill-me"); err != nil {
		t.Fatalf("echo: %v", err)
	}
	// The poller runs on its own 30s ticker; the accounting assertion
	// only needs to prove the IpcGet->Manager path works, which the
	// inbound's own unit tests (TestPollOnce...) cover without waiting.
	// Here we assert the connection was attributed at the router level
	// by checking that billing appears within a short window of a
	// forced poll - reached through the package's exported test hook.
	if err := n.node.PollWireguardUsage("wg-in"); err != nil {
		t.Fatalf("poll: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := n.mgr.Drain(); got["alice"].Up > 0 && got["alice"].Down > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no traffic billed to alice after poll")
}
