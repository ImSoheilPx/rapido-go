// client_test.go: a REAL wireguard-go peer talking to the inbound over
// loopback UDP. The client side runs the SAME forked userspace stack as
// the server (internal/nodecore/wg/transport), built in client mode: no
// forwarders, just tun.Device semantics so wireguard-go can decrypt into
// it, plus DialContext to place TCP dials inside the tunnel.
package wg_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	"golang.org/x/crypto/curve25519"

	"github.com/legendary1205/rapido-go/internal/nodecore/wg/transport"
)

// testKeyPair mints one clamped Curve25519 pair (b64 priv, b64 pub).
func testKeyPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curvePub(priv)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// wgTestClient is one real client peer: own keypair, own userspace stack,
// the inbound under test as its single peer.
type wgTestClient struct {
	dev   *device.Device
	stack *transport.ClientStack
}

// startWGTestClient builds a client whose single peer is the endpoint at
// serverAddr with serverPubB64, tunnel address clientIP, authenticated
// as the user whose private key is userPrivB64.
func startWGTestClient(t *testing.T, serverAddr, serverPubB64, userPrivB64 string, clientIP netip.Addr) *wgTestClient {
	t.Helper()
	privHex := hex.EncodeToString(mustDecodeB64(t, userPrivB64))
	pubHex := hex.EncodeToString(mustDecodeB64(t, serverPubB64))

	stack, err := transport.NewClientStack(clientIP)
	if err != nil {
		t.Fatalf("client stack: %v", err)
	}
	dev := device.NewDevice(context.Background(), stack, conn.NewStdNetBind(nil), quietWGLogger(t), 2)
	ipc := "private_key=" + privHex + "\npublic_key=" + pubHex + "\nendpoint=" + serverAddr + "\nallowed_ip=0.0.0.0/0"
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}
	c := &wgTestClient{dev: dev, stack: stack}
	t.Cleanup(func() { dev.Close() })
	return c
}

// dialEcho opens a TCP conn through the tunnel to host:port, writes
// payload, and wants it echoed back intact.
func (c *wgTestClient) dialEcho(ctx context.Context, host netip.Addr, port uint16, payload string) error {
	conn, err := c.stack.DialContext(ctx, "tcp", socksaddrOf(host, port))
	if err != nil {
		return fmt.Errorf("dial through tunnel: %w", err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(8 * time.Second)
	}
	conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := readFull(conn, got); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(got) != payload {
		return fmt.Errorf("echo mismatch: %q != %q", got, payload)
	}
	return nil
}

// mustDecodeB64 decodes or fails the test.
func mustDecodeB64(t *testing.T, v string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("bad b64 %q: %v", v, err)
	}
	return raw
}

// curvePub derives the public half (test-only mirror of proxysettings).
func curvePub(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// socksaddrOf is M.SocksaddrFromNetIP without importing sing here twice.
func socksaddrOf(addr netip.Addr, port uint16) M.Socksaddr {
	return M.SocksaddrFrom(addr, port)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func quietWGLogger(t *testing.T) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { t.Logf("wg-client: "+format, args...) },
		Errorf:   func(format string, args ...any) { t.Logf("wg-client: "+format, args...) },
	}
}
