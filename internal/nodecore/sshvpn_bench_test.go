package nodecore

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// TestSSHVPNThroughput measures end-to-end throughput through a live
// sshvpn inbound: client writes into a direct-tcpip channel, the node's
// router delivers it to a local sink, and the test reports MB/s. This is
// the number a user's download speed actually rides on.
func TestSSHVPNThroughput(t *testing.T) {
	// Sink: accepts, reads exactly total bytes, tells the test when done.
	const total = 16 << 20
	done := make(chan time.Duration, 1)
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	go func() {
		c, err := sink.Accept()
		if err != nil {
			return
		}
		start := time.Now()
		io.CopyN(io.Discard, c, total)
		done <- time.Since(start)
		c.Close()
	}()
	sinkAddr := M.ParseSocksaddr(sink.Addr().String())

	alice := testUser{"alice", "secret-1"}
	pc := sshvpnCase()
	f := startForkedNode(t, pc, alice)

	conn := f.dial(t, alice)
	_ = conn
	// dial targets the forkedNode's tcp echo server by default; we want
	// the sink instead, so open our own channel via the raw dial helper.
	raw, err := pc.dialTCP(f.addr, alice, sinkAddr)
	if err != nil {
		t.Fatalf("dial through node: %v", err)
	}
	defer raw.Close()

	buf := make([]byte, 128*1024)
	start := time.Now()
	go func() {
		for written := 0; written < total; {
			n, err := raw.Write(buf)
			if err != nil {
				return
			}
			written += n
		}
	}()

	select {
	case el := <-done:
		fmt.Printf("sshvpn end-to-end: %d MB in %v = %.1f MB/s\n", total>>20, el, float64(total)/el.Seconds()/1048576)
	case <-time.After(30 * time.Second):
		t.Fatal("sink never received the full payload")
	}
	_ = start
}
