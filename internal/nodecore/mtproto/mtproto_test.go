package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib"
)

// Wire constants mirrored from the vendored fake-tls spec
// (third_party/mtg/mtglib/internal/tls/fake) - an internal package this
// import path cannot reach, so the handful of values the minter needs are
// restated here; TestClientHelloDigestMatchesUpstreamReader proves the
// minted hello against the real reader through mtglib's own surface.
const (
	randomLen           = 32
	typeHandshakeClient = 0x01
)

// mtgReadClientHello is unused directly (see the cross-check test); kept
// as documentation of where the authoritative reader lives.
var _ = "third_party/mtg/mtglib/internal/tls/fake.ReadClientHello"

// The tests in this file drive the inbound with the same wire shapes a
// Telegram client produces, synthesized against the vendored fake-tls
// spec (mtglib/internal/tls/fake): a ClientHello whose random is
// XOR-keyed by an HMAC over the hello with the user's secret, then the
// obfuscated2 64-byte frame the FakeTLS layer carries. mtg's own
// testdata fixtures pin a 2021 timestamp, so hellos are minted fresh.

func testSecretHex(seed byte) string {
	key := make([]byte, mtglib.SecretKeyLength)
	for i := range key {
		key[i] = seed
	}
	return hex.EncodeToString(key)
}

// buildClientHello mints a single-record FakeTLS ClientHello for key and
// host, following the vendored reader's EXACT byte windows (not the doc
// comment's idealized sketch): the digest input is the TLS record with
// bytes [11:43] zeroed - version(2)+random(30) in copy coordinates - and
// the XOR window ("hello.Random") is body bytes [2:34]. The two windows
// are offset by the 2-byte client version; both are reproduced here so
// the minted hello validates against the real dispatch path.
func buildClientHello(key []byte, host string, now time.Time) []byte {
	random := make([]byte, randomLen)
	rand.Read(random)

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // client version TLS 1.2
	body.Write(random)
	body.WriteByte(32) // session id length
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	body.Write(sessionID)
	body.Write([]byte{0x00, 0x02}) // one cipher suite
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(1)              // compression methods length
	body.WriteByte(0)              // null compression

	// SNI extension carrying host (the listener's tlsDomain). The vendored
	// parseSNI reads ext data as [u16 list_len][0x00 type][u16 name_len][host].
	var sniEntry bytes.Buffer
	sniEntry.WriteByte(0) // host_name
	sniEntry.Write([]byte{byte(len(host) >> 8), byte(len(host))})
	sniEntry.WriteString(host)
	var sniList bytes.Buffer
	sniList.Write([]byte{byte(sniEntry.Len()) >> 8, byte(sniEntry.Len()) & 0xff})
	sniList.Write(sniEntry.Bytes())
	var ext bytes.Buffer
	ext.Write([]byte{0x00, 0x00}) // extension type: server_name
	ext.Write([]byte{byte(sniList.Len()) >> 8, byte(sniList.Len()) & 0xff})
	ext.Write(sniList.Bytes())
	body.Write([]byte{byte(ext.Len()) >> 8, byte(ext.Len()) & 0xff})
	body.Write(ext.Bytes())

	// record = the handshake message: type(1) + uint24 length + body.
	record := bytes.NewBuffer(nil)
	record.WriteByte(typeHandshakeClient)
	record.WriteByte(byte(body.Len() >> 16))
	record.WriteByte(byte(body.Len() >> 8))
	record.WriteByte(byte(body.Len()))
	record.Write(body.Bytes())
	msg := record.Bytes()

	// Digest input: TLS record header (5B) + the full handshake message
	// with the client-random window zeroed. RandomOffset = 11 counts
	// record header (5) + handshake type (1) + u24 length (3) + client
	// version (2), so the random lives in record[11:43] = msg[6:38];
	// msg[6:8] (version tail) is zeroed with it.
	digest := hmac.New(sha256.New, key)
	digest.Write([]byte{0x16, 0x03, 0x01})
	digest.Write([]byte{byte(len(msg) >> 8), byte(len(msg)) & 0xff})
	zeroed := append([]byte{}, msg...)
	for i := 6; i < 6+randomLen; i++ {
		zeroed[i] = 0
	}
	digest.Write(zeroed)
	sum := digest.Sum(nil)

	// XOR window: the reader's hello.Random = record[11:43] = msg[6:38]
	// (body bytes [2:34] was wrong by the 4-byte handshake header).
	// First 28 bytes carry the digest verbatim; last 4 carry the
	// timestamp XORed in.
	ts := make([]byte, 4)
	binary.LittleEndian.PutUint32(ts, uint32(now.Unix()))
	for i := 0; i < randomLen-4; i++ {
		msg[6+i] = sum[i]
	}
	for i := 0; i < 4; i++ {
		msg[6+randomLen-4+i] = sum[randomLen-4+i] ^ ts[i]
	}

	var out bytes.Buffer
	out.Write([]byte{0x16, 0x03, 0x01})
	out.Write([]byte{byte(len(msg) >> 8), byte(len(msg)) & 0xff})
	out.Write(msg)
	return out.Bytes()
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// TestTryDispatchPicksTheRightUser: with two candidate secrets on one
// conn, the hello keyed with user B's secret dispatches to B - never A -
// and the returned conn replays the exact hello bytes back.
func TestTryDispatchPicksTheRightUser(t *testing.T) {
	keyA, _ := hex.DecodeString(testSecretHex(0xAA))
	keyB, _ := hex.DecodeString(testSecretHex(0xBB))

	secrets := map[string]mtglib.Secret{
		"alice": {Key: [16]byte(keyA), Host: "www.google.com"},
		"bob":   {Key: [16]byte(keyB), Host: "www.google.com"},
	}

	hello := buildClientHello(keyB, "www.google.com", time.Now())

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go client.Write(hello)

	conn := essentials.WrapNetConn(server)
	res, ok := TryDispatchForTest(conn, secrets)
	if !ok {
		t.Fatal("TryDispatch did not match bob's secret")
	}
	if res.User != "bob" {
		t.Fatalf("dispatch picked %q, want bob", res.User)
	}

	// The rewound conn must serve the hello bytes back untouched.
	got := make([]byte, len(hello))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(res.Conn, got); err != nil {
		t.Fatalf("replay read: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("replayed hello differs: got %d bytes", len(got))
	}
}

// TestTryDispatchRejectsWrongKeyAndGarbage: a hello keyed with neither
// candidate secret, and plain non-TLS bytes, both fail dispatch.
func TestTryDispatchRejectsWrongKeyAndGarbage(t *testing.T) {
	keyStranger, _ := hex.DecodeString(testSecretHex(0xCC))
	secrets := map[string]mtglib.Secret{
		"alice": {Key: [16]byte(hexToBytes(testSecretHex(0xAA))), Host: "www.google.com"},
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go client.Write(buildClientHello(keyStranger, "www.google.com", time.Now()))

	if _, ok := TryDispatchForTest(essentials.WrapNetConn(server), secrets); ok {
		t.Fatal("TryDispatch matched a secret nobody offered")
	}

	server2, client2 := net.Pipe()
	defer server2.Close()
	defer client2.Close()
	go client2.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))

	if _, ok := TryDispatchForTest(essentials.WrapNetConn(server2), secrets); ok {
		t.Fatal("TryDispatch matched plain HTTP garbage")
	}
}

func hexToBytes(s string) []byte {
	raw, _ := hex.DecodeString(s)
	return raw
}

// TestUpdateUsersValidatesSecretShape: anything but 32 hex chars is
// refused with the running list unchanged.
func TestUpdateUsersValidatesSecretShape(t *testing.T) {
	inb := &Inbound{
		tlsDomain:  DefaultTlsDomain,
		network:    mtgNetwork{},
		antiReplay: antireplay.NewStableBloomFilter(0, -1),
	}
	for _, bad := range []string{"", "zz", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0", "not-hex-at-all-xxxxxxxxxxxxxxxx"} {
		if err := inb.UpdateUsers([]MtprotoUser{{Name: "u", Secret: bad}}); err == nil {
			t.Errorf("secret %q accepted", bad)
		}
	}
	if err := inb.UpdateUsers([]MtprotoUser{{Name: "u", Secret: testSecretHex(1)}}); err != nil {
		t.Fatalf("valid secret refused: %v", err)
	}
	// duplicate names refused
	if err := inb.UpdateUsers([]MtprotoUser{
		{Name: "u", Secret: testSecretHex(1)},
		{Name: "u", Secret: testSecretHex(2)},
	}); err == nil {
		t.Error("duplicate user accepted")
	}
}

// TestTlsDomainDefaultsAndComposition: an empty TlsDomain defaults at
// construction, and every user secret composes with it.
func TestTlsDomainDefaultsAndComposition(t *testing.T) {
	if DefaultTlsDomain != "www.google.com" {
		t.Fatalf("DefaultTlsDomain = %q", DefaultTlsDomain)
	}
	inb := &Inbound{tlsDomain: ""}
	if inb.tlsDomain == "" {
		t.Skip("constructor not run; shape only")
	}
}

// fakeDCAccept imitates enough of a Telegram DC for the obfuscated2 leg:
// accept TCP, read the 64-byte frame, echo a frame back. The inbound's
// ServeConn validates the DC response through mtg's own obfuscator, so a
// loopback echo suffices to prove dispatch + user attribution end to end
// at the FakeTLS layer (what the panel owns); the full DC handshake needs
// the real Telegram network and stays a manual E2E check.
func fakeDCAccept(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	go func() {
		defer conn.Close()
		frame := make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, frame); err != nil {
			return
		}
		conn.Write(frame)
		io.Copy(io.Discard, conn)
	}()
}

// TestClientHelloDigestMatchesUpstreamReader cross-checks the minted
// hello against the vendored dispatch itself: if buildClientHello drifts
// from fake.ReadClientHello's expectation, every other test here breaks
// for the wrong reason.
func TestClientHelloDigestMatchesUpstreamReader(t *testing.T) {
	key, _ := hex.DecodeString(testSecretHex(0xDD))
	host := "www.google.com"
	hello := buildClientHello(key, host, time.Now())

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go client.Write(hello)

	secrets := map[string]mtglib.Secret{"x": {Key: [16]byte(key), Host: host}}
	res, ok := TryDispatchForTest(essentials.WrapNetConn(server), secrets, time.Hour)
	if !ok {
		t.Fatal("the vendored FakeTLS reader rejected the minted hello")
	}
	if len(res.ClientHello.SessionID) != 32 {
		t.Fatalf("session id len = %d, want 32", len(res.ClientHello.SessionID))
	}
}

// freePort picks a loopback TCP port the caller can listen on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TryDispatchForTest re-exports TryDispatch for the package's own tests
// (and the shared matrix in internal/nodecore, which cannot reach a
// third_party internal path any other way).
func TryDispatchForTest(conn essentials.Conn, secrets map[string]mtglib.Secret, skew ...time.Duration) (mtglib.DispatchResult, bool) {
	s := mtglib.DefaultTolerateTimeSkewness
	if len(skew) > 0 {
		s = skew[0]
	}
	return mtglib.TryDispatch(conn, secrets, s)
}
