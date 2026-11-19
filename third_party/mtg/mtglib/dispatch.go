package mtglib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib/internal/tls"
	"github.com/9seconds/mtg/v2/mtglib/internal/tls/fake"
)

// dispatchMaxFrames mirrors fake.maxFragmentsCount: a ClientHello spread
// over more handshake records than this is not something a Telegram client
// sends, and reading further would let a hostile peer pin a dispatcher
// goroutine indefinitely.
const dispatchMaxFrames = 10

// Dispatch-local sentinel errors for frames the vendored fake package has
// no exported equivalent of (its own are unexported).
var (
	errUnexpectedRecordType = errors.New("unexpected record type")
	errProtocolVersion      = errors.New("unexpected protocol version")
	errTooBigRecord         = errors.New("record is too big")
)

// DispatchResult names the user whose secret matched an incoming
// connection. Conn is the original connection with the consumed ClientHello
// bytes rewound, so the matched Proxy's own ServeConn sees the stream from
// the very first byte - exactly what Proxy.doFakeTLSHandshake's rewind does
// in the single-secret case.
type DispatchResult struct {
	User        string
	Conn        essentials.Conn
	ClientHello *fake.ClientHello
}

// TryDispatch peeks the FakeTLS ClientHello on conn and returns which of
// secrets (user -> secret) matches, rewinding the stream so the matched
// Proxy.ServeConn reads it untouched. ok=false means no secret matched (or
// the bytes are not a ClientHello this version understands): the caller
// should close the connection.
//
// The ClientHello frames are read from the wire ONCE and then replayed to
// fake.ReadClientHello once per candidate key over an in-memory reader -
// Proxy.doFakeTLSHandshake parses the same hello once per candidate with a
// rewind between tries, but connRewind's buffer drains on the first replay,
// so a multi-candidate dispatch cannot reuse it. The framing here mirrors
// fake.fragmentedHandshakeReader record for record, so the byte stream each
// candidate sees is identical to what the single-secret proxy sees.
//
// All of ReadClientHello's own checks run per candidate: record framing,
// handshake type, digest (the HMAC keyed by the candidate's secret), the
// SNI list (every secret of one inbound shares a host, but the check runs
// anyway) and the timestamp skew.
func TryDispatch(conn essentials.Conn, secrets map[string]Secret, skew time.Duration) (DispatchResult, bool) {
	if len(secrets) == 0 {
		return DispatchResult{}, false
	}

	raw, err := readClientHelloFrames(conn)
	if err != nil {
		return DispatchResult{}, false
	}

	for user, secret := range secrets {
		hello, err := fake.ReadClientHello(
			memConn{reader: bytes.NewReader(raw)},
			secret.Key[:],
			secret.Host,
			skew,
		)
		if err != nil {
			continue
		}
		return DispatchResult{
			User:        user,
			Conn:        &replayConn{Conn: conn, prefix: bytes.NewReader(raw)},
			ClientHello: hello,
		}, true
	}

	return DispatchResult{}, false
}

// readClientHelloFrames consumes exactly the TLS records carrying the
// ClientHello handshake message and returns them verbatim (record headers
// included). It stops before the handshake message is complete-plus-one
// record, so everything after the hello stays on the wire.
func readClientHelloFrames(conn essentials.Conn) ([]byte, error) {
	var (
		raw    bytes.Buffer
		stream bytes.Buffer
	)

	header := make([]byte, tls.SizeHeader)
	for frames := 0; ; frames++ {
		if frames >= dispatchMaxFrames {
			return nil, fake.ErrTooManyFragments
		}
		if _, err := io.ReadFull(io.TeeReader(conn, &raw), header); err != nil {
			return nil, err
		}
		if header[0] != tls.TypeHandshake {
			return nil, errUnexpectedRecordType
		}
		if header[1] != 3 || header[2] != 1 {
			return nil, errProtocolVersion
		}

		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || length > tls.MaxRecordSize {
			return nil, errTooBigRecord
		}
		if _, err := io.Copy(&stream, io.TeeReader(io.LimitReader(conn, int64(length)), &raw)); err != nil {
			return nil, err
		}

		needed, ok := clientHelloLength(stream.Bytes())
		if !ok {
			continue
		}
		if stream.Len() >= needed {
			return raw.Bytes(), nil
		}
	}
}

// clientHelloLength returns 4 + the uint24 handshake length once the first
// four bytes of the reassembled handshake stream are available, mirroring
// fake.parseClientHello's own type and length handling.
func clientHelloLength(stream []byte) (int, bool) {
	if len(stream) < 4 {
		return 0, false
	}
	if stream[0] != fake.TypeHandshakeClient {
		return 0, false
	}
	return 4 + int(uint32(stream[1])<<16|uint32(stream[2])<<8|uint32(stream[3])), true
}

// memConn serves pre-read bytes to fake.ReadClientHello, whose signature
// takes a net.Conn but only ever reads from it. Nothing else is reachable:
// the hello is fully buffered, so the read cannot touch the network.
type memConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c memConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// replayConn serves the buffered ClientHello frames first, then everything
// still queued on the live connection - the multi-candidate equivalent of
// connRewind.Rewind, replayable any number of times because the prefix is
// an independent reader rather than a drained buffer.
type replayConn struct {
	essentials.Conn

	prefix *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if n, _ := c.prefix.Read(p); n > 0 {
		return n, nil
	}
	return c.Conn.Read(p)
}
