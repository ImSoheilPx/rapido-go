package sshvpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// The badvpn udpgw client protocol (badvpn/protocol/udpgw_proto.h) - the
// dialect NetMod, HTTP Injector, HTTP Custom and the other SSH-proxy
// apps speak on their "UDPGW / UDP over SSH" channel:
//
//	header:  flags u8, conid u16 LITTLE-endian
//	addr:    IPv4: 4-byte IP + 2-byte port (network byte order)
//	         IPv6: 16-byte IP + 2-byte port (network byte order)
//	         (present on client->server packets and on server->client
//	         answers, which echo the ORIGIN address; absent on keepalives)
//	payload: the datagram
//
// One channel multiplexes every UDP flow by its 16-bit conid, exactly
// like the reference badvpn-udpgw server this mirrors. A client opens
// one direct-tcpip channel to udpgwRelayAddr (127.0.0.3:7300 - see the
// package doc comment) and speaks this protocol on it.
const (
	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3
)

const (
	udpgwHeaderLen = 3
	udpgwAddrV4Len = 6
	udpgwAddrV6Len = 18
	udpgwMaxConns  = 256
	udpgwMTU       = 1500
	udpgwIdleSec   = 90 // badvpn's own disconnect timeout is 30s; slack for jitter
)

// udpgwRelayAddr is the in-session target of a udpgw channel:
// 127.0.0.3:7300 - loopback, unreachable from outside the SSH session,
// and a different address than uot's own relay so a client speaking
// either dialect lands on the right handler.
var udpgwRelayAddr = M.ParseSocksaddr("127.0.0.3:7300")

// udpgwServe runs the whole udpgw protocol on one authenticated
// direct-tcpip channel, for the lifetime of that channel.
func (h *Inbound) udpgwServe(ctx context.Context, conn *channelConn, metadata adapter.InboundContext, user string, fingerprint [32]byte) {
	s := &udpgwSession{
		h:        h,
		conn:     conn,
		user:     user,
		conns:    make(map[uint16]*udpgwConn),
		lastSeen: time.Now(),
	}
	h.conns.TrackAuthenticated(h.Tag(), user, fingerprint, conn, func(error) { conn.Close() })

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		s.readLoop()
	}()

	t := time.NewTicker(udpgwIdleSec * time.Second / 3)
	defer t.Stop()
	for {
		select {
		case <-readerDone:
			s.closeAll()
			return
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.lastSeen)
			s.mu.Unlock()
			if idle > udpgwIdleSec*time.Second {
				conn.Close() // the reader then errors out and the branch above cleans up
				return
			}
		}
	}
}

type udpgwSession struct {
	h    *Inbound
	conn *channelConn
	user string

	mu       sync.Mutex
	conns    map[uint16]*udpgwConn
	lastSeen time.Time
	closed   bool
}

// readLoop pulls client->server frames off the channel until it dies.
func (s *udpgwSession) readLoop() {
	header := make([]byte, udpgwHeaderLen)
	for {
		if _, err := io.ReadFull(s.conn, header); err != nil {
			return
		}
		flags := header[0]
		conid := binary.LittleEndian.Uint16(header[1:3])

		s.mu.Lock()
		s.lastSeen = time.Now()
		s.mu.Unlock()

		if flags&udpgwFlagKeepalive != 0 {
			continue
		}

		var dest M.Socksaddr
		if flags&udpgwFlagIPv6 != 0 {
			addr := make([]byte, udpgwAddrV6Len)
			if _, err := io.ReadFull(s.conn, addr); err != nil {
				return
			}
			ip := net.IP(addr[:16])
			dest = M.SocksaddrFromNet(&net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(addr[16:18]))})
		} else {
			addr := make([]byte, udpgwAddrV4Len)
			if _, err := io.ReadFull(s.conn, addr); err != nil {
				return
			}
			ip := net.IP(addr[:4])
			dest = M.SocksaddrFromNet(&net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(addr[4:6]))})
		}
		payload := make([]byte, udpgwMTU)
		n, err := s.conn.Read(payload)
		if err != nil || n == 0 {
			return
		}
		payload = payload[:n]

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		c := s.conns[conid]
		if c != nil && (flags&udpgwFlagRebind != 0 || c.origAddr != dest) {
			c.pc.Close()
			delete(s.conns, conid)
			c = nil
		}
		if c == nil {
			if len(s.conns) >= udpgwMaxConns {
				// The reference server evicts LRU; these clients use a
				// handful of conids, so refusing a brand-new one beyond the
				// cap is equivalent in practice.
				s.mu.Unlock()
				continue
			}
			pc, lerr := net.ListenPacket("udp", "0.0.0.0:0")
			if lerr != nil {
				s.mu.Unlock()
				return
			}
			c = &udpgwConn{s: s, conid: conid, origAddr: dest, pc: pc}
			s.conns[conid] = c
			go c.readLoop()
		}
		s.mu.Unlock()

		if _, werr := c.pc.WriteTo(payload, dest.UDPAddr()); werr != nil {
			s.closeConn(conid)
			continue
		}
		s.count(int64(len(payload)), 0)
	}
}

// closeConn drops one mapping (errors and rebinding).
func (s *udpgwSession) closeConn(conid uint16) {
	s.mu.Lock()
	c := s.conns[conid]
	delete(s.conns, conid)
	s.mu.Unlock()
	if c != nil {
		c.pc.Close()
	}
}

// closeAll tears every mapping down once, on channel death.
func (s *udpgwSession) closeAll() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := make([]*udpgwConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = map[uint16]*udpgwConn{}
	s.mu.Unlock()
	for _, c := range conns {
		c.pc.Close()
	}
}

// count adds bytes to the user's counters - the udpgw path's UDP traffic
// is accounted per user exactly like the TCP channels are.
func (s *udpgwSession) count(up, down int64) {
	if s.h.trafficMgr != nil {
		s.h.trafficMgr.Add(s.user, up, down)
	}
}

// writeFrame serializes one server->client answer. Every mapping's
// answers share the one channel, so writes hold the session mutex.
func (s *udpgwSession) writeFrame(conid uint16, addr M.Socksaddr, payload []byte) error {
	var flags byte
	var addrBytes []byte
	if addr.Addr.Is6() && !addr.Addr.Is4In6() {
		flags = udpgwFlagIPv6
		addrBytes = make([]byte, udpgwAddrV6Len)
		ip16 := addr.Addr.As16()
		copy(addrBytes, ip16[:])
		binary.BigEndian.PutUint16(addrBytes[16:18], addr.Port)
	} else {
		addrBytes = make([]byte, udpgwAddrV4Len)
		ip4 := addr.Addr.Unmap().As4()
		copy(addrBytes, ip4[:])
		binary.BigEndian.PutUint16(addrBytes[4:6], addr.Port)
	}
	frame := make([]byte, 0, udpgwHeaderLen+len(addrBytes)+len(payload))
	frame = append(frame, flags, byte(conid), byte(conid>>8))
	frame = append(frame, addrBytes...)
	frame = append(frame, payload...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("udpgw: session closed")
	}
	_, err := s.conn.Write(frame)
	return err
}

// udpgwConn is one conid: a UDP socket whose answers are framed back to
// the session's channel. badvpn's own server is exactly this - a plain
// per-flow UDP forwarder - so UDP leaves by the node's own default
// route, byte-counted per user, matching the reference implementation.
type udpgwConn struct {
	s        *udpgwSession
	conid    uint16
	origAddr M.Socksaddr
	pc       net.PacketConn
}

func (c *udpgwConn) readLoop() {
	buf := make([]byte, udpgwMTU)
	for {
		n, addr, err := c.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		origin := M.SocksaddrFromNet(addr)
		if err := c.s.writeFrame(c.conid, origin, buf[:n]); err != nil {
			c.pc.Close()
			return
		}
		c.s.count(0, int64(n))
	}
}
