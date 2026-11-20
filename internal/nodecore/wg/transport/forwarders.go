// Forwarder bodies copied from sing-tun v0.9.0-beta.4 (stack_gvisor_tcp.go,
// stack_gvisor_udp.go, stack_gvisor_icmp.go, stack_gvisor_lazy.go,
// stack_gvisor_tcp_conn.go) with the with_gvisor tag dropped - see the
// package doc comment for why they live here. Each deviation from the
// upstream body is marked "rapido:".
package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/sync"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// TCP (sing-tun stack_gvisor_tcp.go; the loopback-rewrite arm of
// HandlePacket is dropped - rapido: it exists for tun's local-stack
// capture mode, which this stack never runs in)
// ---------------------------------------------------------------------------

type tcpForwarder struct {
	ctx       context.Context
	stack     *stack.Stack
	handler   Handler
	forwarder *tcp.Forwarder
}

func newTCPForwarder(ctx context.Context, stack *stack.Stack, handler Handler) *tcpForwarder {
	forwarder := &tcpForwarder{
		ctx:     ctx,
		stack:   stack,
		handler: handler,
	}
	forwarder.forwarder = tcp.NewForwarder(stack, 0, 1024, forwarder.Forward)
	return forwarder
}

func (f *tcpForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return f.forwarder.HandlePacket(id, pkt)
}

func (f *tcpForwarder) Forward(r *tcp.ForwarderRequest) {
	source := M.SocksaddrFrom(addrFromAddress(r.ID().RemoteAddress), r.ID().RemotePort)
	destination := M.SocksaddrFrom(addrFromAddress(r.ID().LocalAddress), r.ID().LocalPort)
	switch f.handler.JudgeFlow(uint8(header.TCPProtocolNumber), source.AddrPort(), destination.AddrPort(), nil).Action {
	case tun.ActionReject:
		r.Complete(true)
		return
	case tun.ActionDrop:
		r.Complete(false)
		return
	}
	conn := &gLazyConn{
		parentCtx:  f.ctx,
		stack:      f.stack,
		request:    r,
		localAddr:  source.TCPAddr(),
		remoteAddr: destination.TCPAddr(),
	}
	go f.handler.NewConnectionEx(f.ctx, conn, source, destination, nil)
}

// addrFromAddress is sing-tun's tun.AddrFromAddress, restated here for
// the same tag reason as defaultNIC.
func addrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	}
	return netip.AddrFrom4(address.As4())
}

// ---------------------------------------------------------------------------
// UDP (sing-tun stack_gvisor_udp.go)
// ---------------------------------------------------------------------------

type udpForwarder struct {
	ctx     context.Context
	stack   *stack.Stack
	handler Handler
	udpNat  *tun.UDPNat
}

func newUDPForwarder(ctx context.Context, stack *stack.Stack, handler Handler, options tun.UDPNatOptions) *udpForwarder {
	forwarder := &udpForwarder{
		ctx:     ctx,
		stack:   stack,
		handler: handler,
	}
	options.Handler = handler
	options.Prepare = forwarder.PreparePacketConnection
	forwarder.udpNat = tun.NewUDPNat(options)
	return forwarder
}

func (f *udpForwarder) Start() error {
	return f.udpNat.Start()
}

func (f *udpForwarder) Close() error {
	return f.udpNat.Close()
}

func (f *udpForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	source := M.SocksaddrFrom(addrFromAddress(id.RemoteAddress), id.RemotePort)
	destination := M.SocksaddrFrom(addrFromAddress(id.LocalAddress), id.LocalPort)
	data := pkt.Data()
	payload, _ := data.PullUp(data.Size())
	f.udpNat.NewPacket([][]byte{payload}, source, destination, pkt)
	return true
}

func (f *udpForwarder) PreparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	firstPacketBuffer := userData.(*stack.PacketBuffer)
	// rapido: upstream linknames stack.Range.iterate over the payload
	// range; this sagernet/gvisor exposes the same bytes through
	// PacketBuffer.AsSlices.
	var firstPacket []byte
	for _, view := range firstPacketBuffer.AsSlices() {
		if firstPacket == nil {
			firstPacket = view
		} else {
			firstPacket = append(firstPacket[:len(firstPacket):len(firstPacket)], view...)
		}
	}
	var sourceNetwork tcpip.NetworkProtocolNumber
	if source.Addr.Is4() {
		sourceNetwork = header.IPv4ProtocolNumber
	} else {
		sourceNetwork = header.IPv6ProtocolNumber
	}
	switch f.handler.JudgeFlow(uint8(header.UDPProtocolNumber), source.AddrPort(), destination.AddrPort(), firstPacket).Action {
	case tun.ActionReject:
		gWriteUnreachable(f.stack, userData.(*stack.PacketBuffer))
		return false, nil, nil, nil
	case tun.ActionDrop:
		return false, nil, nil, nil
	case tun.ActionHijackDNS:
		// rapido: unreachable - this stack's JudgeFlow always accepts
		// (see Handler's own doc comment) - kept for body parity.
		f.handler.NewDNSPacket(firstPacket, source, destination, &udpBackWriter{
			stack:         f.stack,
			source:        addressFromAddr(source.Addr),
			sourcePort:    source.Port,
			sourceNetwork: sourceNetwork,
		})
		return false, nil, nil, nil
	}
	writer := &udpBackWriter{
		stack:         f.stack,
		packet:        userData.(*stack.PacketBuffer).IncRef(),
		source:        addressFromAddr(source.Addr),
		sourcePort:    source.Port,
		sourceNetwork: sourceNetwork,
	}
	return true, f.ctx, writer, nil
}

// addressFromAddr is sing-tun's tun.AddressFromAddr, restated (tag).
func addressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	}
	return tcpip.AddrFrom4(destination.As4())
}

type udpBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	packet        *stack.PacketBuffer
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *udpBackWriter) HandshakeSuccess() error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.packet != nil {
		w.packet.DecRef()
		w.packet = nil
	}
	return nil
}

func (w *udpBackWriter) HandshakeFailure(err error) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.packet == nil {
		return os.ErrInvalid
	}
	wErr := gWriteUnreachable(w.stack, w.packet)
	w.packet.DecRef()
	w.packet = nil
	return wErr
}

func (w *udpBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	} else if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		defaultNIC,
		addressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)
	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return gonet.TranslateNetstackError(err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}

func gWriteUnreachable(gStack *stack.Stack, packet *stack.PacketBuffer) error {
	if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler).SendRejectionError(packet, stack.RejectIPv4WithICMPPortUnreachable, true))
	} else {
		return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler).SendRejectionError(packet, stack.RejectIPv6WithICMPPortUnreachable, true))
	}
}

// ---------------------------------------------------------------------------
// ICMP (sing-tun stack_gvisor_icmp.go, echo-reply arm only - rapido: the
// flow-tracker arm is for tun's flow accounting, which this stack never
// uses; an echo request from a peer gets its echo reply, everything else
// is dropped)
// ---------------------------------------------------------------------------

type icmpForwarder struct {
	stack   *stack.Stack
	handler Handler
	logger  HandlerLogger
}

func newICMPForwarder(stack *stack.Stack, handler Handler, logger HandlerLogger) *icmpForwarder {
	return &icmpForwarder{stack: stack, handler: handler, logger: logger}
}

func (f *icmpForwarder) Close() error { return nil }

func (f *icmpForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv4(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return false
		}
		switch f.handler.JudgeFlow(
			uint8(header.ICMPv4ProtocolNumber),
			netip.AddrPortFrom(addrFromAddress(ipHdr.SourceAddress()), icmpHdr.Ident()),
			netip.AddrPortFrom(addrFromAddress(ipHdr.DestinationAddress()), icmpHdr.Ident()),
			nil,
		).Action {
		case tun.ActionReject, tun.ActionDrop:
			return true
		}
		icmpHdr.SetType(header.ICMPv4EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], pkt.Data().Checksum()))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(defaultNIC, header.IPv4ProtocolNumber)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "get IPv4 network endpoint"))
			return true
		}
		route, gErr := f.stack.FindRoute(
			defaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv4ProtocolNumber,
			false,
		)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find IPv4 route"))
			return true
		}
		defer route.Release()
		outgoingEP.(ipv4.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv6(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv6EchoRequest {
			return false
		}
		if icmpHdr.Code() != 0 {
			return true
		}
		switch f.handler.JudgeFlow(
			uint8(header.ICMPv6ProtocolNumber),
			netip.AddrPortFrom(addrFromAddress(ipHdr.SourceAddress()), icmpHdr.Ident()),
			netip.AddrPortFrom(addrFromAddress(ipHdr.DestinationAddress()), icmpHdr.Ident()),
			nil,
		).Action {
		case tun.ActionReject, tun.ActionDrop:
			return true
		}
		icmpHdr.SetType(header.ICMPv6EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr,
			Src:         ipHdr.SourceAddress(),
			Dst:         ipHdr.DestinationAddress(),
			PayloadCsum: pkt.Data().Checksum(),
			PayloadLen:  pkt.Data().Size(),
		}))
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(defaultNIC, header.IPv6ProtocolNumber)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "get IPv6 network endpoint"))
			return true
		}
		route, gErr := f.stack.FindRoute(
			defaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find IPv6 route"))
			return true
		}
		defer route.Release()
		outgoingEP.(ipv6.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	}
}

// ---------------------------------------------------------------------------
// gLazyConn + gTCPConn (sing-tun stack_gvisor_lazy.go and
// stack_gvisor_tcp_conn.go, verbatim apart from the package rename)
// ---------------------------------------------------------------------------

type gLazyConn struct {
	tcpConn         *gTCPConn
	parentCtx       context.Context
	stack           *stack.Stack
	request         *tcp.ForwarderRequest
	localAddr       net.Addr
	remoteAddr      net.Addr
	handshakeAccess sync.Mutex
	handshakeDone   bool
	handshakeErr    error
}

func (c *gLazyConn) HandshakeContext(ctx context.Context) error {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	if c.handshakeDone {
		return c.handshakeErr
	}
	defer func() {
		c.handshakeDone = true
	}()
	var (
		wq       waiter.Queue
		endpoint tcpip.Endpoint
	)
	var cancel context.CancelFunc
	if parentDone := c.parentCtx.Done(); parentDone != nil {
		var handshakeCtx context.Context
		handshakeCtx, cancel = context.WithCancel(ctx)
		go func() {
			select {
			case <-parentDone:
				wq.Notify(wq.Events())
			case <-handshakeCtx.Done():
			}
		}()
	}
	endpoint, err := c.request.CreateEndpoint(&wq)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		gErr := gonet.TranslateNetstackError(err)
		c.handshakeErr = gErr
		c.request.Complete(true)
		return gErr
	}
	c.request.Complete(false)
	endpoint.SocketOptions().SetKeepAlive(true)
	tcpConn := newGTCPConn(&wq, endpoint, c.localAddr, c.remoteAddr)
	c.tcpConn = tcpConn
	return nil
}

func (c *gLazyConn) HandshakeFailure(err error) error {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	if c.handshakeDone {
		return os.ErrInvalid
	}
	c.request.Complete(true)
	c.handshakeDone = true
	c.handshakeErr = err
	return nil
}

func (c *gLazyConn) HandshakeSuccess() error {
	return c.HandshakeContext(context.Background())
}

func (c *gLazyConn) NeedHandshakeForRead() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return !c.handshakeDone
}

func (c *gLazyConn) NeedHandshakeForWrite() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return !c.handshakeDone
}

func (c *gLazyConn) Read(b []byte) (n int, err error) {
	err = c.HandshakeContext(context.Background())
	if err != nil {
		return
	}
	return c.tcpConn.Read(b)
}

func (c *gLazyConn) Write(b []byte) (n int, err error) {
	err = c.HandshakeContext(context.Background())
	if err != nil {
		return
	}
	return c.tcpConn.Write(b)
}

func (c *gLazyConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *gLazyConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *gLazyConn) SetDeadline(t time.Time) error {
	err := c.HandshakeContext(context.Background())
	if err != nil {
		return err
	}
	return c.tcpConn.SetDeadline(t)
}

func (c *gLazyConn) SetReadDeadline(t time.Time) error {
	err := c.HandshakeContext(context.Background())
	if err != nil {
		return err
	}
	return c.tcpConn.SetReadDeadline(t)
}

func (c *gLazyConn) SetWriteDeadline(t time.Time) error {
	err := c.HandshakeContext(context.Background())
	if err != nil {
		return err
	}
	return c.tcpConn.SetWriteDeadline(t)
}

func (c *gLazyConn) Close() error {
	if c.closeBeforeHandshake() {
		return nil
	}
	return c.tcpConn.Close()
}

func (c *gLazyConn) CloseRead() error {
	if c.closeBeforeHandshake() {
		return nil
	}
	return c.tcpConn.CloseRead()
}

func (c *gLazyConn) CloseWrite() error {
	if c.closeBeforeHandshake() {
		return nil
	}
	return c.tcpConn.CloseWrite()
}

func (c *gLazyConn) closeBeforeHandshake() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	if !c.handshakeDone {
		if c.request != nil {
			c.request.Complete(true)
		}
		c.handshakeErr = net.ErrClosed
		c.handshakeDone = true
		return true
	}
	return c.handshakeErr != nil
}

func (c *gLazyConn) ReaderReplaceable() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return c.handshakeDone && c.handshakeErr == nil
}

func (c *gLazyConn) WriterReplaceable() bool {
	c.handshakeAccess.Lock()
	defer c.handshakeAccess.Unlock()
	return c.handshakeDone && c.handshakeErr == nil
}

func (c *gLazyConn) Upstream() any {
	return c.tcpConn
}

var (
	_ net.Conn     = (*gTCPConn)(nil)
	_ N.ReadWaiter = (*gTCPConn)(nil)
)

type gTCPConn struct {
	gTCPDeadline

	wq *waiter.Queue
	ep tcpip.Endpoint

	localAddr  net.Addr
	remoteAddr net.Addr

	readMu         sync.Mutex
	readWaitOption N.ReadWaitOptions
}

func newGTCPConn(wq *waiter.Queue, ep tcpip.Endpoint, localAddr net.Addr, remoteAddr net.Addr) *gTCPConn {
	conn := &gTCPConn{
		wq:         wq,
		ep:         ep,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	conn.gTCPDeadline.init()
	return conn
}

func (c *gTCPConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOption = options
	return false
}

func (c *gTCPConn) WaitReadBuffer() (*buf.Buffer, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	deadline := c.readCancel()
	for {
		if err := c.waitReadable(deadline); err != nil {
			return nil, err
		}
		buffer := c.readWaitOption.NewBuffer()
		writer := tcpip.SliceWriter(buffer.FreeBytes())
		result, err := c.ep.Read(&writer, tcpip.ReadOptions{})
		if _, wouldBlock := err.(*tcpip.ErrWouldBlock); wouldBlock {
			buffer.Release()
			continue
		}
		if err != nil {
			buffer.Release()
			return nil, c.translateReadError(err)
		}
		if result.Count == 0 {
			buffer.Release()
			continue
		}
		buffer.Truncate(result.Count)
		c.readWaitOption.PostReturn(buffer)
		c.ep.ModerateRecvBuf(result.Count)
		return buffer, nil
	}
}

func (c *gTCPConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	writer := tcpip.SliceWriter(b)
	n, err := c.readTo(&writer, c.readCancel())
	if n != 0 {
		c.ep.ModerateRecvBuf(n)
	}
	return n, err
}

func (c *gTCPConn) readTo(writer io.Writer, deadline <-chan struct{}) (int, error) {
	select {
	case <-deadline:
		return 0, c.newOpError("read", os.ErrDeadlineExceeded)
	default:
	}

	result, err := c.ep.Read(writer, tcpip.ReadOptions{})
	if _, wouldBlock := err.(*tcpip.ErrWouldBlock); wouldBlock {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		c.wq.EventRegister(&waitEntry)
		defer c.wq.EventUnregister(&waitEntry)
		for {
			result, err = c.ep.Read(writer, tcpip.ReadOptions{})
			if _, wouldBlock = err.(*tcpip.ErrWouldBlock); !wouldBlock {
				break
			}
			select {
			case <-deadline:
				return 0, c.newOpError("read", os.ErrDeadlineExceeded)
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return 0, c.translateReadError(err)
	}
	return result.Count, nil
}

func (c *gTCPConn) waitReadable(deadline <-chan struct{}) error {
	select {
	case <-deadline:
		return c.newOpError("read", os.ErrDeadlineExceeded)
	default:
	}
	if c.ep.Readiness(waiter.ReadableEvents)&waiter.ReadableEvents != 0 {
		return nil
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.wq.EventRegister(&waitEntry)
	defer c.wq.EventUnregister(&waitEntry)
	for c.ep.Readiness(waiter.ReadableEvents)&waiter.ReadableEvents == 0 {
		select {
		case <-deadline:
			return c.newOpError("read", os.ErrDeadlineExceeded)
		case <-notifyCh:
		}
	}
	return nil
}

func (c *gTCPConn) translateReadError(err tcpip.Error) error {
	if _, closed := err.(*tcpip.ErrClosedForReceive); closed {
		return io.EOF
	}
	return c.newOpError("read", gonet.TranslateNetstackError(err))
}

func (c *gTCPConn) Write(b []byte) (int, error) {
	deadline := c.writeCancel()

	select {
	case <-deadline:
		return 0, c.newOpError("write", os.ErrDeadlineExceeded)
	default:
	}

	var (
		reader bytes.Reader
		nBytes int
		entry  waiter.Entry
		ch     <-chan struct{}
	)
	for nBytes != len(b) {
		reader.Reset(b[nBytes:])
		n, err := c.ep.Write(&reader, tcpip.WriteOptions{})
		nBytes += int(n)
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			if ch == nil {
				entry, ch = waiter.NewChannelEntry(waiter.WritableEvents)
				c.wq.EventRegister(&entry)
				defer c.wq.EventUnregister(&entry)
			} else {
				select {
				case <-deadline:
					return nBytes, c.newOpError("write", os.ErrDeadlineExceeded)
				case <-ch:
					continue
				}
			}
		default:
			return nBytes, c.newOpError("write", gonet.TranslateNetstackError(err))
		}
	}
	return nBytes, nil
}

func (c *gTCPConn) Close() error {
	c.ep.Close()
	return nil
}

func (c *gTCPConn) CloseRead() error {
	if err := c.ep.Shutdown(tcpip.ShutdownRead); err != nil {
		return c.newOpError("close", errors.New(err.String()))
	}
	return nil
}

func (c *gTCPConn) CloseWrite() error {
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		return c.newOpError("close", errors.New(err.String()))
	}
	return nil
}

func (c *gTCPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *gTCPConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *gTCPConn) SetDeadline(t time.Time) error {
	return c.gTCPDeadline.SetDeadline(t)
}

func (c *gTCPConn) SetReadDeadline(t time.Time) error {
	return c.gTCPDeadline.SetReadDeadline(t)
}

func (c *gTCPConn) SetWriteDeadline(t time.Time) error {
	return c.gTCPDeadline.SetWriteDeadline(t)
}

func (c *gTCPConn) newOpError(op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Source: c.localAddr,
		Addr:   c.remoteAddr,
		Err:    err,
	}
}

type gTCPDeadline struct {
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *gTCPDeadline) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *gTCPDeadline) readCancel() <-chan struct{} {
	d.mu.Lock()
	cancelCh := d.readCancelCh
	d.mu.Unlock()
	return cancelCh
}

func (d *gTCPDeadline) writeCancel() <-chan struct{} {
	d.mu.Lock()
	cancelCh := d.writeCancelCh
	d.mu.Unlock()
	return cancelCh
}

func (d *gTCPDeadline) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *gTCPDeadline) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *gTCPDeadline) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

func (d *gTCPDeadline) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	if t.IsZero() {
		*timer = nil
		return
	}

	timeout := time.Until(t)
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}
