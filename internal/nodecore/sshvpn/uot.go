package sshvpn

import (
	"context"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/legendary1205/rapido-go/internal/nodecore/traffic"
)

// serveUoTChannel carries UDP over the SSH session as a length-framed
// stream on one direct-tcpip channel (see the package doc comment). The
// sing/common/uot wire format is read here so a sing-box-family client
// speaks its own native dialect; an ordinary SOCKS-over-SSH client
// (ssh -D) never reaches this branch - a SOCKS server's UDP ASSOCIATE
// reply names a UDP socket, which nothing over direct-tcpip can dial.
func (h *Inbound) serveUoTChannel(ctx context.Context, conn *channelConn, metadata adapter.InboundContext, user string, fingerprint [32]byte) {
	request, err := uot.ReadRequest(conn)
	if err != nil {
		h.logger.ErrorContext(ctx, "sshvpn: read UoT request: ", err)
		conn.Close()
		return
	}
	metadata.Destination = request.Destination
	packetConn := N.PacketConn(&deadlineFreePacketConn{PacketConn: uot.NewConn(conn, *request)})

	onClose := func(err error) { conn.Close() }
	onClose = h.conns.TrackAuthenticated(h.Tag(), user, fingerprint, conn, onClose)
	if h.trafficMgr != nil {
		packetConn = traffic.WrapPacketConn(packetConn, user, h.trafficMgr)
	}
	h.router.RoutePacketConnectionEx(ctx, packetConn, metadata, onClose)
}

// deadlineFreePacketConn hides deadlines from the router: an SSH channel
// has none (channelConn's own stance), and the counter/route layers would
// otherwise forward deadline calls that can only fail.
type deadlineFreePacketConn struct {
	N.PacketConn
}

func (c *deadlineFreePacketConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (c *deadlineFreePacketConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (c *deadlineFreePacketConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }
