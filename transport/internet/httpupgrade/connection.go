package httpupgrade

import (
	"net"

	"github.com/xtls/xray-core/transport/internet"
)

type connection struct {
	net.Conn
	remoteAddr net.Addr
	handoff    *internet.InboundHandoff
}

func newConnection(conn net.Conn, remoteAddr net.Addr, handoff *internet.InboundHandoff) *connection {
	return &connection{
		Conn:       conn,
		remoteAddr: remoteAddr,
		handoff:    handoff,
	}
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) AcceptInboundHandoff() bool { return c.handoff.Accept() }
func (c *connection) RejectInboundHandoff()      { c.handoff.Reject() }
