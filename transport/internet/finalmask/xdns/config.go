package xdns

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewClient(c, dialer)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	if !c.TcpOnly {
		return NewServer(c, conn)
	}
	if lc == nil || lc.Listen == nil {
		return nil, errors.New("tcpOnly requires a TCP listener")
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("tcpOnly requires a UDP listen address")
	}
	listener, err := lc.Listen(&net.TCPAddr{IP: local.IP, Port: local.Port, Zone: local.Zone})
	if err != nil {
		return nil, err
	}
	server, err := newServer(c, conn, listener)
	if err != nil {
		_ = listener.Close()
	}
	return server, err
}
