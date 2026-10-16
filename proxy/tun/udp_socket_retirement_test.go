package tun

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestUDPSocketRetirementDiscardsUnreadPackets(t *testing.T) {
	s := &stack{addresses: []netip.Addr{netip.MustParseAddr("10.66.0.2")}, sockets: make(map[netip.AddrPort]*udpSocket)}
	packetConn, err := s.DialUDP()
	if err != nil {
		t.Fatal(err)
	}
	u := packetConn.(*udpSocket)
	queued := buf.New()
	queued.WriteString("unread")
	if !u.queue.push(queued) {
		t.Fatal("queue rejected input")
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if !queued.IsEmpty() {
		t.Fatal("socket retained unread packet")
	}
	if n, _, err := u.ReadFrom(make([]byte, 16)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed read: %d %v", n, err)
	}
	if n, err := u.WriteTo([]byte("closed"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.66.0.1:53"))); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed write: %d %v", n, err)
	}
}
