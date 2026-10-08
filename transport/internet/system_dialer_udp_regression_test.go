package internet

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func udpFixture(t *testing.T, network, address string) net.PacketConn {
	t.Helper()
	peer, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return peer
}

func readUDPPayload(t *testing.T, packet net.PacketConn, want []byte) net.Addr {
	t.Helper()
	if err := packet.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 256)
	n, from, err := packet.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], want) {
		t.Fatalf("bind=%v read=%d source=%v error=%v payload=%q want=%q", packet.LocalAddr(), n, from, err, b[:n], want)
	}
	return from
}

func sendUDPPayload(t *testing.T, packet net.PacketConn, to net.Addr, payload []byte) {
	t.Helper()
	if err := packet.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := packet.WriteTo(payload, to)
	if err != nil || n != len(payload) {
		t.Fatalf("bind=%v to=%v written=%d error=%v", packet.LocalAddr(), to, n, err)
	}
}

// Exercise actual native packet sources and alternate destinations, independently
// of Measurement parsing and without changing the global dialer/controllers.
func TestSystemUDPAlternateIPv4Packets(t *testing.T) {
	peer := udpFixture(t, "udp4", "127.0.0.1:0")
	other := udpFixture(t, "udp4", "127.0.0.1:0")
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(peer.LocalAddr().(*net.UDPAddr).Port))
	conn, err := new(DefaultSystemDialer).Dial(context.Background(), nil, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	packet, ok := conn.(*xnet.PacketConnWrapper)
	if !ok {
		t.Fatalf("native packet type %T", conn)
	}
	for i, target := range []net.PacketConn{peer, other} {
		request := []byte{byte(i), 1, 2, 3}
		sendUDPPayload(t, packet, target.LocalAddr(), request)
		source := readUDPPayload(t, target, request)
		reply := []byte{byte(i), 9, 8, 7}
		sendUDPPayload(t, other, source, reply)
		actual := readUDPPayload(t, packet, reply)
		if actual.String() != other.LocalAddr().String() {
			t.Fatalf("actual source=%v want=%v", actual, other.LocalAddr())
		}
	}
}
