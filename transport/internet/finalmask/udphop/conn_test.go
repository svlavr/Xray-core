package udphop

import (
	"context"
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func testConfig() *Config {
	return &Config{IntervalMin: 3600, IntervalMax: 3600}
}

func TestRemoteOnlyUDPHopReceivesOnInitialSocket(t *testing.T) {
	server, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	raw, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewUDPHopConnContext(context.Background(), testConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		n, addr, err := server.ReadFromUDP(buffer)
		if err == nil {
			_, err = server.WriteToUDP(buffer[:n], addr)
		}
		echoDone <- err
	}()
	payload := []byte("remote-only")
	if _, err := conn.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", buffer[:n], payload)
	}
	if err := <-echoDone; err != nil {
		t.Fatal(err)
	}
}

type blockingPacketConn struct {
	closed       chan struct{}
	writeEntered chan struct{}
	closeOnce    sync.Once
	writeOnce    sync.Once
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{closed: make(chan struct{}), writeEntered: make(chan struct{})}
}

func (c *blockingPacketConn) ReadFrom([]byte) (int, gonet.Addr, error) {
	<-c.closed
	return 0, nil, gonet.ErrClosed
}

func (c *blockingPacketConn) WriteTo([]byte, gonet.Addr) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	<-c.closed
	return 0, gonet.ErrClosed
}

func (c *blockingPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*blockingPacketConn) LocalAddr() gonet.Addr            { return &gonet.UDPAddr{} }
func (*blockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*blockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPHopCloseUnblocksWriteAndJoinsLoops(t *testing.T) {
	raw := newBlockingPacketConn()
	packetConn, err := NewUDPHopConnContext(context.Background(), testConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := packetConn.WriteTo([]byte("blocked"), &gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 53})
		writeDone <- err
	}()
	<-raw.writeEntered
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked write returned synthetic success")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock and join WriteTo")
	}
	if err := packetConn.Close(); err != nil {
		t.Fatalf("repeated Close = %v", err)
	}
}

func TestUDPHopCloseCancelsBlockedRotationDial(t *testing.T) {
	raw := newBlockingPacketConn()
	packetConn, err := NewUDPHopConnContext(context.Background(), &Config{Local: true, IntervalMin: 3600, IntervalMax: 3600}, raw)
	if err != nil {
		t.Fatal(err)
	}
	conn := packetConn.(*udpHopConn)
	dialEntered := make(chan struct{})
	conn.dial = func(ctx context.Context, _ net.Destination, _ *internet.SocketConfig) (net.Conn, error) {
		close(dialEntered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("blocked"), &gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 53})
		writeDone <- err
	}()
	<-dialEntered
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("canceled initial hop returned synthetic success")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join blocked hop dial")
	}
}

func TestUDPHopRejectsInvalidConfigurationWithoutPanic(t *testing.T) {
	cases := []*Config{
		{IntervalMin: 4, IntervalMax: 5},
		{IntervalMin: 10, IntervalMax: 5},
		{IntervalMin: 5, IntervalMax: 5, RemoteIPs: []string{"not-a-prefix"}},
		{IntervalMin: 5, IntervalMax: 5, RemotePorts: []uint32{1 << 16}},
	}
	for _, config := range cases {
		raw := newBlockingPacketConn()
		if conn, err := NewUDPHopConnContext(context.Background(), config, raw); err == nil {
			_ = conn.Close()
			t.Fatalf("invalid config was accepted: %+v", config)
		}
		_ = raw.Close()
	}
}

var _ gonet.PacketConn = (*blockingPacketConn)(nil)
