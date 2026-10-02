package xdns

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type shutdownSocket struct {
	net.Conn
	addr    net.Addr
	started chan struct{}
	closed  chan struct{}
	read    sync.Once
	close   sync.Once
}

func (s *shutdownSocket) Read([]byte) (int, error) {
	s.read.Do(func() { close(s.started) })
	<-s.closed
	return 0, io.EOF
}

func (s *shutdownSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := s.Read(p)
	return n, s.addr, err
}

func (s *shutdownSocket) Write(p []byte) (int, error) { return len(p), nil }
func (s *shutdownSocket) WriteTo(p []byte, _ net.Addr) (int, error) {
	return s.Write(p)
}

func (s *shutdownSocket) Close() error {
	s.close.Do(func() { close(s.closed) })
	return nil
}
func (s *shutdownSocket) RemoteAddr() net.Addr { return s.addr }

func shutdownDialer(t *testing.T, tcp bool) (*shutdownSocket, *finalmask.Dialer, *serial.TypedMessage) {
	t.Helper()
	socket := &shutdownSocket{started: make(chan struct{}), closed: make(chan struct{})}
	t.Cleanup(func() { socket.Close() })
	if tcp {
		socket.addr = &net.TCPAddr{IP: net.LocalHostIP.IP(), Port: 53}
		return socket, &finalmask.Dialer{DialTCP: func(net.Destination) (net.Conn, error) { return socket, nil }}, serial.ToTypedMessage(&TCPResolverProto{Addr: "127.0.0.1:53"})
	}
	socket.addr = &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: 53}
	return socket, &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
		return &net.PacketConnWrapper{PacketConn: socket, Dest: socket.addr}, nil
	}}, serial.ToTypedMessage(&UDPResolverProto{Addr: "127.0.0.1:53"})
}

func TestXDNSResolverCloseJoinsReceiver(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			socket, dialer, config := shutdownDialer(t, tcp)
			resolver, err := NewResolver(config, dialer)
			if err != nil {
				t.Fatal(err)
			}
			<-socket.started
			done := make(chan struct{})
			go func() { resolver.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("resolver Close cannot join receiver")
			}
			resolver.Close()
			if _, err := resolver.Read(make([]byte, 1)); err != io.ErrClosedPipe {
				t.Fatalf("read after close: %v", err)
			}
		})
	}
}

func TestXDNSClientConstructionClosesEarlierResolvers(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			socket, dialer, config := shutdownDialer(t, tcp)
			client, err := NewClient(&Config{
				Domains:   []*DomainProto{{Name: "example.com", LenLimit: 200, LabelLimit: 63, Types: []int32{1}}},
				Resolvers: []*serial.TypedMessage{config, serial.ToTypedMessage(&Config{})},
			}, dialer)
			if err == nil || client != nil {
				t.Fatalf("constructor outcome: %v %v", client, err)
			}
			select {
			case <-socket.closed:
			case <-time.After(time.Second):
				t.Fatal("constructor leaked earlier resolver socket")
			}
		})
	}
}
