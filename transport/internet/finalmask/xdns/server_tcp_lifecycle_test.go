package xdns

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type testTCPListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *testTCPListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *testTCPListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *testTCPListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }

type observedTCPConn struct {
	net.Conn
	read, write, closed chan struct{}
	once                sync.Once
}

func (c *observedTCPConn) Read(p []byte) (int, error) {
	if c.read != nil {
		select {
		case c.read <- struct{}{}:
		default:
		}
	}
	return c.Conn.Read(p)
}
func (c *observedTCPConn) Write(p []byte) (int, error) {
	if c.write != nil {
		select {
		case c.write <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(p)
}
func (c *observedTCPConn) Close() error {
	c.once.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return c.Conn.Close()
}

func testPipeServer(t *testing.T) (*xdnsServer, *testTCPListener) {
	t.Helper()
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &testTCPListener{conns: make(chan net.Conn, maxTCPConnections+2), done: make(chan struct{})}
	pc, err := newServer(&Config{Domains: []*DomainProto{testDomain()}, TcpOnly: true}, raw, l)
	if err != nil {
		raw.Close()
		l.Close()
		t.Fatal(err)
	}
	s := pc.(*xdnsServer)
	t.Cleanup(func() { _ = s.Close() })
	return s, l
}

func waitTCP(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("TCP condition timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func testTCPQuery(t *testing.T, c net.Conn, id uint16) {
	t.Helper()
	q := new(mdns.Msg)
	q.SetQuestion("outside.example.", mdns.TypeTXT)
	q.Id = id
	p, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(p)))
	b := net.Buffers{prefix[:], p}
	if _, err := b.WriteTo(c); err != nil {
		t.Fatal(err)
	}
}
func testTCPReply(t *testing.T, c net.Conn) *mdns.Msg {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
	if _, err := io.ReadFull(c, p); err != nil {
		t.Fatal(err)
	}
	r := new(mdns.Msg)
	if err := r.Unpack(p); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServerTCPSlowWriterIsolationAndClose(t *testing.T) {
	s, l := testPipeServer(t)
	left, slow := net.Pipe()
	defer slow.Close()
	observed := &observedTCPConn{Conn: left, write: make(chan struct{}, 1)}
	l.conns <- observed
	var target *tcpServerConn
	waitTCP(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for c := range s.conns {
			if c.Conn == observed {
				target = c
				return true
			}
		}
		return false
	})
	s.writeDNS(make([]byte, 64000), target)
	select {
	case <-observed.write:
	case <-time.After(time.Second):
		t.Fatal("slow writer was not entered")
	}
	// The slow peer never reads. A second connection must still get a real reply.
	other, healthy := net.Pipe()
	defer healthy.Close()
	l.conns <- other
	testTCPQuery(t, healthy, 1234)
	if r := testTCPReply(t, healthy); !r.Response || r.Id != 1234 {
		t.Fatalf("healthy reply: %v", r)
	}
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt blocked TCP write")
	}
}

func TestServerTCPCloseInterruptsPartialRead(t *testing.T) {
	s, l := testPipeServer(t)
	left, peer := net.Pipe()
	defer peer.Close()
	observed := &observedTCPConn{Conn: left, read: make(chan struct{}, 4)}
	l.conns <- observed
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	// ReadFull has consumed one byte and entered a second read for the prefix.
	for range 2 {
		select {
		case <-observed.read:
		case <-time.After(time.Second):
			t.Fatal("partial-prefix read was not entered")
		}
	}
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt partial read")
	}
}

func TestServerTCPConnectionLimit(t *testing.T) {
	s, l := testPipeServer(t)
	var peers []net.Conn
	defer func() {
		for _, p := range peers {
			_ = p.Close()
		}
	}()
	for range maxTCPConnections {
		left, peer := net.Pipe()
		peers = append(peers, peer)
		l.conns <- left
	}
	waitTCP(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) == maxTCPConnections })
	left, peer := net.Pipe()
	peers = append(peers, peer)
	extra := &observedTCPConn{Conn: left, closed: make(chan struct{})}
	l.conns <- extra
	select {
	case <-extra.closed:
	case <-time.After(time.Second):
		t.Fatal("excess connection was not rejected")
	}
	_ = peers[0].Close()
	waitTCP(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) == maxTCPConnections-1 })
	left, peer = net.Pipe()
	peers = append(peers, peer)
	l.conns <- left
	waitTCP(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for c := range s.conns {
			if c.Conn == left {
				return true
			}
		}
		return false
	})
}

func TestServerTCPConstructorRollback(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	l := &testTCPListener{conns: make(chan net.Conn), done: make(chan struct{})}
	_, err = (&Config{TcpOnly: true}).WrapPacketConnServer(raw, raw.LocalAddr(), &finalmask.ListenConfig{Listen: func(net.Addr) (net.Listener, error) { return l, nil }})
	if err == nil {
		t.Fatal("empty domains accepted")
	}
	select {
	case <-l.done:
	default:
		t.Fatal("TCP listener was not closed after construction failed")
	}
}

func TestServerTCPHealthyPipeline(t *testing.T) {
	s := testServer(t, true)
	conn, err := net.Dial("tcp", s.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const count = 16
	written := make(chan error, 1)
	go func() {
		for i := range count {
			q := new(mdns.Msg)
			q.SetQuestion("outside.example.", mdns.TypeTXT)
			q.Id = uint16(i)
			p, err := q.Pack()
			if err != nil {
				written <- err
				return
			}
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], uint16(len(p)))
			b := net.Buffers{prefix[:], p}
			if _, err := b.WriteTo(conn); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	seen := make(map[uint16]bool)
	for range count {
		r := testTCPReply(t, conn)
		if !r.Response || r.Id >= count || seen[r.Id] {
			t.Fatalf("bad pipeline response %v", r)
		}
		seen[r.Id] = true
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestServerTCPOversizeQueryPreservesFraming(t *testing.T) {
	s := testServer(t, true)
	c, err := net.Dial("tcp", s.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], 513)
	b := net.Buffers{prefix[:], make([]byte, 513)}
	if _, err := b.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	testTCPQuery(t, c, 42)
	if r := testTCPReply(t, c); !r.Response || r.Id != 42 {
		t.Fatalf("framing lost after oversized query: %v", r)
	}
}

func TestServerTCPBackpressureBounds(t *testing.T) {
	for _, size := range []int{1, maxDNSMessageSize} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			left, peer := net.Pipe()
			defer peer.Close()
			conn := &tcpServerConn{Conn: left, send: make(chan []byte, maxPendingResponses), done: make(chan struct{})}
			defer conn.Close()
			s := &xdnsServer{closeCh: make(chan struct{})}
			count := min(maxPendingResponses, maxPendingResponseBytes/size)
			p := make([]byte, size)
			for range count {
				s.writeDNS(p, conn)
			}
			select {
			case <-conn.done:
				t.Fatal("connection closed before its response budget filled")
			default:
			}
			if got := conn.pendingBytes.Load(); got != int32(count*size) {
				t.Fatalf("pending bytes %d want%d", got, count*size)
			}
			s.writeDNS(p, conn)
			select {
			case <-conn.done:
			default:
				t.Fatal("overloaded connection remained open")
			}
			if conn.pendingBytes.Load() > maxPendingResponseBytes {
				t.Fatal("pending response bytes exceeded bound")
			}
		})
	}
}
