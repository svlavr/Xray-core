package xdns

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

var errHeldPacketClose = stderrors.New("held packet close")

type lifecyclePacketConn struct {
	closeOnce    sync.Once
	closed       chan struct{}
	closeStarted chan struct{}
	closeRelease <-chan struct{}
	closeErr     error
	closeCalls   atomic.Int32
	writes       atomic.Int32
}

func newLifecyclePacketConn(release <-chan struct{}, closeErr error) *lifecyclePacketConn {
	return &lifecyclePacketConn{
		closed:       make(chan struct{}),
		closeStarted: make(chan struct{}),
		closeRelease: release,
		closeErr:     closeErr,
	}
}

func (c *lifecyclePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *lifecyclePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		c.writes.Add(1)
		return len(p), nil
	}
}

func (c *lifecyclePacketConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() {
		close(c.closeStarted)
		if c.closeRelease != nil {
			<-c.closeRelease
		}
		close(c.closed)
	})
	return c.closeErr
}

func (*lifecyclePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*lifecyclePacketConn) SetDeadline(time.Time) error      { return nil }
func (*lifecyclePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*lifecyclePacketConn) SetWriteDeadline(time.Time) error { return nil }

func testClientConfig() *Config {
	return &Config{Resolvers: []string{"example.com+udp://127.0.0.1:53"}}
}

func testServerConfig() *Config { return &Config{Domains: []string{"example.com"}} }

func TestSignalStopStartsRawCloseWithoutWaitingAndCloseJoins(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(net.PacketConn) (net.PacketConn, error)
		stop func(net.PacketConn)
	}{
		{
			name: "client",
			wrap: func(raw net.PacketConn) (net.PacketConn, error) { return NewConnClient(testClientConfig(), raw) },
			stop: func(conn net.PacketConn) { conn.(*xdnsConnClient).SignalStop() },
		},
		{
			name: "server",
			wrap: func(raw net.PacketConn) (net.PacketConn, error) { return NewConnServer(testServerConfig(), raw) },
			stop: func(conn net.PacketConn) { conn.(*xdnsConnServer).SignalStop() },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			release := make(chan struct{})
			raw := newLifecyclePacketConn(release, errHeldPacketClose)
			conn, err := test.wrap(raw)
			if err != nil {
				t.Fatal(err)
			}
			stopped := make(chan struct{})
			go func() {
				test.stop(conn)
				close(stopped)
			}()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("SignalStop waited for raw Close")
			}
			select {
			case <-raw.closeStarted:
			case <-time.After(time.Second):
				t.Fatal("SignalStop did not start raw Close")
			}
			closed := make(chan error, 2)
			go func() { closed <- conn.Close() }()
			go func() { closed <- conn.Close() }()
			select {
			case err := <-closed:
				t.Fatalf("Close returned before raw receipt: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			for range 2 {
				select {
				case err := <-closed:
					if !stderrors.Is(err, errHeldPacketClose) {
						t.Fatalf("Close error = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("Close did not join raw and loop receipts")
				}
			}
			if calls := raw.closeCalls.Load(); calls != 1 {
				t.Fatalf("raw Close calls = %d, want 1", calls)
			}
		})
	}
}

func TestContextualWrappersJoinResourceLifecycle(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(context.Context, net.PacketConn) (net.PacketConn, error)
	}{
		{
			name: "client",
			wrap: func(ctx context.Context, raw net.PacketConn) (net.PacketConn, error) {
				return NewConnClientContext(ctx, testClientConfig(), raw)
			},
		},
		{
			name: "server",
			wrap: func(ctx context.Context, raw net.PacketConn) (net.PacketConn, error) {
				return NewConnServerContext(ctx, testServerConfig(), raw)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := internet.NewResourceLifecycle(context.Background())
			ctx := internet.ContextWithResourceLifecycle(owner.Context(), owner)
			raw := newLifecyclePacketConn(nil, nil)
			conn, err := test.wrap(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.CloseAndWait(); err != nil {
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if calls := raw.closeCalls.Load(); calls != 1 {
				t.Fatalf("raw Close calls = %d, want 1", calls)
			}
		})
	}
}

func TestContextCancellationClosesAndJoinsClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	raw := newLifecyclePacketConn(nil, nil)
	conn, err := NewConnClientContext(ctx, testClientConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-raw.closed:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not close raw connection")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("late"), &net.UDPAddr{}); !stderrors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("post-close WriteTo error = %v", err)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 1)); !stderrors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close ReadFrom error = %v", err)
	}
}

func TestPreCanceledContextClosesAndJoinsWrappers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, construct := range []func(context.Context, net.PacketConn) (net.PacketConn, error){
		func(ctx context.Context, raw net.PacketConn) (net.PacketConn, error) {
			return NewConnClientContext(ctx, testClientConfig(), raw)
		},
		func(ctx context.Context, raw net.PacketConn) (net.PacketConn, error) {
			return NewConnServerContext(ctx, testServerConfig(), raw)
		},
	} {
		raw := newLifecyclePacketConn(nil, nil)
		conn, err := construct(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-raw.closed:
		case <-time.After(time.Second):
			t.Fatal("pre-canceled context did not close raw connection")
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientConcurrentWriteAndClose(t *testing.T) {
	raw := newLifecyclePacketConn(nil, nil)
	conn, err := NewConnClient(testClientConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var writers sync.WaitGroup
	for range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			for range 64 {
				_, _ = conn.WriteTo([]byte("payload"), &net.UDPAddr{})
			}
		}()
	}
	close(start)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	writers.Wait()
	if _, err := conn.WriteTo([]byte("late"), &net.UDPAddr{}); !stderrors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("post-close WriteTo error = %v", err)
	}
}

func TestClosedWrappersDoNotPublishBufferedReads(t *testing.T) {
	for _, construct := range []func(net.PacketConn) (net.PacketConn, chan *packet, error){
		func(raw net.PacketConn) (net.PacketConn, chan *packet, error) {
			conn, err := NewConnClient(testClientConfig(), raw)
			if err != nil {
				return nil, nil, err
			}
			return conn, conn.(*xdnsConnClient).readQueue, nil
		},
		func(raw net.PacketConn) (net.PacketConn, chan *packet, error) {
			conn, err := NewConnServer(testServerConfig(), raw)
			if err != nil {
				return nil, nil, err
			}
			return conn, conn.(*xdnsConnServer).readQueue, nil
		},
	} {
		raw := newLifecyclePacketConn(nil, nil)
		conn, readQueue, err := construct(raw)
		if err != nil {
			t.Fatal(err)
		}
		readQueue <- &packet{p: []byte("stale"), addr: &net.UDPAddr{}}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := conn.ReadFrom(make([]byte, 16)); !stderrors.Is(err, net.ErrClosed) {
			t.Fatalf("post-close buffered ReadFrom error = %v", err)
		}
	}
}

func TestServerRetiresExactQueueWithoutClosingDataChannels(t *testing.T) {
	raw := newLifecyclePacketConn(nil, nil)
	wrapped, err := NewConnServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	server := wrapped.(*xdnsConnServer)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}
	server.mutex.Lock()
	oldQueue := server.ensureQueue(addr)
	oldQueue.last = time.Now().Add(-idleTimeout)
	server.mutex.Unlock()
	server.retireIdleQueues(time.Now())
	select {
	case <-oldQueue.retireDone:
	default:
		t.Fatal("idle queue did not publish retirement")
	}
	if n, err := server.WriteTo([]byte("new"), addr); err != nil || n != 3 {
		t.Fatalf("replacement WriteTo = %d, %v", n, err)
	}
	server.mutex.Lock()
	newQueue := server.writeQueueMap[addr.String()]
	server.mutex.Unlock()
	if newQueue == nil || newQueue == oldQueue {
		t.Fatal("retired queue was reused instead of replaced")
	}
	server.stash(oldQueue, []byte("stale"))
	if len(oldQueue.stash) != 0 {
		t.Fatal("stale payload entered retired stash")
	}
	if len(newQueue.stash) != 0 || len(newQueue.queue) != 1 {
		t.Fatal("stale retirement mutated replacement queue")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerCloseInterruptsResponseWaitAndCleaner(t *testing.T) {
	raw := newLifecyclePacketConn(nil, nil)
	wrapped, err := NewConnServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	server := wrapped.(*xdnsConnServer)
	server.ch <- &record{
		Resp:       &Message{Question: []Question{{Name: Name{[]byte("example"), []byte("com")}, Type: RRTypeTXT, Class: ClassIN}}},
		Addr:       &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 53},
		ClientAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3)},
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.mutex.Lock()
		waiting := len(server.writeQueueMap) != 0
		server.mutex.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("send loop did not enter response wait")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server Close did not interrupt response wait and cleaner")
	}
}

func TestServerConcurrentWriteStashAndClose(t *testing.T) {
	raw := newLifecyclePacketConn(nil, nil)
	wrapped, err := NewConnServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	server := wrapped.(*xdnsConnServer)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 4), Port: 4}
	server.mutex.Lock()
	q := server.ensureQueue(addr)
	server.mutex.Unlock()
	start := make(chan struct{})
	var producers sync.WaitGroup
	for index := range 8 {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for range 64 {
				if index%2 == 0 {
					_, _ = server.WriteTo([]byte("payload"), addr)
				} else {
					server.stash(q, []byte("payload"))
				}
			}
		}()
	}
	close(start)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	producers.Wait()
	if _, err := server.WriteTo([]byte("late"), addr); !stderrors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("post-close WriteTo error = %v", err)
	}
}

func TestSealedResourceOwnerRejectsConstructionWithoutClosingRaw(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	owner.SignalStop()
	ctx := internet.ContextWithResourceLifecycle(owner.Context(), owner)
	for _, construct := range []func(context.Context, net.PacketConn) (net.PacketConn, error){
		func(ctx context.Context, raw net.PacketConn) (net.PacketConn, error) {
			return NewConnClientContext(ctx, testClientConfig(), raw)
		},
		func(ctx context.Context, raw net.PacketConn) (net.PacketConn, error) {
			return NewConnServerContext(ctx, testServerConfig(), raw)
		},
	} {
		raw := newLifecyclePacketConn(nil, nil)
		if _, err := construct(ctx, raw); err == nil {
			t.Fatal("sealed owner admitted xdns wrapper")
		}
		if calls := raw.closeCalls.Load(); calls != 0 {
			t.Fatalf("failed constructor closed caller-owned raw connection %d times", calls)
		}
	}
}
