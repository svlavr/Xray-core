package socks

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type responseResultConn struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c responseResultConn) Write(p []byte) (int, error) { return c.write(p) }

func TestSOCKSUDPResponseReceipts(t *testing.T) {
	for _, mode := range []string{"full", "full-error", "partial-error", "zero-error", "oversized", "missing-header", "encode-error"} {
		t.Run(mode, func(t *testing.T) {
			manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
			view, _ := manager.EnableInspection(fs.ObservationOptions{})
			defer manager.Close()
			flow := manager.Observation().Begin(cnet.Network_UDP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.OutboundRef{Tag: "tag-1"})
			ctx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: flow})
			request := &protocol.RequestHeader{Address: cnet.LocalHostIP, Port: 53}
			if mode == "encode-error" {
				request.Address = cnet.DomainAddress(strings.Repeat("d", 257))
			}
			if mode != "missing-header" {
				ctx = protocol.ContextWithRequestHeader(ctx, request)
			}
			payload := buf.New()
			payload.WriteString("logical payload")
			if mode == "oversized" {
				payload.Release()
				payload = buf.New()
				payload.Extend(buf.Size)
			}
			want := uint64(payload.Len())
			var calls int
			var encoded int64
			conn := responseResultConn{write: func(p []byte) (int, error) {
				calls++
				encoded = int64(len(p))
				switch mode {
				case "full-error":
					return len(p), errors.New("error after full datagram")
				case "partial-error":
					encoded--
					return len(p) - 1, errors.New("short framed datagram")
				case "zero-error":
					encoded = 0
					return 0, errors.New("no accepted datagram")
				default:
					return len(p), nil
				}
			}}
			counter := new(appstats.Counter)
			writeUDPResponse(ctx, &stat.CounterConnection{Connection: conn, WriteCounter: counter}, &protocoludp.Packet{Payload: payload})
			if got := counter.Value(); got != encoded {
				t.Fatalf("native encoded count: %d, want actual write result %d", got, encoded)
			}
			if !payload.IsEmpty() {
				t.Fatal("response did not release input")
			}
			flow.Finish()
			totals, err := view.ReadTotals()
			if err != nil {
				t.Fatal(err)
			}
			fact := totals.User.Downlink
			switch mode {
			case "full", "full-error":
				if fact != want {
					t.Fatalf("decoded packet bytes: %d want %d", fact, want)
				}
			case "partial-error":
				if fact != 0 {
					t.Fatalf("failed packet invented bytes: %d", fact)
				}
			default:
				if fact != 0 {
					t.Fatalf("failed packet invented bytes: %d", fact)
				}
			}
			if (mode == "missing-header" || mode == "encode-error") && calls != 0 {
				t.Fatal("invalid encoding reached writer")
			}
		})
	}
}

type inspectionCloseConn struct {
	net.Conn
	calls atomic.Int32
}

func (c *inspectionCloseConn) Close() error { c.calls.Add(1); return nil }

type inspectionClosePacketConn struct {
	net.PacketConn
	calls atomic.Int32
	err   error
}

func (c *inspectionClosePacketConn) Close() error { c.calls.Add(1); return c.err }

func TestSOCKSTempUDPConnCloseIsIdempotent(t *testing.T) {
	tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
	conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
	conn.observed = true
	conn.SetTimeout(time.Hour)
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if tcp.calls.Load() != 1 || udp.calls.Load() != 1 {
		t.Fatalf("recursive/concurrent close: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
	}
}

func TestSOCKSTempUDPConnTimeoutInitialization(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Nanosecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			for range 16 {
				tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
				conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
				conn.observed = true
				conn.SetTimeout(timeout)
				deadline := time.Now().Add(time.Second)
				for udp.calls.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				if tcp.calls.Load() != 1 || udp.calls.Load() != 1 {
					t.Fatalf("timeout/native cleanup: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
				}
			}
		})
	}
}

func TestSOCKSTempUDPConnCloseBeforeSetTimeout(t *testing.T) {
	for _, observed := range []bool{false, true} {
		name := "native"
		if observed {
			name = "observed"
		}
		t.Run(name, func(t *testing.T) {
			tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
			conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
			conn.observed = observed
			if conn.Timer == nil {
				t.Fatal("constructor did not initialize timer")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			conn.SetTimeout(time.Nanosecond)
			if tcp.calls.Load() == 0 || udp.calls.Load() == 0 {
				t.Fatal("close did not release both sockets")
			}
			if observed && (tcp.calls.Load() != 1 || udp.calls.Load() != 1) {
				t.Fatalf("selected callback duplicated close: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
			}
		})
	}
}

func TestSOCKSTempUDPConnClosePreservesSocketError(t *testing.T) {
	want := errors.New("selected socket close error")
	tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{err: want}
	conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
	conn.observed = true
	if err := conn.Close(); err != want {
		t.Fatalf("first close lost socket error: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
	if tcp.calls.Load() != 1 || udp.calls.Load() != 1 {
		t.Fatalf("callback took close custody: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
	}
}

func TestSOCKSTempUDPConnConcurrentCloseAndTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Nanosecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			for range 16 {
				tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
				conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
				conn.observed = true
				var group sync.WaitGroup
				group.Go(func() { conn.SetTimeout(timeout) })
				for range 16 {
					group.Go(func() {
						if err := conn.Close(); err != nil {
							t.Error(err)
						}
					})
				}
				group.Wait()
				if tcp.calls.Load() != 1 || udp.calls.Load() != 1 {
					t.Fatalf("timeout/concurrent close: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
				}
			}
		})
	}
}

func TestSOCKSTempUDPConnNativeTimeoutInitialization(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Nanosecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
			conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
			defer conn.Close()
			conn.SetTimeout(timeout)
			deadline := time.Now().Add(time.Second)
			for udp.calls.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if tcp.calls.Load() == 0 || udp.calls.Load() == 0 {
				t.Fatal("native timeout did not close both sockets")
			}
		})
	}
}

type inspectionReadPacketConn struct {
	*net.UDPConn
	reads chan net.Addr
}

func (c *inspectionReadPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, remote, err := c.UDPConn.ReadFrom(b)
	if err == nil {
		c.reads <- remote
	}
	return n, remote, err
}

func TestSOCKSTempUDPConnLoopback(t *testing.T) {
	for _, observed := range []bool{false, true} {
		name := "native"
		if observed {
			name = "observed"
		}
		t.Run(name, func(t *testing.T) {
			listen := func() *net.UDPConn {
				t.Helper()
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				return conn
			}
			udp, peer, foreign := listen(), listen(), listen()
			reads := &inspectionReadPacketConn{UDPConn: udp, reads: make(chan net.Addr, 2)}
			tcp := &inspectionCloseConn{}
			conn := NewTempUDPConn(reads, tcp, peer.LocalAddr().(*net.UDPAddr))
			conn.observed = observed
			defer conn.Close()
			conn.SetTimeout(time.Hour)
			type result struct {
				payload string
				err     error
			}
			done := make(chan result, 1)
			go func() {
				b := make([]byte, 128)
				n, err := conn.Read(b)
				done <- result{string(b[:n]), err}
			}()
			if _, err := foreign.WriteToUDP([]byte("wrong source port"), udp.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			select {
			case remote := <-reads.reads:
				if remote.String() != foreign.LocalAddr().String() {
					t.Fatalf("negative control reached unexpected source: %v", remote)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("negative-control datagram did not reach socket owner")
			}
			if _, err := peer.WriteToUDP([]byte("accepted payload"), udp.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-done:
				if got.err != nil || got.payload != "accepted payload" {
					t.Fatalf("accepted datagram: %+v", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("accepted datagram was not forwarded")
			}
			if _, err := conn.Write([]byte("reply payload")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 128)
			n, remote, err := peer.ReadFromUDP(b)
			if err != nil || string(b[:n]) != "reply payload" || remote.String() != udp.LocalAddr().String() {
				t.Fatalf("reply destination/payload: payload=%q remote=%v error=%v", b[:n], remote, err)
			}
		})
	}
}
