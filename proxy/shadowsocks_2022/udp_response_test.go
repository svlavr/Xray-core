package shadowsocks_2022

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type responseBatchReader func() (buf.MultiBuffer, error)

func (r responseBatchReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return r() }

type responsePacketConn struct {
	*authPacketConn
	peer  net.Addr
	write func([]byte, net.Addr) (int, error)
}

func (c *responsePacketConn) RemoteAddr() net.Addr { return c.peer }

func (c *responsePacketConn) WriteTo(p []byte, peer net.Addr) (int, error) {
	return c.write(p, peer)
}

func responseBuffer(payload string) *buf.Buffer {
	b := buf.New()
	b.Write([]byte(payload))
	return b
}

func responseEntry(t *testing.T, reader buf.Reader) (*udpConnEntry, context.Context, *int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	closed := new(int)
	e := &udpConnEntry{link: &transport.Link{Reader: reader}, cancel: cancel, onClose: func() { *closed++ }}
	e.setTimer(signal.CancelAfterInactivity(ctx, func() { e.Close() }, time.Hour))
	t.Cleanup(func() { e.Close() })
	return e, ctx, closed
}

func TestUDPResponsesDestinationsEncodingAndRebind(t *testing.T) {
	fallback := net.UDPDestination(net.LocalHostIP, 1001)
	explicit := net.UDPDestination(net.LocalHostIP, 1002)
	mb := buf.MultiBuffer{responseBuffer("a"), responseBuffer("b"), responseBuffer("bad"), responseBuffer("c")}
	owned := append(buf.MultiBuffer(nil), mb...)
	mb[1].UDP = &explicit
	read := false
	e, ctx, closed := responseEntry(t, responseBatchReader(func() (buf.MultiBuffer, error) {
		if read {
			return nil, io.EOF
		}
		read = true
		return mb, nil
	}))
	first, second := newAuthPacketConn(), newAuthPacketConn()
	defer first.Close()
	defer second.Close()
	var got []string
	secondPeer := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 40001}
	secondConn := &responsePacketConn{authPacketConn: second, peer: secondPeer, write: func(p []byte, peer net.Addr) (int, error) {
		if peer != secondPeer {
			t.Fatal("response retained old peer")
		}
		got = append(got, "second:"+string(p))
		return len(p), nil
	}}
	e.setTransport(&responsePacketConn{authPacketConn: first, peer: first.RemoteAddr(), write: func(p []byte, peer net.Addr) (int, error) {
		got = append(got, "first:"+string(p))
		e.setTransport(secondConn)
		return len(p), nil
	}})
	var destinations []net.Destination
	e.writeResponses(fallback, func(dest net.Destination, p []byte) ([]byte, error) {
		destinations = append(destinations, dest)
		if string(p) == "bad" {
			return nil, io.ErrUnexpectedEOF
		}
		return append([]byte(nil), p...), nil
	})
	want := []net.Destination{fallback, explicit, fallback, fallback}
	if len(destinations) != len(want) {
		t.Fatalf("encoded destinations: %v", destinations)
	}
	for i, dest := range want {
		if destinations[i] != dest {
			t.Fatalf("destination %d: %v want %v", i, destinations[i], dest)
		}
	}
	if len(got) != 3 || got[0] != "first:a" || got[1] != "second:b" || got[2] != "second:c" {
		t.Fatalf("response order/rebind: %v", got)
	}
	for _, b := range owned {
		if !b.IsEmpty() {
			t.Fatal("decoded buffer retained")
		}
	}
	if ctx.Err() == nil || *closed != 1 {
		t.Fatal("association did not close once")
	}
	select {
	case <-first.done:
		t.Fatal("association closed shared listener")
	default:
	}
}

func TestUDPResponsesFailureReleasesBatch(t *testing.T) {
	for _, mode := range []string{"short", "partial-error", "full-error", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			mb := buf.MultiBuffer{responseBuffer("one"), responseBuffer("two")}
			owned := append(buf.MultiBuffer(nil), mb...)
			reads, writes := 0, 0
			e, ctx, closed := responseEntry(t, responseBatchReader(func() (buf.MultiBuffer, error) {
				reads++
				if reads > 1 {
					return nil, io.EOF
				}
				if mode == "read-error" {
					return mb, io.ErrUnexpectedEOF
				}
				return mb, nil
			}))
			conn := newAuthPacketConn()
			defer conn.Close()
			e.setTransport(&responsePacketConn{authPacketConn: conn, write: func(p []byte, _ net.Addr) (int, error) {
				writes++
				if mode == "short" {
					return 1, nil
				}
				if mode == "full-error" {
					return len(p), io.ErrClosedPipe
				}
				return 1, io.ErrClosedPipe
			}})
			e.writeResponses(net.UDPDestination(net.LocalHostIP, 1001), func(_ net.Destination, p []byte) ([]byte, error) {
				return append([]byte(nil), p...), nil
			})
			wantWrites := 1
			if mode == "read-error" {
				wantWrites = 0
			}
			if reads != 1 || writes != wantWrites || *closed != 1 || ctx.Err() == nil {
				t.Fatalf("termination: reads=%d writes=%d closes=%d err=%v", reads, writes, *closed, ctx.Err())
			}
			for _, b := range owned {
				if !b.IsEmpty() {
					t.Fatal("failed response retained batch tail")
				}
			}
		})
	}
}

type responseBlockingReader struct {
	*pipe.Reader
	entered chan struct{}
}

func (r *responseBlockingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.entered)
	return r.Reader.ReadMultiBuffer()
}

func TestUDPResponsesCloseUnblocksRead(t *testing.T) {
	reader, writer := pipe.New()
	defer writer.Close()
	r := &responseBlockingReader{Reader: reader, entered: make(chan struct{})}
	e, _, _ := responseEntry(t, r)
	done := make(chan struct{})
	go func() {
		e.writeResponses(net.UDPDestination(net.LocalHostIP, 1001), nil)
		close(done)
	}()
	<-r.entered
	e.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("response worker retained blocked read after close")
	}
}
