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

type nativeResponseConn struct {
	*authPacketConn
	write func([]byte) (int, error)
}

func (c *nativeResponseConn) Write(p []byte) (int, error) { return c.write(p) }
func responseBuffer(payload string) *buf.Buffer {
	b := buf.New()
	if _, err := b.WriteString(payload); err != nil {
		panic(err)
	}
	return b
}

func TestNativeUDPResponsesDestinationsAndEncoding(t *testing.T) {
	fallback := net.UDPDestination(net.LocalHostIP, 1001)
	explicit := net.UDPDestination(net.LocalHostIP, 1002)
	mb := buf.MultiBuffer{responseBuffer("a"), responseBuffer("b"), responseBuffer("bad"), responseBuffer("c")}
	mb[1].UDP = &explicit
	owned := append(buf.MultiBuffer(nil), mb...)
	read := false
	link := &transport.Link{Reader: responseBatchReader(func() (buf.MultiBuffer, error) {
		if read {
			return nil, io.EOF
		}
		read = true
		return mb, nil
	})}
	conn := &nativeResponseConn{authPacketConn: newAuthPacketConn()}
	t.Cleanup(func() { conn.Close() })
	var got []string
	conn.write = func(p []byte) (int, error) { got = append(got, string(p)); return len(p), nil }
	s := new(ServerUDPSession)
	s.timer = signal.CancelAfterInactivity(context.Background(), func() {}, time.Minute)
	t.Cleanup(func() { s.timer.SetTimeout(0) })
	s.UpdateConn(conn)
	var destinations []net.Destination
	handleUDPResponse(s, link, fallback, func(dest net.Destination, payload []byte) ([]byte, error) {
		destinations = append(destinations, dest)
		if string(payload) == "bad" {
			return nil, io.ErrUnexpectedEOF
		}
		return append([]byte(nil), payload...), nil
	})
	want := []net.Destination{fallback, explicit, fallback, fallback}
	if len(destinations) != len(want) {
		t.Fatalf("destinations %v", destinations)
	}
	for i := range want {
		if destinations[i] != want[i] {
			t.Fatalf("destination %d: %v", i, destinations[i])
		}
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("responses %v", got)
	}
	for _, b := range owned {
		if !b.IsEmpty() {
			t.Fatal("native decoded response retained")
		}
	}
	select {
	case <-conn.done:
		t.Fatal("response closed shared connection")
	default:
	}
}

func TestNativeUDPResponsesWriteFailureReleasesBatch(t *testing.T) {
	for _, full := range []bool{false, true} {
		mb := buf.MultiBuffer{responseBuffer("first"), responseBuffer("tail")}
		owned := append(buf.MultiBuffer(nil), mb...)
		reads, writes := 0, 0
		link := &transport.Link{Reader: responseBatchReader(func() (buf.MultiBuffer, error) { reads++; return mb, nil })}
		conn := &nativeResponseConn{authPacketConn: newAuthPacketConn(), write: func(p []byte) (int, error) {
			writes++
			if full {
				return len(p), io.ErrClosedPipe
			}
			return 1, io.ErrClosedPipe
		}}
		s := new(ServerUDPSession)
		s.timer = signal.CancelAfterInactivity(context.Background(), func() {}, time.Minute)
		t.Cleanup(func() { s.timer.SetTimeout(0) })
		s.UpdateConn(conn)
		handleUDPResponse(s, link, net.UDPDestination(net.LocalHostIP, 1001), nil)
		conn.Close()
		if reads != 1 || writes != 1 {
			t.Fatalf("reads=%d writes=%d", reads, writes)
		}
		for _, b := range owned {
			if !b.IsEmpty() {
				t.Fatal("native failure retained batch tail")
			}
		}
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

func TestNativeUDPResponsesExplicitCloseUnblocksRead(t *testing.T) {
	r, w := pipe.New()
	defer w.Close()
	reader := &responseBlockingReader{Reader: r, entered: make(chan struct{})}
	link := &transport.Link{Reader: reader, Writer: w}
	s := new(ServerUDPSession)
	s.timer = signal.CancelAfterInactivity(context.Background(), func() {}, time.Minute)
	t.Cleanup(func() { s.timer.SetTimeout(0) })
	s.link.Store(link)
	finished := make(chan struct{})
	go func() { handleUDPResponse(s, link, net.UDPDestination(net.LocalHostIP, 1001), nil); close(finished) }()
	<-reader.entered
	s.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("native response read remained blocked")
	}
}
