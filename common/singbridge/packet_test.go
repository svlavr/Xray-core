package singbridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/pipe"
)

type packetReadFunc func() (buf.MultiBuffer, error)

func (f packetReadFunc) ReadMultiBuffer() (buf.MultiBuffer, error) { return f() }

type packetWriteFunc func(buf.MultiBuffer) error

func (f packetWriteFunc) WriteMultiBuffer(mb buf.MultiBuffer) error { return f(mb) }

func packetWrapper(t *testing.T) *PacketConnWrapper {
	t.Helper()
	w := &PacketConnWrapper{Dest: net.UDPDestination(net.DomainAddress("fallback.invalid"), 53)}
	w.T = signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	t.Cleanup(func() { w.Close() })
	return w
}

func TestPacketBridgeRetainsBatchTerminalError(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("read failed")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			w := packetWrapper(t)
			a, b := buf.New(), buf.New()
			a.Write([]byte("first"))
			// The second packet is a valid empty datagram with its own address.
			destination := net.UDPDestination(net.DomainAddress("second.invalid"), 99)
			b.UDP = &destination
			calls := 0
			w.Reader = packetReadFunc(func() (buf.MultiBuffer, error) {
				calls++
				return buf.MultiBuffer{nil, a, nil, b, nil}, terminal
			})
			for _, want := range []struct {
				data string
				dest net.Destination
			}{{"first", w.Dest}, {"", destination}} {
				p := B.NewPacket()
				addr, err := w.ReadPacket(p)
				if err != nil || string(p.Bytes()) != want.data || addr != ToSocksaddr(want.dest) {
					t.Fatalf("packet: %q %v %v", p.Bytes(), addr, err)
				}
				p.Release()
			}
			p := B.NewPacket()
			defer p.Release()
			if _, err := w.ReadPacket(p); !errors.Is(err, terminal) || calls != 1 {
				t.Fatalf("terminal: %v, reads=%d", err, calls)
			}
			if a.Bytes() != nil || b.Bytes() != nil {
				t.Fatal("batch buffers retained")
			}
		})
	}
}

func TestPacketBridgeShortReadIsReported(t *testing.T) {
	w := packetWrapper(t)
	source := buf.New()
	source.Write([]byte("packet"))
	w.Reader = packetReadFunc(func() (buf.MultiBuffer, error) { return buf.MultiBuffer{source}, io.EOF })
	p := B.NewSize(2)
	defer p.Release()
	addr, err := w.ReadPacket(p)
	if !errors.Is(err, io.ErrShortBuffer) || string(p.Bytes()) != "pa" || addr != ToSocksaddr(w.Dest) || source.Bytes() != nil {
		t.Fatalf("short read: %q %v %v", p.Bytes(), addr, err)
	}
}

func TestPacketBridgeWritePreservesPayloadAndCustody(t *testing.T) {
	for _, size := range []int{0, buf.Size, buf.Size + 1, 64000} {
		for _, failure := range []error{nil, io.ErrClosedPipe} {
			w := packetWrapper(t)
			payload := bytes.Repeat([]byte{0xa5}, size)
			destination := M.ParseSocksaddr("example.invalid:53")
			w.Writer = packetWriteFunc(func(mb buf.MultiBuffer) error {
				defer buf.ReleaseMulti(mb)
				if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || ToSocksaddr(*mb[0].UDP) != destination {
					t.Fatalf("write lost packet size=%d", size)
				}
				return failure
			})
			p := B.NewSize(size + 1)
			p.Write(payload)
			if err := w.WritePacket(p, destination); !errors.Is(err, failure) || p.Bytes() != nil {
				t.Fatalf("write: %v, source retained=%v", err, p.Bytes() != nil)
			}
		}
	}
}

type blockingPacketReader struct {
	entered chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (r *blockingPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.entered)
	<-r.done
	return nil, io.ErrClosedPipe
}

func (r *blockingPacketReader) Interrupt() { r.once.Do(func() { close(r.done) }) }

func awaitPacketResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("packet operation did not finish")
		return nil
	}
}

func TestPacketBridgeCloseUnblocksRead(t *testing.T) {
	w := packetWrapper(t)
	r := &blockingPacketReader{entered: make(chan struct{}), done: make(chan struct{})}
	w.Reader = r
	result := make(chan error, 1)
	go func() {
		p := B.NewPacket()
		defer p.Release()
		_, err := w.ReadPacket(p)
		result <- err
	}()
	<-r.entered
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	if err := awaitPacketResult(t, result); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := awaitPacketResult(t, closed); err != nil {
		t.Fatal(err)
	}
}

func TestPacketBridgeCloseReleasesCachedAndPendingWrites(t *testing.T) {
	w := packetWrapper(t)
	a, b := buf.New(), buf.New()
	a.Write([]byte("a"))
	b.Write([]byte("b"))
	w.Reader = packetReadFunc(func() (buf.MultiBuffer, error) { return buf.MultiBuffer{a, b}, io.EOF })
	p := B.NewPacket()
	defer p.Release()
	if _, err := w.ReadPacket(p); err != nil {
		t.Fatal(err)
	}
	_, writer := pipe.New(pipe.WithSizeLimit(0))
	w.Writer = writer
	// Fill the pipe first: a subsequent write must wait or fail after Close.
	queued := buf.New()
	queued.Write([]byte("queued"))
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{queued}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	q := B.NewPacket()
	q.Write([]byte("pending"))
	go func() { result <- w.WritePacket(q, ToSocksaddr(w.Dest)) }()
	w.Close()
	if err := awaitPacketResult(t, result); err == nil || q.Bytes() != nil || b.Bytes() != nil || queued.Bytes() != nil {
		t.Fatalf("close: %v, write retained=%v, cached retained=%v", err, q.Bytes() != nil, b.Bytes() != nil)
	}
	w.Close()
}
