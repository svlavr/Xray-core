package singbridge

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

func TestPipeAndPacketWrappersJoinActivityTimer(t *testing.T) {
	for _, test := range []struct {
		name  string
		close func(*signal.ActivityTimer) error
	}{
		{name: "stream", close: func(timer *signal.ActivityTimer) error { return (&PipeConnWrapper{T: timer}).Close() }},
		{name: "packet", close: func(timer *signal.ActivityTimer) error { return (&PacketConnWrapper{T: timer}).Close() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			timer := signal.CancelAfterInactivity(context.Background(), func() {
				calls.Add(1)
				close(entered)
				<-release
			}, time.Hour)
			closeDone := make(chan error, 1)
			go func() { closeDone <- test.close(timer) }()
			<-entered
			select {
			case err := <-closeDone:
				t.Fatalf("wrapper Close returned before timer callback: %v", err)
			default:
			}
			close(release)
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("wrapper Close did not join activity timer")
			}
			if calls.Load() != 1 {
				t.Fatalf("timer callbacks = %d, want 1", calls.Load())
			}
		})
	}
}

type blockingMultiReader struct {
	release chan struct{}
	once    sync.Once
}

func (r *blockingMultiReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.release
	return nil, io.ErrClosedPipe
}

func (r *blockingMultiReader) Interrupt() {
	r.once.Do(func() { close(r.release) })
}

type blockingMultiWriter struct {
	started chan struct{}
	release chan struct{}
	start   sync.Once
	once    sync.Once
}

func (w *blockingMultiWriter) WriteMultiBuffer(buf.MultiBuffer) error {
	w.start.Do(func() { close(w.started) })
	<-w.release
	return io.ErrClosedPipe
}

func (w *blockingMultiWriter) Interrupt() {
	w.once.Do(func() { close(w.release) })
}

func waitForCopyReceipt(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copy did not return after owner cancellation")
	}
}

func TestCopyConnCancellationUnblocksLinkWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &blockingMultiReader{release: make(chan struct{})}
	writer := &blockingMultiWriter{started: make(chan struct{}), release: make(chan struct{})}
	serverConn, peer := stdnet.Pipe()
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		done <- CopyConn(ctx, nil, &transport.Link{Reader: reader, Writer: writer}, serverConn)
	}()
	go func() { _, _ = peer.Write([]byte("download")) }()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("download did not reach the blocked link writer")
	}
	cancel()
	waitForCopyReceipt(t, done)
}

func TestCopyPacketConnCancellationUnblocksLinkWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &blockingMultiReader{release: make(chan struct{})}
	writer := &blockingMultiWriter{started: make(chan struct{}), release: make(chan struct{})}
	serverConn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	peer, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		done <- CopyPacketConn(ctx, nil, &transport.Link{Reader: reader, Writer: writer},
			net.UDPDestination(net.DomainAddress("example.test"), 53), serverConn)
	}()
	if _, err := peer.WriteTo([]byte("download"), serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("packet download did not reach the blocked link writer")
	}
	cancel()
	waitForCopyReceipt(t, done)
}

type latePacketReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *latePacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.started)
	<-r.release
	return buf.MultiBuffer{
		buf.FromBytes([]byte("first")),
		buf.FromBytes([]byte("late-cached")),
	}, nil
}

func (r *latePacketReader) Interrupt() {
	r.once.Do(func() { close(r.release) })
}

func TestPacketWrapperCloseJoinsReadBeforeCachedRelease(t *testing.T) {
	reader := &latePacketReader{started: make(chan struct{}), release: make(chan struct{})}
	timer := signal.CancelAfterInactivity(context.Background(), func() {
		common.Interrupt(reader)
	}, time.Hour)
	wrapper := &PacketConnWrapper{
		Reader: reader,
		Dest:   net.UDPDestination(net.DomainAddress("example.test"), 53),
		T:      timer,
	}
	packet := B.New()
	defer packet.Release()
	readDone := make(chan error, 1)
	go func() {
		_, err := wrapper.ReadPacket(packet)
		readDone <- err
	}()
	<-reader.started
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapper.Close() }()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the active packet read")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the active packet read")
	}
	if wrapper.cached != nil {
		t.Fatal("late-published cached buffers survived Close")
	}
	postClosePacket := B.New()
	defer postClosePacket.Release()
	if _, err := wrapper.ReadPacket(postClosePacket); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("post-close read error = %v, want io.ErrClosedPipe", err)
	}
}
