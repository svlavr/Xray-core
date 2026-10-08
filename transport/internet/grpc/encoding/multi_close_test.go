package encoding

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestMultiHunkClientCloseCancelsBlockedSendAndRecv(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	RegisterGRPCServiceServer(server, multiCloseServer{})
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() { server.Stop(); listener.Close(); <-served })
	client, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	newStream := func() (GRPCService_TunMultiClient, context.CancelFunc) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		stream, err := NewGRPCServiceClient(client).TunMulti(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return stream, cancel
	}
	exchange := func(h *MultiHunkReaderWriter, payload string) {
		t.Helper()
		b := buf.New()
		if _, err := b.WriteString(payload); err != nil {
			t.Fatal(err)
		}
		if err := h.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("native write: %v", err)
		}
		got, err := h.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("native echo: %v", err)
		}
		if len(got) != 1 || string(got[0].Bytes()) != payload {
			buf.ReleaseMulti(got)
			t.Fatalf("native echo: expected %q", payload)
		}
		buf.ReleaseMulti(got)
	}
	siblingStream, siblingCancel := newStream()
	sibling := NewMultiHunkReadWriter(siblingStream, siblingCancel)
	exchange(sibling, "sibling")
	stream, cancel := newStream()
	probe := &multiCloseClientProbe{
		GRPCService_TunMultiClient: stream,
		sendEntered:                make(chan struct{}), sendReturned: make(chan struct{}),
		recvEntered: make(chan struct{}), recvReturned: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(probe.release) }) }
	t.Cleanup(release)
	h := NewMultiHunkReadWriter(probe, cancel)
	exchange(h, "hold")
	readResult := make(chan error, 1)
	go func() {
		mb, err := h.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		readResult <- err
	}()
	select {
	case <-probe.recvEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked native Recv did not start")
	}
	select {
	case <-probe.recvReturned:
		t.Fatal("peer did not hold native Recv")
	case <-time.After(50 * time.Millisecond):
	}
	large := bytes.Repeat([]byte("x"), 1<<20)
	writeLarge := func() error {
		b := buf.NewWithSize(int32(len(large)))
		if _, err := b.Write(large); err != nil {
			b.Release()
			return err
		}
		return h.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	// The peer stops receiving after its echo. One large Send consumes the
	// transport's quota; the next must wait for native flow control.
	if err := writeLarge(); err != nil {
		t.Fatalf("initial queued hunk: %v", err)
	}
	written := make(chan error, 1)
	go func() { written <- writeLarge() }()
	select {
	case <-probe.sendEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("second large native Send did not start")
	}
	select {
	case <-probe.sendReturned:
		t.Fatal("peer did not apply native Send backpressure")
	case <-time.After(50 * time.Millisecond):
	}
	closed := make(chan error, 16)
	for range cap(closed) {
		go func() { closed <- h.Close() }()
	}
	select {
	case <-probe.sendReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel the flow-control blocked native Send")
	}
	select {
	case <-probe.recvReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel the blocked native Recv")
	}
	// Keep Send active after native cancellation. Close must return promptly
	// using cancellation alone, without waiting for Send or calling CloseSend.
	for range cap(closed) {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent Close did not return")
		}
	}
	if probe.closes.Load() != 0 || probe.overlap.Load() {
		t.Fatalf("native CloseSend: calls=%d overlap=%t", probe.closes.Load(), probe.overlap.Load())
	}
	owned := buf.New()
	if _, err := owned.WriteString("after close"); err != nil {
		t.Fatal(err)
	}
	if err := h.WriteMultiBuffer(buf.MultiBuffer{owned}); !errors.Is(err, io.ErrClosedPipe) || owned.Len() != 0 || probe.sends.Load() != 3 {
		t.Fatalf("post-close WriteMultiBuffer: error=%v remaining=%d native sends=%d", err, owned.Len(), probe.sends.Load())
	}
	if got, err := h.ReadMultiBuffer(); got != nil || err != io.EOF {
		buf.ReleaseMulti(got)
		t.Fatalf("post-close ReadMultiBuffer: buffers=%d error=%v", len(got), err)
	}
	select {
	case err := <-readResult:
		if err == nil || !errors.Is(stream.Context().Err(), context.Canceled) {
			t.Fatalf("canceled native Recv: error=%v context=%v", err, stream.Context().Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled ReadMultiBuffer did not return")
	}
	exchange(sibling, "sibling-after-cancellation")
	release()
	select {
	case err := <-written:
		if err == nil || !errors.Is(stream.Context().Err(), context.Canceled) {
			t.Fatalf("canceled native Send: error=%v context=%v", err, stream.Context().Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled WriteMultiBuffer did not return")
	}
	if err := sibling.Close(); err != nil {
		t.Fatal(err)
	}
}

type multiCloseServer struct {
	UnimplementedGRPCServiceServer
}

func (multiCloseServer) TunMulti(stream GRPCService_TunMultiServer) error {
	for {
		hunk, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(hunk); err != nil {
			return err
		}
		for _, data := range hunk.Data {
			if string(data) == "hold" {
				<-stream.Context().Done()
				return nil
			}
		}
	}
}

type multiCloseClientProbe struct {
	GRPCService_TunMultiClient
	sends, closes, recvs atomic.Int32
	active, overlap      atomic.Bool
	sendEntered          chan struct{}
	sendReturned         chan struct{}
	recvEntered          chan struct{}
	recvReturned         chan struct{}
	release              chan struct{}
}

func (p *multiCloseClientProbe) Send(hunk *MultiHunk) error {
	p.active.Store(true)
	defer p.active.Store(false)
	if p.sends.Add(1) != 3 {
		return p.GRPCService_TunMultiClient.Send(hunk)
	}
	close(p.sendEntered)
	err := p.GRPCService_TunMultiClient.Send(hunk)
	close(p.sendReturned)
	<-p.release
	return err
}

func (p *multiCloseClientProbe) Recv() (*MultiHunk, error) {
	if p.recvs.Add(1) != 2 {
		return p.GRPCService_TunMultiClient.Recv()
	}
	close(p.recvEntered)
	hunk, err := p.GRPCService_TunMultiClient.Recv()
	close(p.recvReturned)
	return hunk, err
}

func (p *multiCloseClientProbe) CloseSend() error {
	p.closes.Add(1)
	if p.active.Load() {
		p.overlap.Store(true)
	}
	return p.GRPCService_TunMultiClient.CloseSend()
}
