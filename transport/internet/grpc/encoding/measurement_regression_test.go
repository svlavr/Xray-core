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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestMeasurementHunkClientCloseCancelsBlockedSend(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	RegisterGRPCServiceServer(server, measurementHunkServer{})
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
	newStream := func() (GRPCService_TunClient, context.CancelFunc) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		stream, err := NewGRPCServiceClient(client).Tun(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return stream, cancel
	}
	sibling, siblingCancel := newStream()
	ordinary := NewHunkReadWriter(sibling, siblingCancel)
	exchange := func(h *HunkReaderWriter, payload string) {
		t.Helper()
		if n, err := h.Write([]byte(payload)); err != nil || n != len(payload) {
			t.Fatalf("native write: n=%d error=%v", n, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(h, got); err != nil || string(got) != payload {
			t.Fatalf("native echo: payload=%q error=%v", got, err)
		}
	}
	exchange(ordinary, "ordinary")
	stream, cancel := newStream()
	probe := &measurementHunkClientProbe{GRPCService_TunClient: stream, entered: make(chan struct{}), returned: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(probe.release) }) }
	t.Cleanup(release)
	h := NewHunkReadWriter(probe, cancel)
	exchange(h, "hold")
	payload := bytes.Repeat([]byte("x"), 1<<20)
	// The peer stops receiving after its echo. One large Send consumes the
	// transport's quota; the next must wait for native flow control.
	if n, err := h.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("initial queued hunk: n=%d error=%v", n, err)
	}
	type result struct {
		n   int
		err error
	}
	written := make(chan result, 1)
	go func() { n, err := h.Write(payload); written <- result{n, err} }()
	select {
	case <-probe.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second large native Send did not start")
	}
	select {
	case <-probe.returned:
		t.Fatal("peer did not apply native Send backpressure")
	case <-time.After(50 * time.Millisecond):
	}
	closed := make(chan error, 16)
	for range cap(closed) {
		go func() { closed <- h.Close() }()
	}
	select {
	case <-probe.returned:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel the flow-control blocked native Send")
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
	if n, err := h.Write([]byte("after close")); n != 0 || !errors.Is(err, io.ErrClosedPipe) || probe.sends.Load() != 3 {
		t.Fatalf("post-close Send: n=%d error=%v native sends=%d", n, err, probe.sends.Load())
	}
	if n, err := h.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("post-close Read: n=%d error=%v", n, err)
	}
	exchange(ordinary, "same-stream-after-cancellation")
	release()
	select {
	case got := <-written:
		if got.n != 0 || got.err == nil || !errors.Is(stream.Context().Err(), context.Canceled) {
			t.Fatalf("canceled native Send: n=%d error=%v context=%v", got.n, got.err, stream.Context().Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled Write did not return")
	}
	if err := ordinary.Close(); err != nil {
		t.Fatal(err)
	}
}

type measurementHunkServer struct {
	UnimplementedGRPCServiceServer
}

func (measurementHunkServer) Tun(stream GRPCService_TunServer) error {
	for {
		hunk, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(hunk); err != nil {
			return err
		}
		if string(hunk.Data) == "hold" {
			<-stream.Context().Done()
			return nil
		}
	}
}

type measurementHunkClientProbe struct {
	GRPCService_TunClient
	sends    atomic.Int32
	closes   atomic.Int32
	active   atomic.Bool
	overlap  atomic.Bool
	entered  chan struct{}
	returned chan struct{}
	release  chan struct{}
}

func (p *measurementHunkClientProbe) Send(hunk *Hunk) error {
	p.active.Store(true)
	defer p.active.Store(false)
	if p.sends.Add(1) != 3 {
		return p.GRPCService_TunClient.Send(hunk)
	}
	close(p.entered)
	err := p.GRPCService_TunClient.Send(hunk)
	close(p.returned)
	<-p.release
	return err
}

func (p *measurementHunkClientProbe) CloseSend() error {
	p.closes.Add(1)
	if p.active.Load() {
		p.overlap.Store(true)
	}
	return p.GRPCService_TunClient.CloseSend()
}

func TestMeasurementHunkServerCloseDoesNotWaitForSend(t *testing.T) {
	stream := &measurementBlockedServer{entered: make(chan struct{}), release: make(chan struct{})}
	h := NewHunkReadWriter(stream, nil)
	written := make(chan error, 1)
	go func() { _, err := h.Write([]byte("blocked server hunk")); written <- err }()
	<-stream.entered
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(stream.release)
		<-written
		t.Fatal("server Close waited for a Send that needs handler return")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	close(stream.release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if n, err := h.Write([]byte("after close")); n != 0 || err != io.ErrClosedPipe {
		t.Fatalf("closed server Write: n=%d error=%v", n, err)
	}
}

type measurementBlockedServer struct {
	entered chan struct{}
	release chan struct{}
}

func (*measurementBlockedServer) Context() context.Context { return context.Background() }
func (*measurementBlockedServer) Recv() (*Hunk, error)     { return nil, io.EOF }
func (s *measurementBlockedServer) Send(*Hunk) error {
	close(s.entered)
	<-s.release
	return nil
}
func (s *measurementBlockedServer) SendMsg(m interface{}) error { return s.Send(m.(*Hunk)) }
func (*measurementBlockedServer) RecvMsg(interface{}) error     { return io.EOF }
