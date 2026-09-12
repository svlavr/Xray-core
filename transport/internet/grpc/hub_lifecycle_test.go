package grpc

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/stat"
	grpcgo "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type heldTunStream struct{ ctx context.Context }

func (s *heldTunStream) SetHeader(metadata.MD) error   { return nil }
func (s *heldTunStream) SendHeader(metadata.MD) error  { return nil }
func (s *heldTunStream) SetTrailer(metadata.MD)        {}
func (s *heldTunStream) Context() context.Context      { return s.ctx }
func (s *heldTunStream) SendMsg(any) error             { return nil }
func (s *heldTunStream) RecvMsg(any) error             { return io.EOF }
func (s *heldTunStream) Send(*encoding.Hunk) error     { return nil }
func (s *heldTunStream) Recv() (*encoding.Hunk, error) { return nil, io.EOF }

func TestCloseLeavesHeldTunCallbackReceiptActive(t *testing.T) {
	var tasks task.Lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	l := &Listener{
		ctx:         ctx,
		cancel:      cancel,
		s:           grpcgo.NewServer(),
		lifecycle:   &internet.InboundLifecycle{Tasks: &tasks},
		connections: make(map[net.Conn]struct{}),
		handler: func(stat.Connection) {
			close(handlerEntered)
			<-handlerRelease
		},
	}
	stream := &heldTunStream{ctx: context.Background()}
	done := make(chan error, 1)
	go func() { done <- l.Tun(stream) }()
	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("Tun callback did not start")
	}
	tasks.Seal()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() { tasks.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("lifecycle joined before held callback returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(handlerRelease)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Tun did not return after callback release")
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not join Tun callback")
	}
}

func TestListenReturnsBindFailureSynchronously(t *testing.T) {
	probe, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	port := probe.Addr().(*stdnet.TCPAddr).Port
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	listener, err := Listen(context.Background(), net.LocalHostIP, net.Port(port), settings, func(stat.Connection) {})
	if err == nil {
		listener.Close()
		t.Fatal("bind failure was deferred or ignored")
	}
}

func TestCloseRejectsRegisteredTunCallbackBeforeInvocation(t *testing.T) {
	var tasks task.Lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		ctx:         ctx,
		cancel:      cancel,
		s:           grpcgo.NewServer(),
		lifecycle:   &internet.InboundLifecycle{Tasks: &tasks},
		connections: make(map[net.Conn]struct{}),
	}
	if !l.register() {
		t.Fatal("Tun receipt was rejected")
	}
	server, client := stdnet.Pipe()
	defer client.Close()
	conn := &inboundConnection{Conn: server, handoff: new(internet.InboundHandoff)}
	if !l.addConnection(conn) {
		t.Fatal("Tun connection registration was rejected")
	}
	tasks.Seal()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if internet.AcceptInboundHandoff(conn) {
		t.Fatal("closed listener allowed a first Tun callback")
	}
	l.removeConnection(conn)
	tasks.Release()
	tasks.Wait()
}
