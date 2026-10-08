package grpc

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func TestGRPCMultiModeCloseOwnership(t *testing.T) {
	config := &Config{ServiceName: "multi-owner-test", MultiMode: true}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &multiOwnerEchoServer{streams: make(chan context.Context, 3)}
	server := grpc.NewServer()
	encoding.RegisterGRPCServiceServerX(server, peer, config.getServiceName(), config.getTunStreamName(), config.getTunMultiStreamName())
	served := make(chan struct{})
	go func() { defer close(served); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); <-served })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
	exchange := func(conn net.Conn, payload string) {
		t.Helper()
		if n, err := conn.Write([]byte(payload)); err != nil || n != len(payload) {
			t.Fatalf("native write: n=%d error=%v", n, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
			t.Fatalf("native echo: payload=%q error=%v", got, err)
		}
	}
	streamContext := func() context.Context {
		t.Helper()
		select {
		case stream := <-peer.streams:
			return stream
		case <-ctx.Done():
			t.Fatal("server did not accept MultiMode stream")
			return nil
		}
	}
	awaitClosed := func(stream context.Context) {
		t.Helper()
		select {
		case <-stream.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("closed MultiMode stream remained active on server")
		}
	}
	owner, cancelOwner := context.WithCancel(ctx)
	t.Cleanup(cancelOwner)
	pooledSettings := &internet.MemoryStreamConfig{Owner: owner, ProtocolName: protocolName, ProtocolSettings: config}
	client, err := getGrpcClient(ctx, dest, pooledSettings)
	if err != nil {
		t.Fatal(err)
	}
	first, err := dialgRPC(ctx, dest, pooledSettings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	exchange(first, "first")
	firstRPC := streamContext()
	sibling, err := dialgRPC(ctx, dest, pooledSettings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	exchange(sibling, "sibling")
	siblingRPC := streamContext()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	awaitClosed(firstRPC)
	if client.GetState() == connectivity.Shutdown {
		t.Fatal("closing one pooled MultiMode stream shut down its client")
	}
	if cached, err := getGrpcClient(ctx, dest, pooledSettings); err != nil || cached != client {
		t.Fatalf("closing one pooled MultiMode stream replaced its client: %v", err)
	}
	select {
	case <-siblingRPC.Done():
		t.Fatal("closing one pooled MultiMode stream ended its sibling")
	default:
	}
	exchange(sibling, "sibling-after-close")

	standaloneSettings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	standalone, err := dialgRPC(ctx, dest, standaloneSettings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = standalone.Close() })
	exchange(standalone, "standalone")
	standaloneRPC := streamContext()
	if err := standalone.Close(); err != nil {
		t.Fatal(err)
	}
	awaitClosed(standaloneRPC)
	exchange(sibling, "sibling-after-standalone")
	if err := sibling.Close(); err != nil {
		t.Fatal(err)
	}
	awaitClosed(siblingRPC)
}

type multiOwnerEchoServer struct {
	encoding.UnimplementedGRPCServiceServer
	streams chan context.Context
}

func (s *multiOwnerEchoServer) TunMulti(stream encoding.GRPCService_TunMultiServer) error {
	s.streams <- stream.Context()
	for {
		hunk, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(hunk); err != nil {
			return err
		}
	}
}
