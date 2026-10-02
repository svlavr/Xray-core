package grpc

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

type reconnectEchoServer struct {
	encoding.UnimplementedGRPCServiceServer
}

func (reconnectEchoServer) Tun(stream encoding.GRPCService_TunServer) error {
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

func TestGRPCReconnectAfterFirstCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	config := &Config{ServiceName: "reconnect-test"}
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	start := func(address string) (net.Listener, func()) {
		t.Helper()
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		encoding.RegisterGRPCServiceServerX(server, reconnectEchoServer{}, config.getServiceName(), config.getTunStreamName(), config.getTunMultiStreamName())
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Errorf("serve: %v", err)
			}
		}()
		stop := func() { server.Stop(); <-done }
		t.Cleanup(stop)
		return listener, stop
	}
	listener, stop := start("127.0.0.1:0")
	address := listener.Addr().String()
	destination := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
	firstCtx, cancelFirst := context.WithCancel(ctx)
	t.Cleanup(cancelFirst)
	client, err := getGrpcClient(firstCtx, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		delete(globalDialerMap, dialerConf{destination, settings})
		globalDialerAccess.Unlock()
		_ = client.Close()
	})
	waitReady := func(want bool) {
		t.Helper()
		for {
			state := client.GetState()
			if state == connectivity.Shutdown {
				t.Fatal("cached client unexpectedly shut down")
			}
			if (state == connectivity.Ready) == want {
				return
			}
			if !client.WaitForStateChange(ctx, state) {
				t.Fatalf("waiting for Ready=%v: state=%v err=%v", want, state, ctx.Err())
			}
		}
	}
	echo := func(conn net.Conn) {
		t.Helper()
		if _, err := conn.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, 5)
		if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "alive" {
			t.Fatalf("echo: %q %v", payload, err)
		}
	}
	waitReady(true)
	first, err := dialgRPC(firstCtx, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	echo(first)
	cancelFirst()
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("first stream survived caller cancellation")
	}
	if conn, err := dialgRPC(firstCtx, destination, settings); err == nil {
		_ = conn.Close()
		t.Fatal("canceled caller opened another stream")
	}
	stop()
	waitReady(false)
	_, _ = start(address)
	cached, err := getGrpcClient(ctx, destination, settings)
	if err != nil || cached != client {
		t.Fatalf("reconnect replaced cached client: %v", err)
	}
	client.Connect()
	client.ResetConnectBackoff()
	waitReady(true)
	second, err := dialgRPC(ctx, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	echo(second)
}
