package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
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
	owner, cancelOwner := context.WithCancel(context.Background())
	t.Cleanup(cancelOwner)
	settings := &internet.MemoryStreamConfig{Owner: owner, ProtocolName: protocolName, ProtocolSettings: config}
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
	third, err := dialgRPC(ctx, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = third.Close() })
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	echo(third)

	// Per-user targets do not change the physical route when Gateway is nil.
	routeA := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("user-a.example"), 80)}})
	routeB := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("user-b.example"), 443)}})
	a, err := getGrpcClient(routeA, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	b, err := getGrpcClient(routeB, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	if a != client || b != client {
		t.Fatal("nil-gateway user targets did not reuse the owner client")
	}

	// Explicit source gateways create stream-owned clients. Probe each source
	// address independently so a host binding limitation is not a gRPC failure.
	t.Run("source gateways", func(t *testing.T) {
		supported := 0
		for i := 1; i <= 8; i++ {
			gateway := fmt.Sprintf("127.0.0.%d", i)
			probe, err := stdnet.DialTCP("tcp", &stdnet.TCPAddr{IP: stdnet.ParseIP(gateway)}, listener.Addr().(*stdnet.TCPAddr))
			if err != nil {
				t.Logf("source gateway %s unsupported by host: %v", gateway, err)
				continue
			}
			_ = probe.Close()
			supported++
			route := session.ContextWithOutbounds(ctx, []*session.Outbound{{Gateway: net.ParseAddress(gateway)}})
			stream, err := dialgRPC(route, destination, settings)
			if err != nil {
				t.Fatalf("source gateway %s: %v", gateway, err)
			}
			echo(stream)
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			globalDialerAccess.Lock()
			entries := len(globalDialerMap)
			retained := globalDialerMap[dialerConf{Destination: destination, MemoryStreamConfig: settings}]
			globalDialerAccess.Unlock()
			if entries != 1 || retained != client {
				t.Fatalf("source gateway %s entered shared cache: entries=%d", gateway, entries)
			}
		}
		if supported < 2 {
			t.Skipf("host supports only %d tested loopback source gateways", supported)
		}
	})

	cancelOwner()
	deadline := time.After(5 * time.Second)
	for client.GetState() != connectivity.Shutdown {
		select {
		case <-deadline:
			t.Fatal("owner cancellation did not retire clients")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := getGrpcClient(ctx, destination, settings); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed owner acquired a new client: %v", err)
	}
	globalDialerAccess.Lock()
	remaining := len(globalDialerMap)
	globalDialerAccess.Unlock()
	if remaining != 0 {
		t.Fatalf("closed owner left %d cached clients", remaining)
	}
}

func TestGRPCStandaloneStreamClosesClient(t *testing.T) {
	config := &Config{ServiceName: "standalone-test"}
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	encoding.RegisterGRPCServiceServerX(server, reconnectEchoServer{}, config.getServiceName(), config.getTunStreamName(), config.getTunMultiStreamName())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); <-done })
	destination := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	stream, err := dialgRPC(ctx, destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if _, err := stream.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(stream, response); err != nil || string(response) != "alive" {
		t.Fatalf("standalone echo: %q %v", response, err)
	}
	globalDialerAccess.Lock()
	remaining := len(globalDialerMap)
	globalDialerAccess.Unlock()
	if remaining != 0 {
		t.Fatal("standalone client entered shared cache")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}
