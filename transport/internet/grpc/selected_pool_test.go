package grpc

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func TestGRPCPoolSharesNativeAndSelectedOrigins(t *testing.T) {
	for _, multi := range []bool{false, true} {
		for _, nativeFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("multi=%v/native-first=%v", multi, nativeFirst), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				config := &Config{ServiceName: "native-selected-sharing", MultiMode: multi}
				settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
				var sockets atomic.Int32
				physicalContexts := make(chan context.Context, 8)
				settings.FinalMask = finalmask.NewFinalMask(nil, nil, func(ctx context.Context, dest net.Destination) (net.Conn, error) {
					conn, err := (&stdnet.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr())
					if err == nil {
						sockets.Add(1)
						physicalContexts <- ctx
					}
					return conn, err
				}, nil, nil, nil)
				server := gogrpc.NewServer()
				encoding.RegisterGRPCServiceServerX(server, sharedOriginEchoServer{}, config.getServiceName(), config.getTunStreamName(), config.getTunMultiStreamName())
				done := make(chan struct{})
				go func() { defer close(done); _ = server.Serve(listener) }()
				t.Cleanup(func() { server.Stop(); <-done })
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				t.Cleanup(cancel)
				nativeCtx := session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
				userCtx, cancelUser := context.WithCancel(internet.ContextWithMUTransport(nativeCtx))
				t.Cleanup(cancelUser)
				userCtx = session.ContextWithLogicalObservation(userCtx, &session.LogicalObservation{})
				measurementCtx := session.ContextWithTrafficOrigin(ctx, session.TrafficOriginControlledMeasurement)
				dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
				firstCtx := measurementCtx
				if nativeFirst {
					firstCtx = nativeCtx
				}
				client, err := getGrpcClient(firstCtx, dest, settings)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				for _, call := range []context.Context{nativeCtx, userCtx, measurementCtx} {
					if shared, err := getGrpcClient(call, dest, settings); err != nil || shared != client {
						t.Fatalf("logical selection/origin partitioned physical pool: %v", err)
					}
				}
				for {
					state := client.GetState()
					if state == connectivity.Ready {
						break
					}
					if state == connectivity.Shutdown || !client.WaitForStateChange(ctx, state) {
						t.Fatal("shared client did not connect")
					}
				}
				var physical context.Context
				select {
				case physical = <-physicalContexts:
				case <-ctx.Done():
					t.Fatal("no actual shared socket witness")
				}
				if session.LogicalObservationFromContext(physical) != nil {
					t.Fatal("shared physical channel inherited logical USER observation")
				}
				if !internet.MUSelected(physical) || session.TrafficOriginFromContext(physical) != session.TrafficOriginInternal {
					t.Fatal("shared default physical channel lost backend fence")
				}
				native, err := dialgRPC(nativeCtx, dest, settings)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = native.Close() })
				user, err := dialgRPC(userCtx, dest, settings)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = user.Close() })
				measurement, err := dialgRPC(measurementCtx, dest, settings)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = measurement.Close() })
				exchange := func(conn net.Conn, value string) {
					t.Helper()
					if _, err := conn.Write([]byte(value)); err != nil {
						t.Fatal(err)
					}
					payload := make([]byte, len(value))
					if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != value {
						t.Fatalf("shared exchange: %q %v", payload, err)
					}
				}
				exchange(native, "native")
				exchange(user, "user")
				exchange(measurement, "measurement")
				cancelUser()
				if _, err := user.Read(make([]byte, 1)); err == nil {
					t.Fatal("canceled USER RPC remained readable")
				}
				if client.GetState() == connectivity.Shutdown {
					t.Fatal("logical USER cancellation closed shared physical channel")
				}
				exchange(native, "native-after-user-cancel")
				exchange(measurement, "measurement-after-user-cancel")
				if sockets.Load() != 1 {
					t.Fatalf("same transport opened %d physical sockets", sockets.Load())
				}
				if again, err := getGrpcClient(measurementCtx, dest, settings); err != nil || again != client {
					t.Fatalf("RPC cancellation replaced native pool channel: %v", err)
				}
			})
		}
	}
}

func TestGRPCSelectedDefaultDoesNotBorrowNativeGatewayChannel(t *testing.T) {
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{ServiceName: "gateway-bucket"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// No server is needed: native NewClient exposes physical owner identity
	// before asynchronous connect, and every created owner is explicitly closed.
	dest := net.TCPDestination(net.LocalHostIP, 9)
	nativeGateway := session.ContextWithOutbounds(ctx, []*session.Outbound{{Gateway: net.LocalHostIP}})
	gateway, err := getGrpcClient(nativeGateway, dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	if same, err := getGrpcClient(nativeGateway, dest, settings); err != nil || same != gateway {
		t.Fatalf("native same-gateway pool changed: %v", err)
	}
	selectedDefault := session.ContextWithTrafficOrigin(ctx, session.TrafficOriginControlledMeasurement)
	plain, err := getGrpcClient(selectedDefault, dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if plain == gateway {
		t.Fatal("selected default borrowed native explicitly sourced channel")
	}
	privateCtx := session.ContextWithOutbounds(selectedDefault, []*session.Outbound{{Gateway: net.LocalHostIP}})
	first, err := getGrpcClient(privateCtx, dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := getGrpcClient(privateCtx, dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first == gateway || second == gateway || first == second || first == plain || second == plain {
		t.Fatal("selected gateway entered a shared physical bucket")
	}
	proxySettings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: settings.ProtocolSettings, SocketSettings: &internet.SocketConfig{DialerProxy: "private-test"}}
	if grpcPooled(selectedDefault, proxySettings) {
		t.Fatal("selected DialerProxy was pooled")
	}
}

func TestGRPCDefaultPoolFreezesNativeCreatorRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{ServiceName: "route-snapshot"}
	server := gogrpc.NewServer()
	encoding.RegisterGRPCServiceServerX(server, sharedOriginEchoServer{}, config.getServiceName(), config.getTunStreamName(), config.getTunMultiStreamName())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	entered := make(chan context.Context, 8)
	release := make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	settings.FinalMask = finalmask.NewFinalMask(nil, nil, func(physical context.Context, dest net.Destination) (net.Conn, error) {
		entered <- physical
		select {
		case <-release:
		case <-physical.Done():
			return nil, physical.Err()
		}
		obs := session.OutboundsFromContext(physical)
		if len(obs) != 1 || obs[0].Gateway != nil || obs[0].Tag != "native-original" {
			return nil, fmt.Errorf("mutated creator changed gateway-free physical route: %+v", obs)
		}
		return (&stdnet.Dialer{}).DialContext(physical, "tcp", dest.NetAddr())
	}, nil, nil, nil)
	original := &session.Outbound{Tag: "native-original"}
	native := session.ContextWithOutbounds(ctx, []*session.Outbound{original})
	dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
	client, err := getGrpcClient(native, dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("native-created default dial did not start")
	}
	// The real dial callback is waiting; channel release orders this mutation
	// before its metadata check. No concurrent test-owned mutation is assumed.
	original.Gateway = net.LocalHostIP
	original.Tag = "mutated-caller"
	selected := session.ContextWithTrafficOrigin(ctx, session.TrafficOriginControlledMeasurement)
	if borrowed, err := getGrpcClient(selected, dest, settings); err != nil || borrowed != client {
		t.Fatalf("selected default did not borrow qualified native route: %v", err)
	}
	unblock()
	for {
		state := client.GetState()
		if state == connectivity.Ready {
			break
		}
		if state == connectivity.Shutdown || !client.WaitForStateChange(ctx, state) {
			t.Fatal("mutated creator prevented qualified default connect")
		}
	}
	stream, err := dialgRPC(selected, dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if _, err := stream.Write([]byte("snapshot")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, len("snapshot"))
	if _, err := io.ReadFull(stream, payload); err != nil || string(payload) != "snapshot" {
		t.Fatalf("qualified shared route exchange: %q %v", payload, err)
	}
}

type sharedOriginEchoServer struct {
	encoding.UnimplementedGRPCServiceServer
}

func (sharedOriginEchoServer) Tun(stream encoding.GRPCService_TunServer) error {
	for {
		h, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(h); err != nil {
			return err
		}
	}
}

func (sharedOriginEchoServer) TunMulti(stream encoding.GRPCService_TunMultiServer) error {
	for {
		h, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(h); err != nil {
			return err
		}
	}
}
