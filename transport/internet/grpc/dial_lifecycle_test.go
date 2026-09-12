package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestGRPCDialContextKeepsGRPCCancellationAndOwner(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	grpcCtx, cancelGRPC := context.WithCancel(context.Background())
	linked, release := grpcDialContext(grpcCtx, context.Background(), owner)
	defer release()
	if got := internet.ResourceLifecycleFromContext(linked); got != owner {
		t.Fatal("dial context lost exact resource lifecycle")
	}
	cancelGRPC()
	select {
	case <-linked.Done():
	case <-time.After(time.Second):
		t.Fatal("grpc cancellation did not propagate")
	}

	linked, release = grpcDialContext(context.Background(), context.Background(), owner)
	defer release()
	owner.SignalStop()
	select {
	case <-linked.Done():
	case <-time.After(time.Second):
		t.Fatal("owner cancellation did not propagate")
	}

	stoppedOwner := internet.NewResourceLifecycle(context.Background())
	stoppedOwner.SignalStop()
	linked, release = grpcDialContext(context.Background(), context.Background(), stoppedOwner)
	defer release()
	select {
	case <-linked.Done():
	default:
		t.Fatal("already-stopped owner was not reflected synchronously")
	}

	cancelledGRPC, cancel := context.WithCancel(context.Background())
	cancel()
	linked, release = grpcDialContext(cancelledGRPC, context.Background(), internet.NewResourceLifecycle(context.Background()))
	defer release()
	select {
	case <-linked.Done():
	default:
		t.Fatal("already-cancelled grpc context was not reflected synchronously")
	}
}

func TestGRPCCacheKeySeparatesOwners(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	dest := net.TCPDestination(net.ParseAddress("127.0.0.1"), net.Port(443))
	left := dialerConf{Destination: dest, MemoryStreamConfig: settings, ownerID: 1}
	right := dialerConf{Destination: dest, MemoryStreamConfig: settings, ownerID: 2}
	if left == right {
		t.Fatal("distinct resource owners share a cached gRPC key")
	}
}

func TestGRPCResourceStopOnlyEvictsItsOwnCacheEntry(t *testing.T) {
	settings := &internet.MemoryStreamConfig{}
	key := dialerConf{Destination: net.TCPDestination(net.ParseAddress("127.0.0.1"), net.Port(443)), MemoryStreamConfig: settings, ownerID: 1}
	firstConn, err := googlegrpc.NewClient("passthrough:///first", googlegrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	secondConn, err := googlegrpc.NewClient("passthrough:///second", googlegrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	first := &grpcClientResource{key: key, conn: firstConn, closeDone: make(chan struct{})}
	second := &grpcClientResource{key: key, conn: secondConn, closeDone: make(chan struct{})}
	globalDialerAccess.Lock()
	previous := globalDialerMap
	globalDialerMap = map[dialerConf]*grpcClientResource{key: first}
	globalDialerMap[key] = second // a newer generation replaces the old entry.
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		_ = secondConn.Close()
		globalDialerAccess.Lock()
		globalDialerMap = previous
		globalDialerAccess.Unlock()
	})
	first.SignalStop()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	globalDialerAccess.Lock()
	got := globalDialerMap[key]
	globalDialerAccess.Unlock()
	if got != second {
		t.Fatal("old resource evicted replacement cache entry")
	}
}

func TestGRPCRejectsMissingOwnerBeforeClientPublication(t *testing.T) {
	_, err := getGrpcClient(context.Background(), net.TCPDestination(net.ParseAddress("127.0.0.1"), net.Port(443)), &internet.MemoryStreamConfig{})
	if err == nil {
		t.Fatal("gRPC client was admitted without an owner")
	}
}

func TestGRPCConcurrentConstructionPublishesOneOwnedClient(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	settings := &internet.MemoryStreamConfig{
		ProtocolSettings:  &Config{UserAgent: "golang"},
		ResourceLifecycle: owner,
	}
	dest := net.TCPDestination(net.ParseAddress("127.0.0.1"), net.Port(1))
	const callers = 32
	start := make(chan struct{})
	results := make(chan *googlegrpc.ClientConn, callers)
	errors := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			conn, err := getGrpcClient(context.Background(), dest, settings)
			results <- conn
			errors <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("owned client construction failed: %v", err)
		}
	}
	var published *googlegrpc.ClientConn
	for conn := range results {
		if published == nil {
			published = conn
		} else if conn != published {
			t.Fatal("concurrent same-key construction published multiple clients")
		}
	}
	if published == nil {
		t.Fatal("no client was published")
	}
	key := dialerConf{Destination: dest, MemoryStreamConfig: settings, ownerID: owner.ID()}
	if err := owner.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if published.GetState() != connectivity.Shutdown {
		t.Fatal("owner close did not join ClientConn shutdown")
	}
	globalDialerAccess.Lock()
	entry := globalDialerMap[key]
	globalDialerAccess.Unlock()
	if entry != nil {
		t.Fatal("owner close did not evict exact cached client")
	}
	if _, err := getGrpcClient(context.Background(), dest, settings); err == nil {
		t.Fatal("sealed owner admitted a cache hit")
	}
}
