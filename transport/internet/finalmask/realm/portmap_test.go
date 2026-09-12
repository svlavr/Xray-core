package realm

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/realm/internal/nat"
)

type testGateway struct {
	mu            sync.Mutex
	grant         nat.Grant
	ip            net.IP
	lookup        error
	deleteErr     error
	adds, deletes int
}

func (g *testGateway) Type() string { return "test" }
func (g *testGateway) AddPortMappingGrant(context.Context, string, int, string, time.Duration) (nat.Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.adds++
	return g.grant, nil
}

func (g *testGateway) DeletePortMappingGrant(context.Context, string, int, nat.Grant) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deletes++
	return g.deleteErr
}

func TestPortMapperCloseCancelsRenewBeforeCleanup(t *testing.T) {
	started := make(chan struct{})
	g := &cancelRenewGateway{started: started}
	m, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: time.Second}, g)
	if err != nil {
		t.Fatal(err)
	}
	renewDone := make(chan error, 1)
	go func() {
		_, err := m.Renew(context.Background())
		renewDone <- err
	}()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	select {
	case err := <-renewDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("renew error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel in-flight renew")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join renew and cleanup")
	}
	if g.deletes != 1 {
		t.Fatalf("deletes=%d", g.deletes)
	}
}

type cancelRenewGateway struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	deletes int
}

func (g *cancelRenewGateway) Type() string { return "cancel-test" }
func (g *cancelRenewGateway) AddPortMappingGrant(ctx context.Context, _ string, _ int, _ string, _ time.Duration) (nat.Grant, error) {
	g.mu.Lock()
	g.calls++
	call := g.calls
	g.mu.Unlock()
	if call == 1 {
		return nat.Grant{Port: 4321, Lifetime: time.Minute}, nil
	}
	close(g.started)
	<-ctx.Done()
	return nat.Grant{}, ctx.Err()
}

func (g *cancelRenewGateway) DeletePortMappingGrant(context.Context, string, int, nat.Grant) error {
	g.mu.Lock()
	g.deletes++
	g.mu.Unlock()
	return nil
}

func (g *cancelRenewGateway) GetExternalAddressContext(context.Context) (net.IP, error) {
	return net.IPv4(203, 0, 113, 2), nil
}

func TestPortMapperCloseFailureIsStableAndNotRetried(t *testing.T) {
	deleteErr := errors.New("delete failed")
	g := &testGateway{grant: nat.Grant{Port: 4321, Lifetime: time.Minute}, ip: net.IPv4(203, 0, 113, 1), deleteErr: deleteErr}
	m, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: time.Second}, g)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); !errors.Is(err, deleteErr) {
		t.Fatalf("first Close error=%v", err)
	}
	if err := m.Close(); !errors.Is(err, deleteErr) {
		t.Fatalf("repeated Close error=%v", err)
	}
	if g.deletes != 1 || m.Receipt() != PortMapRemoteDeleteUnconfirmed {
		t.Fatalf("deletes=%d receipt=%d", g.deletes, m.Receipt())
	}
}

type lateSuccessGateway struct {
	mu           sync.Mutex
	calls        int
	started      chan struct{}
	deletedGrant nat.Grant
}

func (g *lateSuccessGateway) Type() string { return "late-success" }
func (g *lateSuccessGateway) AddPortMappingGrant(ctx context.Context, _ string, _ int, _ string, _ time.Duration) (nat.Grant, error) {
	g.mu.Lock()
	g.calls++
	call := g.calls
	g.mu.Unlock()
	if call == 1 {
		return nat.Grant{Port: 4321, Lifetime: time.Minute}, nil
	}
	close(g.started)
	<-ctx.Done()
	// The remote Add completed concurrently with cancellation. PortMapper must
	// own this exact result before observing ctx.Err and then clean it up.
	return nat.Grant{Port: 5432, Lifetime: 2 * time.Minute}, nil
}

func (g *lateSuccessGateway) DeletePortMappingGrant(_ context.Context, _ string, _ int, grant nat.Grant) error {
	g.mu.Lock()
	g.deletedGrant = grant
	g.mu.Unlock()
	return nil
}

func (g *lateSuccessGateway) GetExternalAddressContext(context.Context) (net.IP, error) {
	return net.IPv4(203, 0, 113, 4), nil
}

func TestPortMapperOwnsAddThatSucceedsAfterCancel(t *testing.T) {
	g := &lateSuccessGateway{started: make(chan struct{})}
	m, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: time.Second}, g)
	if err != nil {
		t.Fatal(err)
	}
	renewDone := make(chan error, 1)
	go func() {
		_, err := m.Renew(context.Background())
		renewDone <- err
	}()
	<-g.started
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-renewDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("renew error=%v", err)
	}
	g.mu.Lock()
	deleted := g.deletedGrant
	g.mu.Unlock()
	if deleted.Port != 5432 || deleted.Lifetime != 2*time.Minute {
		t.Fatalf("deleted grant=%+v", deleted)
	}
}

type timeoutDeleteGateway struct{ testGateway }

func (g *timeoutDeleteGateway) DeletePortMappingGrant(ctx context.Context, _ string, _ int, _ nat.Grant) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestPortMapperCleanupTimeoutIsUnconfirmed(t *testing.T) {
	g := &timeoutDeleteGateway{testGateway: testGateway{
		grant: nat.Grant{Port: 4321, Lifetime: time.Minute},
		ip:    net.IPv4(203, 0, 113, 5),
	}}
	m, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: 20 * time.Millisecond}, g)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = m.Close()
	if !errors.Is(err, context.DeadlineExceeded) || m.Receipt() != PortMapRemoteDeleteUnconfirmed {
		t.Fatalf("error=%v receipt=%d", err, m.Receipt())
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cleanup exceeded bound: %s", elapsed)
	}
	if err := m.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("repeated Close error=%v", err)
	}
}

func (g *testGateway) GetExternalAddressContext(context.Context) (net.IP, error) {
	return g.ip, g.lookup
}

func TestPortMapLifetimeBounds(t *testing.T) {
	for _, lifetime := range []time.Duration{-time.Second, time.Second / 2, 604801 * time.Second} {
		if _, err := (PortMapConfig{Lifetime: lifetime}).withDefaults(); err == nil {
			t.Fatalf("lifetime %s accepted", lifetime)
		}
	}
	if got, err := (PortMapConfig{}).withDefaults(); err != nil || got.Lifetime != 600*time.Second {
		t.Fatalf("default: %#v %v", got, err)
	}
}

func TestPortMapProtoBoundsBeforeDurationConversion(t *testing.T) {
	for _, config := range []*PortMapping{
		{Lifetime: 604801},
		{Lifetime: -1},
		{Timeout: int64(^uint64(0)>>1)/int64(time.Second) + 1},
	} {
		if _, err := portMapConfigFromProto(config); err == nil {
			t.Fatalf("config %+v accepted", config)
		}
	}
	got, err := portMapConfigFromProto(&PortMapping{})
	if err != nil || got.Lifetime != 600*time.Second {
		t.Fatalf("default=%+v err=%v", got, err)
	}
}

func TestPortMapperOwnsAddBeforeLookupAndClosesOnce(t *testing.T) {
	g := &testGateway{grant: nat.Grant{Port: 1234, Lifetime: time.Minute}, ip: net.IPv4(203, 0, 113, 1), lookup: errors.New("lookup")}
	m, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: time.Second}, g)
	if err == nil || m != nil {
		t.Fatal("lookup failure must fail construction")
	}
	if g.deletes != 1 {
		t.Fatalf("deletes=%d, want 1", g.deletes)
	}
}

func TestPortMapperActualGrantAndStableClose(t *testing.T) {
	g := &testGateway{grant: nat.Grant{Port: 4321, Lifetime: 2 * time.Minute}, ip: net.IPv4(203, 0, 113, 1)}
	m, err := newPortMapper(context.Background(), 1234, PortMapConfig{Lifetime: time.Minute, Timeout: time.Second}, g)
	if err != nil {
		t.Fatal(err)
	}
	if m.ExternalAddr().Port() != 4321 || m.Lifetime() != 2*time.Minute {
		t.Fatal("actual grant not retained")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if g.deletes != 1 || m.Receipt() != PortMapRemoteDeleteConfirmed {
		t.Fatalf("delete=%d receipt=%d", g.deletes, m.Receipt())
	}
}
