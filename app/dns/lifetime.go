package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// dnsRuntime owns the published resolver and, at most, one unfinished close.
// The feature mutex serializes publication and admission. Each resolver joins
// its admitted queries before its resource references can be forgotten.
type dnsRuntime struct {
	mu sync.Mutex
	// systemDNSMu orders unsafe resolver publication against Linux system DNS takeover.
	// Takeover holds a read lock until the OS settings are reverted.
	systemDNSMu sync.RWMutex
	closeMu     sync.Mutex
	current     *resolverOwner
	closing     *resolverOwner
	closed      bool
}

type resolverOwner struct {
	resolver  *DNS
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func newResolverOwner(resolver *DNS) *resolverOwner {
	ctx, cancel := context.WithCancel(context.Background())
	return &resolverOwner{resolver: resolver, ctx: ctx, cancel: cancel}
}

func (o *resolverOwner) closeResources() error {
	var errs []error
	for _, client := range o.resolver.clients {
		if resource, ok := client.server.(interface{ Close() error }); ok {
			if err := resource.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close %s: %w", client.Name(), err))
			}
		}
	}
	return errors.Join(errs...)
}

// closeOwned shares one terminal close and query join between retirement callers.
// The resolver is already retired and canceled under dnsRuntime.mu.
func (o *resolverOwner) closeOwned() error {
	o.closeOnce.Do(func() {
		o.closeErr = o.closeResources()
		o.resolver.queries.Wait()
	})
	return o.closeErr
}

// connectionLifetime owns TCP and DoH dial admission, workers, and open sockets.
// Each nameserver supplies its existing cache controller for cancellation.
type connectionLifetime struct {
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	dialing     sync.WaitGroup
	workers     sync.WaitGroup
}

func (l *connectionLifetime) beginDial(cache *CacheController) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cache.ctx.Err() != nil {
		return false
	}
	l.dialing.Add(1)
	return true
}

func (l *connectionLifetime) beginWork(cache *CacheController) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cache.ctx.Err() != nil {
		return false
	}
	l.workers.Add(1)
	return true
}

func (l *connectionLifetime) trackConnection(cache *CacheController, conn net.Conn) (net.Conn, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	accepted := cache.ctx.Err() == nil
	var tracked *trackedConn
	tracked = &trackedConn{Conn: conn, done: func() {
		l.mu.Lock()
		delete(l.connections, tracked)
		l.mu.Unlock()
	}}
	if l.connections == nil {
		l.connections = make(map[net.Conn]struct{})
	}
	l.connections[tracked] = struct{}{}
	return tracked, accepted
}

func (l *connectionLifetime) close(cache *CacheController) error {
	cache.cancel()
	// Join admissions that observed the owner before cancellation.
	l.mu.Lock()
	l.mu.Unlock()
	l.dialing.Wait()
	l.mu.Lock()
	connections := make([]net.Conn, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	var errs []error
	for _, conn := range connections {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	cache.Close()
	l.workers.Wait()
	return errors.Join(errs...)
}

func (s *DNS) initRuntime(resolver *DNS) {
	s.runtime = &dnsRuntime{current: newResolverOwner(resolver)}
}

func (s *DNS) applyConfig(ctx context.Context, config *Config) ApplyResult {
	rt := s.runtime
	clone := proto.Clone(config).(*Config)
	if len(clone.NameServer) == 0 {
		return ApplyResult{Err: fmt.Errorf("explicit DNS update requires a nameserver")}
	}
	if err := ctx.Err(); err != nil {
		return ApplyResult{Err: err}
	}
	var dispatcher routing.Dispatcher
	var fake featuredns.FakeDNSEngine
	if instance := core.FromContext(s.ctx); instance != nil {
		dispatcher, _ = instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
		fake, _ = instance.GetFeature((*featuredns.FakeDNSEngine)(nil)).(featuredns.FakeDNSEngine)
	}
	candidate, err := buildDNS(context.Background(), clone, dispatcher, fake)
	if err != nil {
		return ApplyResult{Err: err}
	}
	candidate.strictSelection = true
	unsafeSystemDNS := resolverMayUseSystem(candidate)
	if unsafeSystemDNS {
		if !rt.systemDNSMu.TryLock() {
			return ApplyResult{Err: fmt.Errorf("system DNS takeover prevents this DNS update")}
		}
		defer func() {
			if unsafeSystemDNS {
				rt.systemDNSMu.Unlock()
			}
		}()
	}
	rt.mu.Lock()
	if err := ctx.Err(); err != nil {
		rt.mu.Unlock()
		return ApplyResult{Err: err}
	}
	if rt.closed {
		rt.mu.Unlock()
		return ApplyResult{Err: context.Canceled}
	}
	if rt.closing != nil {
		rt.mu.Unlock()
		return ApplyResult{Err: fmt.Errorf("previous DNS resolver cleanup incomplete")}
	}
	old := rt.current
	rt.current = newResolverOwner(candidate)
	rt.closing = old
	old.cancel()
	rt.mu.Unlock()
	if unsafeSystemDNS {
		rt.systemDNSMu.Unlock()
		unsafeSystemDNS = false
	}
	// Publication is complete. Cancellation, resource close, and query join are
	// bounded by ctx for the caller; unfinished work remains in rt.closing.
	done := make(chan error, 1)
	go func() {
		err := old.closeOwned()
		rt.mu.Lock()
		rt.closing = nil
		rt.mu.Unlock()
		done <- err
	}()
	select {
	case err := <-done:
		return ApplyResult{Applied: true, Err: err}
	case <-ctx.Done():
		return ApplyResult{Applied: true, Err: ctx.Err()}
	}
}

// trackedConn removes a connection after its terminal Close attempt.
type trackedConn struct {
	net.Conn
	done func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.done()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
