package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

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
	resolver *DNS
	ctx      context.Context
	cancel   context.CancelFunc
	closeMu  sync.Mutex
	queries  sync.WaitGroup
}

// ownedPeriodic preserves the cache and UDP cleanup worker join already needed
// by their native owners; it carries no resolver identity or query capability.
type ownedPeriodic struct {
	mu       sync.Mutex
	interval time.Duration
	execute  func() error
	timer    *time.Timer
	running  bool
	closed   bool
	wg       sync.WaitGroup
}

func newOwnedPeriodic(interval time.Duration, execute func() error) *ownedPeriodic {
	return &ownedPeriodic{interval: interval, execute: execute}
}

func (p *ownedPeriodic) Start() error {
	p.mu.Lock()
	if p.closed || p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = true
	p.wg.Add(1)
	p.mu.Unlock()
	return p.run()
}

func (p *ownedPeriodic) run() error {
	defer p.wg.Done()
	err := p.execute()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil || p.closed {
		p.running = false
		return err
	}
	p.timer = time.AfterFunc(p.interval, func() {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.wg.Add(1)
		p.mu.Unlock()
		p.run()
	})
	return nil
}

func (p *ownedPeriodic) Close() {
	p.mu.Lock()
	p.closed, p.running = true, false
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.mu.Unlock()
	p.wg.Wait()
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

// closeOwned joins a resolver already retired and canceled under dnsRuntime.mu.
// A failed resource is retained in the same owner for a later feature Close.
func (o *resolverOwner) closeOwned() error {
	o.closeMu.Lock()
	defer o.closeMu.Unlock()
	err := o.closeResources()
	o.queries.Wait()
	o.resolver.queryWorkers.Wait()
	return err
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
		if err == nil {
			rt.mu.Lock()
			rt.closing = nil
			rt.mu.Unlock()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return ApplyResult{Applied: true, Err: err}
	case <-ctx.Done():
		return ApplyResult{Applied: true, Err: ctx.Err()}
	}
}

// trackedConn removes a successfully closed connection from its native owner.
type trackedConn struct {
	net.Conn
	done func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	c.done()
	return nil
}
