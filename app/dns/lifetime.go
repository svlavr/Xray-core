package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// dnsRuntime owns the published resolver and, at most, one unfinished close.
// The feature mutex serializes publication and admission. Each resolver joins
// its admitted queries before its resource references can be forgotten.
type dnsRuntime struct {
	mu           sync.Mutex
	closeMu      sync.Mutex
	current      *resolverOwner
	closing      *resolverOwner
	preparing    bool
	prepDone     chan struct{}
	closed       bool
	dispatcher   routing.Dispatcher
	fake         featuredns.FakeDNSEngine
	contextOwner *featuredns.ContextOwner
}

type resolverOwner struct {
	resolver  *DNS
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	cond      *sync.Cond
	queries   int
	closed    bool
	closing   bool
	done      chan struct{}
	err       error
	resources []*resourceState
}

type resourceState struct {
	name     string
	resource interface{ Close() error }
	done     bool
}

// resourceCloseState is local to a concrete native connection owner. Failed
// closes retain that connection so the owner can reach it on the next Close.
type resourceCloseState struct {
	mu      sync.Mutex
	cond    *sync.Cond
	closing bool
	closed  bool
	lastErr error
}

func (s *resourceCloseState) close(run func() error, onSuccess func()) error {
	s.mu.Lock()
	if s.cond == nil {
		s.cond = sync.NewCond(&s.mu)
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.closing {
		for s.closing {
			s.cond.Wait()
		}
		err := s.lastErr
		s.mu.Unlock()
		return err
	}
	s.closing = true
	s.mu.Unlock()
	err := run()
	s.mu.Lock()
	s.closing = false
	s.lastErr = err
	if err == nil {
		s.closed = true
		if onSuccess != nil {
			onSuccess()
		}
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	return err
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
	defer p.wg.Done()
	err := p.execute()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil || p.closed || !p.running {
		p.running = false
		return err
	}
	p.scheduleLocked()
	return nil
}

func (p *ownedPeriodic) scheduleLocked() {
	p.timer = time.AfterFunc(p.interval, func() {
		p.mu.Lock()
		if p.closed || !p.running {
			p.mu.Unlock()
			return
		}
		p.wg.Add(1)
		p.mu.Unlock()
		defer p.wg.Done()
		err := p.execute()
		p.mu.Lock()
		defer p.mu.Unlock()
		if err != nil || p.closed || !p.running {
			p.running = false
			return
		}
		p.scheduleLocked()
	})
}

func (p *ownedPeriodic) Close() error {
	p.mu.Lock()
	p.closed, p.running = true, false
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

func newResolverOwner(resolver *DNS) *resolverOwner {
	ctx, cancel := context.WithCancel(context.Background())
	o := &resolverOwner{resolver: resolver, ctx: ctx, cancel: cancel, resources: resolverResources(resolver)}
	o.cond = sync.NewCond(&o.mu)
	return o
}

func (o *resolverOwner) admit() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return false
	}
	o.queries++
	return true
}

func (o *resolverOwner) release() {
	o.mu.Lock()
	o.queries--
	if o.queries == 0 {
		o.cond.Broadcast()
	}
	o.mu.Unlock()
}

func (o *resolverOwner) stop() {
	o.mu.Lock()
	o.closed = true
	o.cancel()
	o.mu.Unlock()
}

func (o *resolverOwner) closeResources() error {
	var errs []error
	for _, state := range o.resources {
		if state.done {
			continue
		}
		if err := state.resource.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", state.name, err))
		} else {
			state.done = true
		}
	}
	return errors.Join(errs...)
}

// closeOwned first interrupts concrete resources, then joins admitted queries.
// A failed resource is retained in the same owner for a later feature Close.
func (o *resolverOwner) closeOwned() error {
	o.mu.Lock()
	if o.closing {
		done := o.done
		o.mu.Unlock()
		<-done
		return o.err
	}
	o.closing = true
	o.done = make(chan struct{})
	o.mu.Unlock()
	o.stop()
	err := o.closeResources()
	o.mu.Lock()
	for o.queries != 0 {
		o.cond.Wait()
	}
	o.mu.Unlock()
	o.resolver.queryWorkers.Wait()
	o.mu.Lock()
	o.err = err
	o.closing = false
	close(o.done)
	o.mu.Unlock()
	return err
}

func (s *DNS) initRuntime(dispatcher routing.Dispatcher, fake featuredns.FakeDNSEngine, resolver *DNS) {
	s.runtime = &dnsRuntime{current: newResolverOwner(resolver), dispatcher: dispatcher, fake: fake, contextOwner: featuredns.NewContextOwner()}
}

func (s *DNS) acquireCurrent() (*resolverOwner, error) {
	rt := s.runtime
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed || rt.current == nil {
		return nil, context.Canceled
	}
	owner := rt.current
	if !owner.admit() {
		return nil, context.Canceled
	}
	return owner, nil
}

func (s *DNS) finishPreparation() {
	rt := s.runtime
	rt.mu.Lock()
	rt.preparing = false
	close(rt.prepDone)
	rt.prepDone = nil
	rt.mu.Unlock()
}

func (s *DNS) closeUnpublished(candidate *DNS) error {
	o := newResolverOwner(candidate)
	rt := s.runtime
	rt.mu.Lock()
	if rt.closing != nil {
		rt.mu.Unlock()
		return fmt.Errorf("DNS cleanup owner occupied")
	}
	rt.closing = o
	rt.mu.Unlock()
	err := o.closeOwned()
	if err == nil {
		rt.mu.Lock()
		if rt.closing == o {
			rt.closing = nil
		}
		rt.mu.Unlock()
	}
	return err
}

func (s *DNS) applyConfig(ctx context.Context, config *Config) ApplyResult {
	rt := s.runtime
	rt.mu.Lock()
	switch {
	case rt.closed:
		rt.mu.Unlock()
		return ApplyResult{Err: context.Canceled}
	case rt.preparing:
		rt.mu.Unlock()
		return ApplyResult{Err: fmt.Errorf("DNS update already in progress")}
	case rt.closing != nil:
		rt.mu.Unlock()
		return ApplyResult{Err: fmt.Errorf("previous DNS resolver cleanup incomplete")}
	}
	rt.preparing = true
	rt.prepDone = make(chan struct{})
	dispatcher, fake := rt.dispatcher, rt.fake
	rt.mu.Unlock()
	defer s.finishPreparation()

	clone, err := cloneAndValidateConfig(config)
	if err != nil {
		return ApplyResult{Err: err}
	}
	if len(clone.NameServer) == 0 {
		return ApplyResult{Err: fmt.Errorf("explicit DNS update requires a nameserver")}
	}
	if err := ctx.Err(); err != nil {
		return ApplyResult{Err: err}
	}
	if instance := core.FromContext(s.ctx); instance != nil {
		if dispatcher == nil {
			dispatcher, _ = instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
		}
		if fake == nil {
			fake, _ = instance.GetFeature((*featuredns.FakeDNSEngine)(nil)).(featuredns.FakeDNSEngine)
		}
	}
	var candidate *DNS
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("invalid DNS configuration: %v", recovered)
			}
		}()
		candidate, err = buildDNS(context.Background(), clone, dispatcher, fake)
	}()
	if err != nil {
		return ApplyResult{Err: err}
	}
	candidate.strictSelection = true
	if err := ctx.Err(); err != nil {
		return ApplyResult{Err: errors.Join(err, s.closeUnpublished(candidate))}
	}
	rt.mu.Lock()
	if rt.closed || ctx.Err() != nil {
		rt.mu.Unlock()
		return ApplyResult{Err: errors.Join(context.Canceled, ctx.Err(), s.closeUnpublished(candidate))}
	}
	old := rt.current
	rt.current = newResolverOwner(candidate)
	rt.closing = old
	rt.dispatcher, rt.fake = dispatcher, fake
	old.stop()
	rt.mu.Unlock()
	// Publication is complete. Cancellation, resource close, and query join are
	// bounded by ctx for the caller; unfinished work remains in rt.closing.
	done := make(chan error, 1)
	go func() {
		err := old.closeOwned()
		if err == nil {
			rt.mu.Lock()
			if rt.closing == old {
				rt.closing = nil
			}
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

func resolverResources(resolver *DNS) []*resourceState {
	if resolver == nil {
		return nil
	}
	seen := make(map[Server]struct{})
	var resources []*resourceState
	for _, client := range resolver.clients {
		if client == nil || client.server == nil {
			continue
		}
		if _, ok := seen[client.server]; ok {
			continue
		}
		seen[client.server] = struct{}{}
		if resource, ok := client.server.(interface{ Close() error }); ok {
			resources = append(resources, &resourceState{name: client.Name(), resource: resource})
		}
	}
	return resources
}

func closeResolverResources(resolver *DNS) error { return newResolverOwner(resolver).closeOwned() }
