package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

type RetirementDisposition string

const (
	Retired        RetirementDisposition = "RETIRED"
	WaitIncomplete RetirementDisposition = "WAIT_INCOMPLETE"
	RetireFailed   RetirementDisposition = "RETIRE_FAILED"
)

type RetirementResult struct {
	Generation  uint64
	Terminal    bool
	Disposition RetirementDisposition
	Failure     FailureClass
}

type RetirementReceipt struct {
	generation uint64
	mu         sync.Mutex
	done       chan struct{}
	doneClosed bool
	result     RetirementResult
	retrying   bool
	retry      func() RetirementResult
}

func newRetirementReceipt(generation uint64) *RetirementReceipt {
	return &RetirementReceipt{
		generation: generation,
		done:       make(chan struct{}),
		result:     RetirementResult{Generation: generation, Disposition: WaitIncomplete},
	}
}

func (r *RetirementReceipt) complete(result RetirementResult) {
	r.mu.Lock()
	if r.result.Terminal {
		r.mu.Unlock()
		return
	}
	r.result = result
	if result.Terminal {
		r.retry = nil
	}
	if !r.doneClosed {
		close(r.done)
		r.doneClosed = true
	}
	r.mu.Unlock()
}

func (r *RetirementReceipt) Wait(ctx context.Context) RetirementResult {
	r.mu.Lock()
	done := r.done
	result := r.result
	r.mu.Unlock()
	if result.Terminal || result.Disposition == RetireFailed {
		return result
	}
	select {
	case <-done:
		r.mu.Lock()
		result = r.result
		r.mu.Unlock()
		return result
	case <-ctx.Done():
		return RetirementResult{Generation: r.generation, Disposition: WaitIncomplete, Failure: FailureCanceled}
	}
}

func (r *RetirementReceipt) Retry(ctx context.Context) RetirementResult {
	r.mu.Lock()
	if r.result.Terminal {
		result := r.result
		r.mu.Unlock()
		return result
	}
	if r.result.Disposition != RetireFailed || r.retry == nil || r.retrying {
		r.mu.Unlock()
		return RetirementResult{Generation: r.generation, Disposition: WaitIncomplete}
	}
	r.retrying = true
	retry := r.retry
	r.mu.Unlock()

	done := make(chan RetirementResult, 1)
	go func() {
		result := retry()
		r.mu.Lock()
		r.retrying = false
		if !r.result.Terminal {
			r.result = result
			if result.Terminal {
				r.retry = nil
			}
		}
		result = r.result
		r.mu.Unlock()
		done <- result
	}()
	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		return RetirementResult{Generation: r.generation, Disposition: WaitIncomplete, Failure: FailureCanceled}
	}
}

type dnsRuntime struct {
	mu              sync.Mutex
	current         *dnsGeneration
	retiring        *dnsGeneration
	retiringReceipt *RetirementReceipt
	preparing       bool
	prepDone        chan struct{}
	closed          bool
	closeDone       chan struct{}
	closeErr        error
	nextID          uint64
	dispatcher      routing.Dispatcher
	fake            featuredns.FakeDNSEngine
	contextOwner    *featuredns.ContextOwner
	retirementWork  sync.WaitGroup
}

type dnsGeneration struct {
	id       uint64
	owner    *DNS
	resolver *DNS
	ctx      context.Context
	cancel   context.CancelFunc

	mu     sync.Mutex
	cond   *sync.Cond
	sealed bool
	leases int
	closed bool

	cleanupMu   sync.Mutex
	cleanupDone bool
	resources   []*generationResourceState
}

type generationResourceState struct {
	name     string
	resource generationResource
	done     bool
}

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

type dnsLease struct {
	generation *dnsGeneration
	active     atomic.Bool
}

// ownedPeriodic is a DNS-local periodic owner with an explicit in-flight join.
// It replaces task.Periodic only where truthful generation retirement needs it.
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
	p.closed = true
	p.running = false
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

func newDNSGeneration(owner, resolver *DNS, id uint64) *dnsGeneration {
	ctx, cancel := context.WithCancel(context.Background())
	g := &dnsGeneration{id: id, owner: owner, resolver: resolver, ctx: ctx, cancel: cancel, resources: resolverResources(resolver)}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *dnsGeneration) acquireRoot() (*dnsLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return nil, &featuredns.CausalBindingError{Reason: "generation sealed"}
	}
	g.leases++
	lease := &dnsLease{generation: g}
	lease.active.Store(true)
	return lease, nil
}

func (g *dnsGeneration) acquireChild(parent *dnsLease, speculative bool) (*dnsLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if parent == nil || parent.generation != g || !parent.active.Load() || g.closed || speculative && g.sealed {
		return nil, &featuredns.CausalBindingError{Reason: "parent lease expired"}
	}
	g.leases++
	lease := &dnsLease{generation: g}
	lease.active.Store(true)
	return lease, nil
}

func (l *dnsLease) release() {
	if l == nil || !l.active.Swap(false) {
		return
	}
	g := l.generation
	g.mu.Lock()
	g.leases--
	if g.leases == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

func (g *dnsGeneration) bind(ctx context.Context, lease *dnsLease) context.Context {
	var binding *featuredns.ContextBinding
	binding = featuredns.NewContextBindingWithSpeculation(g.owner.runtime.contextOwner,
		func(callCtx context.Context, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
			return g.lookupChild(callCtx, lease, domain, option)
		},
		func(childCtx context.Context) (context.Context, func(), error) {
			child, err := g.acquireChild(lease, false)
			if err != nil {
				return nil, nil, err
			}
			queryCtx, cancel := g.queryContext(childCtx)
			return g.bind(queryCtx, child), func() { cancel(); child.release() }, nil
		},
		func(childCtx context.Context) (context.Context, func(), error) {
			child, err := g.acquireChild(lease, true)
			if err != nil {
				return nil, nil, err
			}
			queryCtx, cancel := g.queryContext(childCtx)
			return g.bind(queryCtx, child), func() { cancel(); child.release() }, nil
		},
		func() bool { return g.bindingValid(lease) },
		g.ctx,
	)
	return featuredns.ContextWithBinding(ctx, binding)
}

func (g *dnsGeneration) bindingValid(lease *dnsLease) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return lease != nil && lease.generation == g && lease.active.Load() && !g.closed
}

func (g *dnsGeneration) lookupChild(ctx context.Context, parent *dnsLease, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	lease, err := g.acquireChild(parent, false)
	if err != nil {
		return nil, 0, err
	}
	defer lease.release()
	ownerCtx, releaseOwnerCtx := owningDNSContext(g.owner.ctx, ctx)
	defer releaseOwnerCtx()
	queryCtx, cancel := g.queryContext(g.bind(ownerCtx, lease))
	defer cancel()
	return g.resolver.lookupIP(queryCtx, domain, option)
}

func (g *dnsGeneration) queryContext(ctx context.Context) (context.Context, func()) {
	queryCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.ctx, cancel)
	return queryCtx, func() { stop(); cancel() }
}

func (g *dnsGeneration) markSealed(cancel bool) {
	g.mu.Lock()
	g.sealed = true
	if cancel {
		g.closed = true
		g.cancel()
	}
	g.mu.Unlock()
}

func (g *dnsGeneration) stopSpeculation() {
	for _, client := range g.resolver.clients {
		if cached, ok := client.server.(CachedNameserver); ok {
			cached.getCacheController().Seal()
		}
	}
}

func (g *dnsGeneration) waitLeases() {
	g.mu.Lock()
	for g.leases != 0 {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

func (g *dnsGeneration) closeResources() error {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()

	g.cleanupMu.Lock()
	defer g.cleanupMu.Unlock()
	if g.cleanupDone {
		return nil
	}
	var errs []error
	allDone := true
	for _, state := range g.resources {
		if state.done {
			continue
		}
		if err := state.resource.Close(); err != nil {
			allDone = false
			errs = append(errs, fmt.Errorf("close %s: %w", state.name, err))
		} else {
			state.done = true
		}
	}
	g.cleanupDone = allDone
	return errors.Join(errs...)
}

func (s *DNS) initRuntime(dispatcher routing.Dispatcher, fake featuredns.FakeDNSEngine, resolver *DNS) {
	rt := &dnsRuntime{dispatcher: dispatcher, fake: fake, nextID: 2, closeDone: make(chan struct{}), contextOwner: featuredns.NewContextOwner()}
	rt.current = newDNSGeneration(s, resolver, 1)
	s.runtime = rt
}

func (s *DNS) acquireCurrent() (*dnsGeneration, *dnsLease, error) {
	rt := s.runtime
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return nil, nil, &featuredns.CausalBindingError{Reason: "DNS feature closed"}
	}
	g := rt.current
	lease, err := g.acquireRoot()
	return g, lease, err
}

func (s *DNS) applyConfig(ctx context.Context, config *Config) ApplyResult {
	rt := s.runtime
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return ApplyResult{Disposition: ApplyClosed, Failure: FailureCanceled}
	}
	if rt.preparing {
		rt.mu.Unlock()
		return ApplyResult{Disposition: ApplyBusy}
	}
	if rt.retiring != nil {
		rt.mu.Unlock()
		return ApplyResult{Disposition: ApplyRetiringLimit}
	}
	rt.preparing = true
	rt.prepDone = make(chan struct{})
	dispatcher, fake := rt.dispatcher, rt.fake
	rt.mu.Unlock()

	finishPreparation := func() {
		rt.mu.Lock()
		if rt.preparing {
			rt.preparing = false
			close(rt.prepDone)
			rt.prepDone = nil
		}
		rt.mu.Unlock()
	}
	clone, err := cloneAndValidateConfig(config)
	if err != nil {
		finishPreparation()
		return ApplyResult{Disposition: ApplyPrepareFailed, Failure: FailureInvalid}
	}
	if err := ctx.Err(); err != nil {
		finishPreparation()
		return ApplyResult{Disposition: ApplyCanceled, Failure: FailureCanceled}
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
		finishPreparation()
		return ApplyResult{Disposition: ApplyPrepareFailed, Failure: preparationFailureClass(err)}
	}
	if err := ctx.Err(); err != nil {
		_ = closeResolverResources(candidate)
		finishPreparation()
		return ApplyResult{Disposition: ApplyCanceled, Failure: FailureCanceled}
	}

	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		_ = closeResolverResources(candidate)
		finishPreparation()
		return ApplyResult{Disposition: ApplyClosed, Failure: FailureCanceled}
	}
	old := rt.current
	newGeneration := newDNSGeneration(s, candidate, rt.nextID)
	rt.nextID++
	rt.current = newGeneration
	rt.retiring = old
	rt.dispatcher, rt.fake = dispatcher, fake
	old.markSealed(false)
	receipt := newRetirementReceipt(old.id)
	receipt.retry = func() RetirementResult { return s.retryRetirement(old) }
	rt.retiringReceipt = receipt
	rt.retirementWork.Add(1)
	rt.mu.Unlock()
	old.stopSpeculation()

	go s.retireGeneration(old, receipt)
	finishPreparation()
	return ApplyResult{
		Disposition: ApplyApplied, Generation: newGeneration.id, PreviousGeneration: old.id, Retirement: receipt,
	}
}

func (s *DNS) retireGeneration(g *dnsGeneration, receipt *RetirementReceipt) {
	defer s.runtime.retirementWork.Done()
	g.waitLeases()
	result := s.finishRetirement(g)
	receipt.complete(result)
}

func (s *DNS) finishRetirement(g *dnsGeneration) RetirementResult {
	g.cancel()
	err := g.closeResources()
	result := RetirementResult{Generation: g.id, Terminal: err == nil, Disposition: Retired}
	if err != nil {
		result.Disposition = RetireFailed
		result.Failure = FailureCleanup
		return result
	}
	s.runtime.mu.Lock()
	if s.runtime.retiring == g {
		s.runtime.retiring = nil
		s.runtime.retiringReceipt = nil
	}
	s.runtime.mu.Unlock()
	return result
}

func (s *DNS) retryRetirement(g *dnsGeneration) RetirementResult {
	// Resource closers are idempotent. A retained failed generation remains in
	// the bounded slot until every closer reports success.
	return s.finishRetirement(g)
}

type generationResource interface{ Close() error }

func resolverResources(resolver *DNS) []*generationResourceState {
	if resolver == nil {
		return nil
	}
	seen := make(map[Server]struct{})
	var resources []*generationResourceState
	for _, client := range resolver.clients {
		if client == nil || client.server == nil {
			continue
		}
		if _, ok := seen[client.server]; ok {
			continue
		}
		seen[client.server] = struct{}{}
		if resource, ok := client.server.(generationResource); ok {
			resources = append(resources, &generationResourceState{name: client.Name(), resource: resource})
		}
	}
	return resources
}

func closeResolverResources(resolver *DNS) error {
	var errs []error
	for _, state := range resolverResources(resolver) {
		if err := state.resource.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", state.name, err))
		}
	}
	return errors.Join(errs...)
}
