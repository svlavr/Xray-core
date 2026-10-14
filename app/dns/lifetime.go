package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// DNS is the stable native feature. Resolver data never recursively embeds DNS.
type DNS struct {
	ctx         context.Context
	pub         *pubsub.Service
	mu          sync.Mutex
	active      atomic.Pointer[resolver]
	pending     *resolver
	started     bool
	closed      bool
	systemDNSMu sync.RWMutex
}

type ApplyResult struct {
	Applied bool
	Err     error
}

func needsFakeDNS(config *Config) bool {
	for _, ns := range config.NameServer {
		if strings.EqualFold(ns.Address.Address.GetDomain(), "fakedns") {
			return true
		}
	}
	return false
}

// requireReady does not register a deferred callback on the update path.
func (s *DNS) requireReady(config *Config) error {
	instance := core.FromContext(s.ctx)
	if instance == nil || instance.GetFeature(routing.DispatcherType()) == nil {
		return fmt.Errorf("missing ready DNS dependency: dispatcher")
	}
	if needsFakeDNS(config) && instance.GetFeature((*featuredns.FakeDNSEngine)(nil)) == nil {
		return fmt.Errorf("missing ready DNS dependency: FakeDNS engine")
	}
	return nil
}

// begin orders admission with retirement, including exact saved Lua references.
func (s *DNS) begin(ctx context.Context, exact *resolver) (*resolver, context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	s.mu.Lock()
	if exact == nil {
		exact, _ = ctx.Value(resolverContextKey{}).(*resolver)
		if exact == nil || exact.owner != s {
			exact = s.active.Load()
		}
	}
	if s.closed || exact == nil || exact.owner != s || exact.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nil, nil, context.Canceled
	}
	exact.queries.Add(1)
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.WithValue(ctx, resolverContextKey{}, exact))
	stop := context.AfterFunc(exact.ctx, cancel)
	if exact.ctx.Err() != nil {
		cancel()
	}
	return exact, ctx, func() { stop(); cancel(); exact.queries.Done() }, nil
}

// initialize owns the entire native factory call, including arbitrary callbacks.
func (r *resolver) initialize() <-chan error {
	result := make(chan error, 1)
	go func() {
		err := r.prepared.start(r)
		if err == nil && r.ctx.Err() == nil {
			r.script.Store(r.prepared)
		} else {
			if err == nil {
				err = r.ctx.Err()
			}
			r.prepared.close()
		}
		close(r.initialized)
		result <- err
	}()
	return result
}

// retire starts all native closes before joining any one resource.
func (r *resolver) retire() {
	r.closeOnce.Do(func() {
		go func() {
			var workers sync.WaitGroup
			errs := make([]error, len(r.clients))
			for i, client := range r.clients {
				if resource, ok := client.server.(interface{ Close() error }); ok {
					workers.Add(1)
					go func() {
						defer workers.Done()
						if err := resource.Close(); err != nil {
							errs[i] = fmt.Errorf("close %s: %w", client.Name(), err)
						}
					}()
				}
			}
			workers.Wait()
			<-r.initialized
			if script := r.script.Swap(nil); script != nil {
				script.close()
			}
			r.queries.Wait()
			r.closeErr = errors.Join(errs...)
			r.owner.mu.Lock()
			if r.owner.pending == r {
				r.owner.pending = nil
			}
			close(r.done)
			r.owner.mu.Unlock()
		}()
	})
}

func (s *DNS) Start() error {
	s.mu.Lock()
	r := s.active.Load()
	if s.closed || r == nil || r.ctx.Err() != nil {
		s.mu.Unlock()
		return context.Canceled
	}
	if s.started || r.prepared == nil {
		s.started = true
		s.mu.Unlock()
		return nil
	}
	select {
	case <-r.initialized:
	default:
		s.mu.Unlock()
		return fmt.Errorf("DNS script initialization in progress")
	}
	r.initialized = make(chan struct{})
	s.mu.Unlock()
	err := <-r.initialize()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && !s.closed && s.active.Load() == r && r.ctx.Err() == nil {
		s.started = true
		return nil
	}
	if err == nil {
		err = context.Canceled
	}
	return err
}

func (s *DNS) Close() error {
	s.mu.Lock()
	s.closed = true
	current, pending := s.active.Load(), s.pending
	for _, r := range []*resolver{current, pending} {
		if r != nil {
			r.cancel()
		}
	}
	s.mu.Unlock()
	for _, r := range []*resolver{current, pending} {
		if r != nil {
			r.retire()
		}
	}
	var errs []error
	for _, r := range []*resolver{current, pending} {
		if r != nil {
			<-r.done
			errs = append(errs, r.closeErr)
		}
	}
	s.mu.Lock()
	s.active.Store(nil)
	s.mu.Unlock()
	if s.pub != nil {
		errs = append(errs, s.pub.Close())
	}
	return errors.Join(errs...)
}

// ApplyConfig changes only this DNS feature. Script-off preparation is inert.
// Script activation can have external effects before publication. Cancellation
// before publication preserves the active resolver; after publication it only
// bounds the caller's cleanup wait. An unfinished owner prevents another update.
func ApplyConfig(ctx context.Context, client featuredns.Client, config *Config) ApplyResult {
	s, ok := client.(*DNS)
	if !ok || s == nil {
		return ApplyResult{Err: fmt.Errorf("DNS client does not support ApplyConfig")}
	}
	if config == nil || len(config.NameServer) == 0 {
		return ApplyResult{Err: fmt.Errorf("explicit DNS update requires a nameserver")}
	}
	if err := ctx.Err(); err != nil {
		return ApplyResult{Err: err}
	}
	config = proto.Clone(config).(*Config)
	if err := s.requireReady(config); err != nil {
		return ApplyResult{Err: err}
	}
	var prepared *scriptEngine
	var err error
	if config.Script != "" {
		prepared, err = newScriptEngine(config.Script)
		if err != nil {
			return ApplyResult{Err: err}
		}
	}
	r, err := s.newResolver(config, prepared)
	if err != nil {
		return ApplyResult{Err: err}
	}
	return s.applyResolver(ctx, r)
}

// applyResolver publishes a prepared value through the same activation gate.
func (s *DNS) applyResolver(ctx context.Context, r *resolver) ApplyResult {
	var err error
	r.strictSelection = true
	unsafe := resolverMayUseSystem(r)
	if unsafe && !s.systemDNSMu.TryLock() {
		r.cancel()
		return ApplyResult{Err: fmt.Errorf("system DNS takeover prevents this DNS update")}
	}
	s.mu.Lock()
	switch {
	case ctx.Err() != nil:
		err = ctx.Err()
	case s.closed || s.active.Load() == nil:
		err = context.Canceled
	case s.pending != nil:
		err = fmt.Errorf("previous DNS activation or cleanup incomplete")
	case r.prepared != nil && !s.started:
		err = fmt.Errorf("script-enabled DNS update requires completed DNS.Start")
	}
	if err == nil && r.prepared != nil {
		r.initialized = make(chan struct{})
		s.pending = r
	}
	if err != nil || r.prepared != nil {
		s.mu.Unlock()
		if unsafe {
			s.systemDNSMu.Unlock()
		}
		if err != nil {
			r.cancel()
			return ApplyResult{Err: err}
		}
		// The caller may stop waiting even if a native Go callback ignores ctx.
		stop := context.AfterFunc(ctx, func() {
			s.mu.Lock()
			if s.pending == r && s.active.Load() != r {
				r.cancel()
			}
			s.mu.Unlock()
		})
		initialized := r.initialize()
		select {
		case err = <-initialized:
		case <-ctx.Done():
			err = ctx.Err()
		}
		s.mu.Lock()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && (s.closed || r.ctx.Err() != nil || s.pending != r) {
			err = context.Canceled
		}
		stop()
		if err != nil {
			r.cancel()
			s.mu.Unlock()
			r.retire()
			select {
			case <-r.done:
				return ApplyResult{Err: errors.Join(err, r.closeErr)}
			case <-ctx.Done():
				return ApplyResult{Err: err}
			}
		}
		// Acquire checks pending until locked publication replaces the value.
		unsafe = false
	}
	old := s.active.Swap(r)
	s.pending = old
	old.cancel()
	s.mu.Unlock()
	if unsafe {
		s.systemDNSMu.Unlock()
	}
	old.retire()
	select {
	case <-old.done:
		return ApplyResult{Applied: true, Err: old.closeErr}
	case <-ctx.Done():
		return ApplyResult{Applied: true, Err: ctx.Err()}
	}
}
