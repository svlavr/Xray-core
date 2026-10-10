package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// dnsRuntime owns the published resolver and, at most, one activation or
// unfinished retirement in the same second slot.
// The feature mutex serializes publication and admission. Each resolver joins
// its admitted queries before its resource references can be forgotten.
type dnsRuntime struct {
	mu sync.Mutex
	// systemDNSMu orders unsafe resolver publication against Linux system DNS takeover.
	// Takeover holds a read lock until the OS settings are reverted.
	systemDNSMu sync.RWMutex
	current     *resolverOwner
	closing     *resolverOwner
	started     bool
}

type resolverOwner struct {
	resolver  *DNS
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
	closeDone chan struct{}
	initDone  chan struct{}
}

func newResolverOwner(resolver *DNS) *resolverOwner {
	base := context.Background()
	if resolver.ctx != nil && core.FromContext(resolver.ctx) != nil {
		base = core.ToBackgroundDetachedContext(resolver.ctx)
	}
	ctx, cancel := context.WithCancel(base)
	o := &resolverOwner{resolver: resolver, ctx: ctx, cancel: cancel, closeDone: make(chan struct{}), initDone: make(chan struct{})}
	close(o.initDone)
	return o
}

func (o *resolverOwner) closeResources() error {
	var joined sync.WaitGroup
	errs := make([]error, len(o.resolver.clients))
	for i, client := range o.resolver.clients {
		if resource, ok := client.server.(interface{ Close() error }); ok {
			joined.Add(1)
			go func() {
				defer joined.Done()
				if err := resource.Close(); err != nil {
					errs[i] = fmt.Errorf("close %s: %w", client.Name(), err)
				}
			}()
		}
	}
	joined.Wait()
	return errors.Join(errs...)
}

// closeOwned shares one terminal close and query join between retirement callers.
// The resolver is already retired and canceled under dnsRuntime.mu.
func (o *resolverOwner) closeOwned() error {
	o.startClose()
	<-o.closeDone
	return o.closeErr
}

func (o *resolverOwner) startClose() {
	o.closeOnce.Do(func() {
		go func() {
			o.closeErr = o.closeResources()
			<-o.initDone
			if engine := o.resolver.getScript(); engine != nil {
				engine.close()
			}
			o.resolver.queries.Wait()
			close(o.closeDone)
		}()
	})
}

func (s *DNS) initRuntime(resolver *DNS) {
	s.runtime = &dnsRuntime{current: newResolverOwner(resolver)}
	owner := s.runtime.current
	resolver.ctx = bindResolverContext(owner.ctx, s.runtime, owner)
}

func (s *DNS) applyConfig(ctx context.Context, config *Config) ApplyResult {
	rt := s.runtime
	clone := proto.Clone(config).(*Config)
	if clone == nil || len(clone.NameServer) == 0 {
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
	base := context.Background()
	if core.FromContext(s.ctx) != nil {
		base = core.ToBackgroundDetachedContext(s.ctx)
	}
	candidate, err := buildDNS(base, clone, dispatcher, fake)
	if err != nil {
		return ApplyResult{Err: err}
	}
	candidate.strictSelection = true
	if candidate.scriptPath != "" {
		return s.applyScript(ctx, candidate)
	}
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
	if rt.current == nil || rt.current.ctx.Err() != nil {
		rt.mu.Unlock()
		return ApplyResult{Err: context.Canceled}
	}
	if rt.closing != nil {
		rt.mu.Unlock()
		return ApplyResult{Err: fmt.Errorf("previous DNS resolver cleanup incomplete")}
	}
	old := rt.current
	rt.current = newResolverOwner(candidate)
	candidate.ctx = bindResolverContext(rt.current.ctx, rt, rt.current)
	rt.closing = old
	old.cancel()
	rt.mu.Unlock()
	if unsafeSystemDNS {
		rt.systemDNSMu.Unlock()
		unsafeSystemDNS = false
	}
	// Publication is complete. Cancellation, resource close, and query join are
	// bounded by ctx for the caller; unfinished work remains in rt.closing.
	return rt.waitRetirement(ctx, old)
}

type ApplyResult struct {
	Applied bool
	Err     error
}

// ApplyConfig prepares and publishes a fresh resolver in the existing DNS feature.
// Applied remains true when old-resource cleanup fails after publication.
// Script-enabled updates require completed DNS.Start and may execute native Lua
// initialization actions before publication. Applied=false preserves the current
// resolver, not external script effects; unfinished disposal remains owned.
// Caller cancellation before publication rejects the candidate. After publication
// it only bounds the caller's wait and does not cancel the installed resolver.
func ApplyConfig(ctx context.Context, client featuredns.Client, config *Config) ApplyResult {
	server, ok := client.(*DNS)
	if !ok || server == nil || server.runtime == nil {
		return ApplyResult{Err: fmt.Errorf("DNS client does not support ApplyConfig")}
	}
	return server.applyConfig(ctx, config)
}
