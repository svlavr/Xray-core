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

// dnsRuntime owns the published resolver and, at most, one unfinished close.
// The feature mutex serializes publication and admission. Each resolver joins
// its admitted queries before its resource references can be forgotten.
type dnsRuntime struct {
	mu sync.Mutex
	// systemDNSMu orders unsafe resolver publication against Linux system DNS takeover.
	// Takeover holds a read lock until the OS settings are reverted.
	systemDNSMu sync.RWMutex
	current     *resolverOwner
	closing     *resolverOwner
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

func (s *DNS) initRuntime(resolver *DNS) {
	s.runtime = &dnsRuntime{current: newResolverOwner(resolver)}
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

type ApplyResult struct {
	Applied bool
	Err     error
}

// ApplyConfig prepares and publishes a fresh resolver in the existing DNS feature.
// Applied remains true when old-resource cleanup fails after publication.
func ApplyConfig(ctx context.Context, client featuredns.Client, config *Config) ApplyResult {
	server, ok := client.(*DNS)
	if !ok || server == nil || server.runtime == nil {
		return ApplyResult{Err: fmt.Errorf("DNS client does not support ApplyConfig")}
	}
	return server.applyConfig(ctx, config)
}
