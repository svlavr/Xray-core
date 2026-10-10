package dns

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
)

type resolverContextKey struct{}

type resolverBinding struct {
	runtime *dnsRuntime
	owner   *resolverOwner
}

func bindResolverContext(ctx context.Context, rt *dnsRuntime, owner *resolverOwner) context.Context {
	return context.WithValue(ctx, resolverContextKey{}, resolverBinding{rt, owner})
}

func resolverFromContext(ctx context.Context, rt *dnsRuntime) *resolverOwner {
	if binding, ok := ctx.Value(resolverContextKey{}).(resolverBinding); ok && binding.runtime == rt {
		return binding.owner
	}
	return nil
}

// WithLuaDNS admits one router Lua operation against the exact resolver used
// by its factory and saved server callbacks. Generic/native local clients keep
// their existing registration and query semantics and have no owner identity.
func WithLuaDNS(ctx context.Context, client featuredns.Client, work func(context.Context, any) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := client.(*DNS)
	if !ok || s == nil || s.runtime == nil {
		return work(ctx, nil)
	}
	rt := s.runtime
	rt.mu.Lock()
	owner := resolverFromContext(ctx, rt)
	if owner == nil {
		owner = rt.current
	}
	if owner == nil || owner.ctx.Err() != nil {
		rt.mu.Unlock()
		return context.Canceled
	}
	owner.resolver.queries.Add(1)
	rt.mu.Unlock()
	defer owner.resolver.queries.Done()
	ctx, cancel := context.WithCancel(bindResolverContext(ctx, rt, owner))
	stop := context.AfterFunc(owner.ctx, cancel)
	defer stop()
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return work(ctx, owner)
}

// boundLuaClient keeps general Query on the same owner as the saved Servers.
type boundLuaClient struct {
	featuredns.Client
	server  *DNS
	binding resolverBinding
}

func (c *boundLuaClient) LookupIP(domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	return c.LookupIPContext(c.binding.owner.ctx, domain, option)
}

func (c *boundLuaClient) LookupIPContext(ctx context.Context, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	return c.server.LookupIPContext(bindResolverContext(ctx, c.binding.runtime, c.binding.owner), domain, option)
}

func queryLuaServer(ctx context.Context, binding resolverBinding, client *Client, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	rt, owner := binding.runtime, binding.owner
	rt.mu.Lock()
	if owner.ctx.Err() != nil {
		rt.mu.Unlock()
		return nil, 0, context.Canceled
	}
	owner.resolver.queries.Add(1)
	rt.mu.Unlock()
	defer owner.resolver.queries.Done()
	ctx, cancel := context.WithCancel(bindResolverContext(ctx, rt, owner))
	stop := context.AfterFunc(owner.ctx, cancel)
	defer stop()
	defer cancel()
	return client.QueryIP(ctx, domain, option)
}
