package dns

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// ResolvableContext is an implementation of routing.Context, with domain resolving capability.
type ResolvableContext struct {
	routing.Context
	dnsClient dns.Client
	cacheIPs  []net.IP
	hasError  bool
}

type originatingContext interface {
	OriginatingContext() context.Context
}

func (ctx *ResolvableContext) OriginatingContext() context.Context {
	if origin, ok := ctx.Context.(originatingContext); ok {
		return origin.OriginatingContext()
	}
	return nil
}

// GetTargetIPs overrides original routing.Context's implementation.
func (ctx *ResolvableContext) GetTargetIPs() []net.IP {
	if len(ctx.cacheIPs) > 0 {
		return ctx.cacheIPs
	}

	if ctx.hasError {
		return nil
	}

	if domain := ctx.GetTargetDomain(); len(domain) != 0 {
		lookupCtx := context.Background()
		if origin, ok := ctx.Context.(originatingContext); ok && origin.OriginatingContext() != nil {
			lookupCtx = origin.OriginatingContext()
		}
		ips, _, err := dns.LookupIPContext(lookupCtx, ctx.dnsClient, domain, dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		})
		if err == nil {
			ctx.cacheIPs = ips
			return ips
		}
		errors.LogInfoInner(context.Background(), err, "resolve ip for ", domain)
	}

	if ips := ctx.Context.GetTargetIPs(); len(ips) != 0 {
		ctx.cacheIPs = ips
		return ips
	}

	ctx.hasError = true
	return nil
}

// ContextWithDNSClient creates a new routing context with domain resolving capability.
// Resolved domain IPs can be retrieved by GetTargetIPs().
func ContextWithDNSClient(ctx routing.Context, client dns.Client) routing.Context {
	return &ResolvableContext{Context: ctx, dnsClient: client}
}
