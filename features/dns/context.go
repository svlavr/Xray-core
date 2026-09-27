package dns

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/net"
)

// ContextClient is an optional DNS lookup entry that preserves caller
// cancellation. The Client interface remains available to existing callers.
type ContextClient interface {
	LookupIPContext(context.Context, string, IPOption) ([]net.IP, uint32, error)
}

// ContextOwner identifies a DNS feature's own routed traffic for loop
// prevention. It does not select a resolver or extend a query lifetime.
type ContextOwner struct{ identity *struct{} }

func NewContextOwner() *ContextOwner { return &ContextOwner{identity: &struct{}{}} }

type contextOwnerKey struct{}

func ContextWithOwner(ctx context.Context, owner *ContextOwner) context.Context {
	if owner == nil {
		return ctx
	}
	return context.WithValue(ctx, contextOwnerKey{}, owner)
}

func CopyContextOwner(dst, src context.Context) context.Context {
	if owner, _ := src.Value(contextOwnerKey{}).(*ContextOwner); owner != nil {
		return ContextWithOwner(dst, owner)
	}
	return dst
}

func ContextOwnedBy(ctx context.Context, owner *ContextOwner) bool {
	bound, _ := ctx.Value(contextOwnerKey{}).(*ContextOwner)
	return owner != nil && bound == owner
}

func LookupIPContext(ctx context.Context, client Client, domain string, option IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if contextClient, ok := client.(ContextClient); ok {
		return contextClient.LookupIPContext(ctx, domain, option)
	}
	if client == nil {
		return nil, 0, errors.New("DNS client not initialized")
	}
	return client.LookupIP(domain, option)
}
