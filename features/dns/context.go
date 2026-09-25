package dns

import (
	"context"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/common/net"
)

// ContextClient is the optional context-aware DNS client surface. Client stays
// stable for callers which intentionally start a new, unbound lookup.
type ContextClient interface {
	LookupIPContext(context.Context, string, IPOption) ([]net.IP, uint32, error)
}

// CausalBindingError reports a present binding that can no longer admit causal
// work. Callers must not fall back to a newer resolver generation.
type CausalBindingError struct {
	Reason string
}

func (e *CausalBindingError) Error() string {
	if e == nil || e.Reason == "" {
		return "invalid DNS causal binding"
	}
	return fmt.Sprintf("invalid DNS causal binding: %s", e.Reason)
}

// ContextBinding is opaque outside this package. A DNS implementation supplies
// the callbacks; consumers can only carry, reserve, and use the capability.
type ContextBinding struct {
	owner              *ContextOwner
	lookup             func(context.Context, string, IPOption) ([]net.IP, uint32, error)
	reserve            func(context.Context) (context.Context, func(), error)
	reserveSpeculative func(context.Context) (context.Context, func(), error)
	valid              func() bool
	lifetime           context.Context
}

// ContextOwner is an opaque identity. Only the DNS feature retaining the
// returned pointer can recognize bindings made with it.
type ContextOwner struct{ identity *struct{} }

func NewContextOwner() *ContextOwner { return &ContextOwner{identity: &struct{}{}} }

// NewContextBinding creates an opaque binding for a DNS implementation.
func NewContextBinding(
	owner *ContextOwner,
	lookup func(context.Context, string, IPOption) ([]net.IP, uint32, error),
	reserve func(context.Context) (context.Context, func(), error),
	valid func() bool,
) *ContextBinding {
	return &ContextBinding{owner: owner, lookup: lookup, reserve: reserve, reserveSpeculative: reserve, valid: valid}
}

// NewContextBindingWithSpeculation additionally distinguishes work which must
// not start after its generation is sealed.
func NewContextBindingWithSpeculation(
	owner *ContextOwner,
	lookup func(context.Context, string, IPOption) ([]net.IP, uint32, error),
	reserve func(context.Context) (context.Context, func(), error),
	reserveSpeculative func(context.Context) (context.Context, func(), error),
	valid func() bool,
	lifetime context.Context,
) *ContextBinding {
	return &ContextBinding{owner: owner, lookup: lookup, reserve: reserve, reserveSpeculative: reserveSpeculative, valid: valid, lifetime: lifetime}
}

type contextBindingKey struct{}

// ContextWithBinding carries a resolver capability without exposing its token.
func ContextWithBinding(ctx context.Context, binding *ContextBinding) context.Context {
	if binding == nil {
		return ctx
	}
	return context.WithValue(ctx, contextBindingKey{}, binding)
}

// CopyContextBinding copies a binding across an intentional context detach.
func CopyContextBinding(dst, src context.Context) context.Context {
	if binding, _ := src.Value(contextBindingKey{}).(*ContextBinding); binding != nil {
		if binding.lifetime != nil && dst.Done() == nil {
			dst = &bindingLifetimeContext{Context: dst, lifetime: binding.lifetime}
		}
		return ContextWithBinding(dst, binding)
	}
	return dst
}

type bindingLifetimeContext struct {
	context.Context
	lifetime context.Context
}

func (ctx *bindingLifetimeContext) Done() <-chan struct{} { return ctx.lifetime.Done() }
func (ctx *bindingLifetimeContext) Err() error {
	if err := ctx.lifetime.Err(); err != nil {
		return err
	}
	return ctx.Context.Err()
}

// ReserveSpeculativeContextBinding atomically rejects speculative work after
// generation sealing. An absent binding remains an explicit external root.
func ReserveSpeculativeContextBinding(ctx context.Context) (context.Context, func(), error) {
	binding, _ := ctx.Value(contextBindingKey{}).(*ContextBinding)
	if binding == nil {
		return ctx, func() {}, nil
	}
	if binding.valid == nil || !binding.valid() || binding.reserveSpeculative == nil {
		return nil, nil, &CausalBindingError{Reason: "expired, sealed, or closed"}
	}
	return binding.reserveSpeculative(ctx)
}

// HasContextBinding reports whether a binding is present, including an invalid
// one. Presence is significant because invalid bindings fail closed.
func HasContextBinding(ctx context.Context) bool {
	binding, _ := ctx.Value(contextBindingKey{}).(*ContextBinding)
	return binding != nil
}

// ContextBindingOwnedBy recognizes a live private capability by owner identity.
func ContextBindingOwnedBy(ctx context.Context, owner *ContextOwner) bool {
	binding, _ := ctx.Value(contextBindingKey{}).(*ContextBinding)
	return binding != nil && owner != nil && binding.owner == owner && binding.valid != nil && binding.valid()
}

// ReserveContextBinding reserves causal work before a goroutine or pending
// callback is launched. An absent binding needs no reservation.
func ReserveContextBinding(ctx context.Context) (context.Context, func(), error) {
	binding, _ := ctx.Value(contextBindingKey{}).(*ContextBinding)
	if binding == nil {
		return ctx, func() {}, nil
	}
	if binding.valid == nil || !binding.valid() || binding.reserve == nil {
		return nil, nil, &CausalBindingError{Reason: "expired or closed"}
	}
	return binding.reserve(ctx)
}

// LookupIPContext resolves through a present binding first. It never falls back
// from an invalid binding to the supplied client or process-global resolver.
func LookupIPContext(ctx context.Context, client Client, domain string, option IPOption) ([]net.IP, uint32, error) {
	binding, _ := ctx.Value(contextBindingKey{}).(*ContextBinding)
	if binding != nil {
		if binding.valid == nil || !binding.valid() || binding.lookup == nil {
			return nil, 0, &CausalBindingError{Reason: "expired or closed"}
		}
		return binding.lookup(ctx, domain, option)
	}
	if contextClient, ok := client.(ContextClient); ok {
		return contextClient.LookupIPContext(ctx, domain, option)
	}
	if client == nil {
		return nil, 0, errors.New("DNS client not initialized")
	}
	return client.LookupIP(domain, option)
}
