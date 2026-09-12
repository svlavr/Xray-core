package flow

import (
	"context"
	"math"
	"sync/atomic"

	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

type (
	rootDispatchOwnerKey struct{}
	linkBindingKey       struct{}
	continuationKey      struct{}
	redispatchScopeKey   struct{}
)

type maskedFlowObservation struct{}

type linkBinding struct {
	handle        *Handle
	expected      *transport.Link
	participant   task.ParticipantTracker
	detourLineage *detourLineage
	depth         uint32
	issued        atomic.Bool
}

type continuationState struct {
	consumed atomic.Bool
}

// FlowContinuation is a single-use capability for one exact internal link.
// The shared state pointer preserves single-use semantics if the value is
// copied through an interface or context.
type FlowContinuation struct {
	state     *continuationState
	binding   *linkBinding
	entryKind HandlerEntryKind
}

// RedispatchScope owns the child participant acquired before nested dispatch.
type RedispatchScope struct {
	handle      *Handle
	participant task.ParticipantLease
	depth       uint32
	released    atomic.Bool
}

func ContextWithRootDispatchOwner(ctx context.Context, handle *Handle) context.Context {
	if ctx == nil || handle == nil {
		return ctx
	}
	return context.WithValue(ctx, rootDispatchOwnerKey{}, handle)
}

func RootDispatchOwnerFromContext(ctx context.Context) *Handle {
	if ctx == nil {
		return nil
	}
	handle, _ := ctx.Value(rootDispatchOwnerKey{}).(*Handle)
	return handle
}

// ContextWithoutFlowObservation masks inherited flow capabilities without
// replacing the caller's context or destroying cancellation/session values.
func ContextWithoutFlowObservation(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	masked := maskedFlowObservation{}
	ctx = context.WithValue(ctx, rootDispatchOwnerKey{}, masked)
	ctx = context.WithValue(ctx, linkBindingKey{}, masked)
	ctx = context.WithValue(ctx, continuationKey{}, masked)
	ctx = context.WithValue(ctx, redispatchScopeKey{}, masked)
	ctx = context.WithValue(ctx, handleContextKey{}, masked)
	ctx = contextWithoutExternalOwnerScope(ctx)
	return task.ContextWithoutParticipantTracker(ctx)
}

// ContextWithoutUnprovenRedispatch records that an internal DispatchLink call
// inherited flow identity without the exact typed continuation, then masks it.
func ContextWithoutUnprovenRedispatch(ctx context.Context) context.Context {
	if handle := HandleFromContext(ctx); handle != nil {
		handle.markContinuationFault(LifecycleFaultContinuationMissing)
	}
	return ContextWithoutFlowObservation(ctx)
}

// HasFlowObservation reports whether flow identity or ownership is inherited.
// It is used only to fail observation closed at public dispatch boundaries.
func HasFlowObservation(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if HandleFromContext(ctx) != nil || RootDispatchOwnerFromContext(ctx) != nil || RedispatchScopeFromContext(ctx) != nil {
		return true
	}
	binding, _ := ctx.Value(linkBindingKey{}).(*linkBinding)
	return binding != nil
}

// ContextWithLinkBinding publishes the exact current handler invocation link.
// It adds observation identity only and never modifies the link.
func ContextWithLinkBinding(ctx context.Context, handle *Handle, link *transport.Link, depth uint32) context.Context {
	return contextWithLinkBindingLineage(ctx, handle, link, depth, newReadyDetourLineage())
}

func contextWithLinkBindingLineage(ctx context.Context, handle *Handle, link *transport.Link, depth uint32, lineage *detourLineage) context.Context {
	if ctx == nil || handle == nil || link == nil {
		return ctx
	}
	if lineage == nil {
		lineage = newReadyDetourLineage()
	}
	binding := &linkBinding{
		handle:        handle,
		expected:      link,
		participant:   task.ParticipantTrackerFromContext(ctx),
		detourLineage: lineage,
		depth:         depth,
	}
	return context.WithValue(ctx, linkBindingKey{}, binding)
}

// ContextWithLoopbackContinuation derives one typed internal capability from
// the exact link binding. A missing binding is retained as an invalid internal
// attempt so DispatchLink cannot fall back to marker-only root reuse.
func ContextWithLoopbackContinuation(ctx context.Context, link *transport.Link) context.Context {
	if ctx == nil {
		return ctx
	}
	binding, _ := ctx.Value(linkBindingKey{}).(*linkBinding)
	continuation := &FlowContinuation{
		state:     &continuationState{},
		binding:   binding,
		entryKind: HandlerEntryLoopbackRedispatch,
	}
	if binding == nil || binding.expected != link {
		if handle := HandleFromContext(ctx); handle != nil {
			handle.markContinuationFault(LifecycleFaultContinuationForeignLink)
		}
	} else if !binding.issued.CompareAndSwap(false, true) {
		continuation.state.consumed.Store(true)
		binding.handle.markContinuationFault(LifecycleFaultContinuationReplay)
	}
	return context.WithValue(ctx, continuationKey{}, continuation)
}

// ConsumeLoopbackContinuation consumes at most one typed internal attempt.
// internal is true whenever loopback supplied a capability, even if proof is
// invalid; callers must continue stock traffic without root inheritance then.
func ConsumeLoopbackContinuation(ctx context.Context, actual *transport.Link) (scope *RedispatchScope, internal bool) {
	if ctx == nil {
		return nil, false
	}
	continuation, _ := ctx.Value(continuationKey{}).(*FlowContinuation)
	if continuation == nil {
		return nil, false
	}
	if continuation.state == nil || !continuation.state.consumed.CompareAndSwap(false, true) {
		if continuation.binding != nil && continuation.binding.handle != nil {
			continuation.binding.handle.markContinuationFault(LifecycleFaultContinuationReplay)
		}
		return nil, true
	}
	binding := continuation.binding
	if binding == nil || binding.handle == nil || binding.expected != actual ||
		continuation.entryKind != HandlerEntryLoopbackRedispatch {
		if binding != nil && binding.handle != nil {
			binding.handle.markContinuationFault(LifecycleFaultContinuationForeignLink)
		}
		return nil, true
	}
	root := binding.handle.root
	registry := binding.handle.registry
	if root == nil || root.logical == nil || registry == nil || root.retired.Load() || registry.continuationsClosed.Load() {
		binding.handle.markContinuationFault(LifecycleFaultContinuationStaleRoot)
		return nil, true
	}
	if binding.participant == nil {
		binding.handle.markContinuationFault(LifecycleFaultContinuationParticipantLost)
		return nil, true
	}
	participant := binding.participant.AcquireParticipant()
	if participant == nil {
		binding.handle.markContinuationFault(LifecycleFaultContinuationParticipantLost)
		return nil, true
	}
	if registry.continuationsClosed.Load() || root.retired.Load() {
		participant.Release(nil)
		binding.handle.markContinuationFault(LifecycleFaultContinuationStaleRoot)
		return nil, true
	}
	if binding.depth == math.MaxUint32 {
		participant.Release(nil)
		binding.handle.markContinuationFault(LifecycleFaultContinuationDepthOverflow)
		return nil, true
	}
	return &RedispatchScope{handle: binding.handle, participant: participant, depth: binding.depth + 1}, true
}

func (s *RedispatchScope) Context(ctx context.Context) context.Context {
	if s == nil || ctx == nil || s.handle == nil || s.participant == nil {
		return ctx
	}
	ctx = ContextWithoutFlowObservation(ctx)
	ctx = context.WithValue(ctx, handleContextKey{}, s.handle)
	ctx = task.ContextWithParticipantTracker(ctx, s.participant)
	return context.WithValue(ctx, redispatchScopeKey{}, s)
}

func RedispatchScopeFromContext(ctx context.Context) *RedispatchScope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(redispatchScopeKey{}).(*RedispatchScope)
	return scope
}

func (s *RedispatchScope) Handle() *Handle {
	if s == nil {
		return nil
	}
	return s.handle
}

func (s *RedispatchScope) Depth() uint32 {
	if s == nil {
		return 0
	}
	return s.depth
}

func (s *RedispatchScope) Release(err error) {
	if s == nil || s.participant == nil {
		return
	}
	if !s.released.CompareAndSwap(false, true) {
		if s.handle != nil && s.handle.root != nil && s.handle.root.logical != nil {
			s.handle.root.logical.markLifecycleFault(LifecycleFaultDoubleParticipantRelease)
		}
		return
	}
	s.participant.Release(err)
}

func (h *Handle) markContinuationFault(fault LifecycleFault) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	h.root.logical.markLifecycleFault(fault)
}
