package flow

import (
	"context"
	"sync/atomic"

	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

// AsyncLinkScope owns one route-neutral child link used by asynchronous work
// inside the current handler. It adds neither a root nor a handler hop.
type AsyncLinkScope struct {
	handle      *Handle
	participant task.ParticipantLease
	link        *transport.Link
	lineage     *detourLineage
	depth       uint32
	valid       bool
	released    atomic.Bool
}

// BeginAsyncLink acquires before the caller publishes asynchronous work. A
// missing exact parent binding fails observation closed but never suppresses
// the stock goroutine.
func BeginAsyncLink(ctx context.Context, link *transport.Link) *AsyncLinkScope {
	scope := &AsyncLinkScope{}
	if ctx == nil || link == nil {
		return scope
	}
	binding, _ := ctx.Value(linkBindingKey{}).(*linkBinding)
	if binding == nil || binding.handle == nil || binding.expected == nil || HandleFromContext(ctx) != binding.handle {
		handle := HandleFromContext(ctx)
		if tracker := task.ParticipantTrackerFromContext(ctx); tracker != nil {
			scope.participant = tracker.AcquireParticipant()
		}
		if handle != nil {
			handle.markContinuationFault(LifecycleFaultAsyncLinkContextMissing)
			scope.handle = handle
		}
		return scope
	}
	handle := binding.handle
	root := handle.root
	registry := handle.registry
	if root == nil || root.logical == nil || registry == nil || root.retired.Load() || registry.continuationsClosed.Load() {
		handle.markContinuationFault(LifecycleFaultAsyncLinkStaleRoot)
		return scope
	}
	if binding.participant == nil {
		handle.markContinuationFault(LifecycleFaultAsyncLinkParticipantLost)
		return scope
	}
	participant := binding.participant.AcquireParticipant()
	if participant == nil {
		handle.markContinuationFault(LifecycleFaultAsyncLinkParticipantLost)
		return scope
	}
	if registry.continuationsClosed.Load() || root.retired.Load() {
		participant.Release(nil)
		handle.markContinuationFault(LifecycleFaultAsyncLinkStaleRoot)
		return scope
	}
	scope.handle = handle
	scope.participant = participant
	scope.link = link
	scope.lineage = binding.detourLineage
	scope.depth = binding.depth
	scope.valid = true
	return scope
}

// Context keeps caller cancellation/session values, replaces the parent flow
// authority with the exact child link and makes the child lease the tracker
// for any work it spawns.
func (s *AsyncLinkScope) Context(ctx context.Context) context.Context {
	if s == nil || ctx == nil {
		return ctx
	}
	if !s.valid || s.handle == nil || s.participant == nil || s.link == nil {
		if HasFlowObservation(ctx) {
			ctx = ContextWithoutFlowObservation(ctx)
		}
		if s.participant != nil {
			ctx = task.ContextWithParticipantTracker(ctx, s.participant)
		}
		return ctx
	}
	ctx = ContextWithoutFlowObservation(ctx)
	ctx = context.WithValue(ctx, handleContextKey{}, s.handle)
	ctx = task.ContextWithParticipantTracker(ctx, s.participant)
	return contextWithLinkBindingLineage(ctx, s.handle, s.link, s.depth, s.lineage)
}

func (s *AsyncLinkScope) Release(err error) {
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
