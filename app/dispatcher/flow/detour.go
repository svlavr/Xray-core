package flow

import (
	"context"
	"math"
	"sync/atomic"

	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

// DetourScope owns one exact same-root handler invocation created by
// dialerProxy. It never starts, joins, closes, or interrupts the stock
// invocation.
type DetourScope struct {
	handle      *Handle
	participant task.ParticipantLease
	link        *transport.Link
	lineage     *detourLineage
	depth       uint32
	released    atomic.Bool
}

type detourLineage struct {
	edge    atomic.Pointer[detourEdge]
	ready   atomic.Bool
	blocked bool
}

type detourEdge struct {
	tag         string
	handlerType string
	entryKind   HandlerEntryKind
	child       *detourLineage
}

func newReadyDetourLineage() *detourLineage {
	lineage := new(detourLineage)
	lineage.ready.Store(true)
	return lineage
}

// BeginDetour acquires lifecycle participation before the caller publishes its
// goroutine. It returns a masking-only scope when exact observation cannot be
// proven, so stock work still starts without inheriting stale authority.
func BeginDetour(ctx context.Context, link *transport.Link, tag, handlerType string, entryKind HandlerEntryKind) *DetourScope {
	return beginDetour(ctx, link, tag, handlerType, entryKind, nil)
}

func beginDetour(ctx context.Context, link *transport.Link, tag, handlerType string, entryKind HandlerEntryKind, afterEdgePublished func()) *DetourScope {
	scope := &DetourScope{}
	if ctx == nil {
		return scope
	}
	binding, _ := ctx.Value(linkBindingKey{}).(*linkBinding)
	if binding == nil || binding.handle == nil || binding.expected == nil || link == nil {
		if handle := HandleFromContext(ctx); handle != nil {
			handle.markContinuationFault(LifecycleFaultDetourContextMissing)
		}
		return scope
	}
	handle := binding.handle
	root := handle.root
	registry := handle.registry
	if root == nil || root.logical == nil || registry == nil || root.retired.Load() || registry.continuationsClosed.Load() {
		handle.markContinuationFault(LifecycleFaultDetourStaleRoot)
		return scope
	}
	if entryKind != HandlerEntryDialerProxy {
		handle.markContinuationFault(LifecycleFaultDetourContextMissing)
		return scope
	}
	if binding.depth == math.MaxUint32 {
		handle.markContinuationFault(LifecycleFaultDetourDepthOverflow)
		return scope
	}
	if binding.participant == nil {
		handle.markContinuationFault(LifecycleFaultDetourParticipantLost)
		return scope
	}
	participant := binding.participant.AcquireParticipant()
	if participant == nil {
		handle.markContinuationFault(LifecycleFaultDetourParticipantLost)
		return scope
	}
	if registry.continuationsClosed.Load() || root.retired.Load() {
		participant.Release(nil)
		handle.markContinuationFault(LifecycleFaultDetourStaleRoot)
		return scope
	}

	lineage := binding.detourLineage
	if lineage == nil {
		lineage = newReadyDetourLineage()
	}
	childLineage := &detourLineage{blocked: lineage.blocked}
	if !lineage.blocked && !lineage.ready.Load() {
		handle.markRouteProofPartial()
		childLineage.blocked = true
	} else if !lineage.blocked {
		tag = boundedText(tag, maxTagBytes)
		handlerType = boundedText(handlerType, maxTagBytes)
		candidate := &detourEdge{tag: tag, handlerType: handlerType, entryKind: entryKind, child: childLineage}
		edge := lineage.edge.Load()
		if edge == nil && lineage.edge.CompareAndSwap(nil, candidate) {
			edge = candidate
			if afterEdgePublished != nil {
				afterEdgePublished()
			}
			handle.RecordDialerProxy(tag, handlerType)
			childLineage.ready.Store(true)
		} else if edge == nil {
			edge = lineage.edge.Load()
		}
		if edge == nil || edge.tag != tag || edge.handlerType != handlerType || edge.entryKind != entryKind {
			handle.markContinuationFault(LifecycleFaultDetourLineageConflict)
			childLineage = &detourLineage{blocked: true}
		} else {
			childLineage = edge.child
		}
	}
	scope.handle = handle
	scope.participant = participant
	scope.link = link
	scope.lineage = childLineage
	scope.depth = binding.depth + 1
	return scope
}

// Context masks the parent invocation and publishes only this exact child link
// plus its linear participant. Cancellation and all session values come from
// the context supplied by the stock caller.
func (s *DetourScope) Context(ctx context.Context) context.Context {
	ctx = ContextWithoutFlowObservation(ctx)
	if s == nil || ctx == nil || s.handle == nil || s.participant == nil || s.link == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, handleContextKey{}, s.handle)
	ctx = task.ContextWithParticipantTracker(ctx, s.participant)
	return contextWithLinkBindingLineage(ctx, s.handle, s.link, s.depth, s.lineage)
}

func (s *DetourScope) Release(err error) {
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
