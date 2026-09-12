package flow

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/task"
)

func TestAsyncLinkScopeBindsExactChildWithoutRouteHop(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	parent := continuationTestLink()
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithRootDispatchOwner(ctx, handle)
	ctx = ContextWithLinkBinding(ctx, handle, parent, 3)
	parentBinding, _ := ctx.Value(linkBindingKey{}).(*linkBinding)
	child := continuationTestLink()
	scope := BeginAsyncLink(ctx, child)
	childCtx := scope.Context(ctx)
	childBinding, _ := childCtx.Value(linkBindingKey{}).(*linkBinding)
	if childBinding == nil || childBinding.expected != child || childBinding.handle != handle || childBinding.depth != 3 || childBinding.detourLineage != parentBinding.detourLineage {
		t.Fatalf("async scope did not bind exact route-neutral child: %+v", childBinding)
	}
	if RootDispatchOwnerFromContext(childCtx) != nil || ExternalOwnerScopeFromContext(childCtx) != nil || HandleFromContext(childCtx) != handle {
		t.Fatal("async child inherited owner authority or lost root identity")
	}
	nested := task.AcquireParticipant(childCtx)
	if nested == nil || handle.LogicalRoot().View().LiveParticipantCount != 3 {
		t.Fatalf("async child did not propagate its linear participant: %+v", handle.LogicalRoot().View())
	}
	nested.Release(nil)
	terminalize(handle)
	if view := handle.LogicalRoot().View(); view.Phase == LifecyclePhaseTerminal || view.LiveParticipantCount != 1 {
		t.Fatalf("root terminalized before async work returned: %+v", view)
	}
	scope.Release(nil)
	if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseTerminal {
		t.Fatalf("async work release did not complete lifecycle: %+v", view)
	}
	if chain := registry.Snapshot().Records[0].Route.KnownHandlerChain; len(chain) != 0 {
		t.Fatalf("route-neutral async scope fabricated handler hops: %+v", chain)
	}
}

func TestAsyncLinkScopePreservesLineageForRealChildDetour(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	async := BeginAsyncLink(ctx, continuationTestLink())
	detour := BeginDetour(async.Context(ctx), continuationTestLink(), "next", "type", HandlerEntryDialerProxy)
	detour.Release(nil)
	async.Release(nil)
	chain := registry.Snapshot().Records[0].Route.KnownHandlerChain
	if len(chain) != 1 || chain[0].HandlerTag != "next" || chain[0].EntryKind != HandlerEntryDialerProxy {
		t.Fatalf("async child lost or fabricated route lineage: %+v", chain)
	}
}

func TestAsyncLinkMissingBindingMasksFlowButKeepsReservedLifetime(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithRootDispatchOwner(ContextWithHandle(context.Background(), handle), handle)
	scope := BeginAsyncLink(ctx, continuationTestLink())
	childCtx := scope.Context(ctx)
	if HasFlowObservation(childCtx) || handle.LogicalRoot().View().LifecycleFault != LifecycleFaultAsyncLinkContextMissing {
		t.Fatalf("unproven async link retained flow authority or lacked typed fault: %+v", handle.LogicalRoot().View())
	}
	nested := task.AcquireParticipant(childCtx)
	if nested == nil || handle.LogicalRoot().View().LiveParticipantCount != 3 {
		t.Fatalf("masked async link lost reserved lifecycle propagation: %+v", handle.LogicalRoot().View())
	}
	nested.Release(nil)
	scope.Release(nil)
}

func TestAsyncLinkWithForeignTrackerPreservesContextAndLinearChildren(t *testing.T) {
	type valueKey struct{}
	tracker := newAsyncTestTracker()
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), valueKey{}, "kept"))
	ctx := task.ContextWithParticipantTracker(parent, tracker)
	scope := BeginAsyncLink(ctx, continuationTestLink())
	childCtx := scope.Context(ctx)
	if childCtx.Value(valueKey{}) != "kept" || tracker.acquired.Load() != 1 {
		t.Fatal("async scope changed non-flow context or failed acquire-before-spawn")
	}
	nested := task.AcquireParticipant(childCtx)
	if nested == nil || tracker.acquired.Load() != 2 {
		t.Fatal("foreign participant tracker was not made linear through child lease")
	}
	nested.Release(nil)
	scope.Release(nil)
	if tracker.released.Load() != 2 {
		t.Fatalf("got %d releases, want 2", tracker.released.Load())
	}
	cancel()
	if childCtx.Err() != context.Canceled {
		t.Fatalf("async child lost cancellation: %v", childCtx.Err())
	}
}

func TestAsyncLinkAfterRegistryCloseMasksStaleAuthority(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	registry.Close()
	scope := BeginAsyncLink(ctx, continuationTestLink())
	if HasFlowObservation(scope.Context(ctx)) || handle.LogicalRoot().View().LifecycleFault != LifecycleFaultAsyncLinkStaleRoot {
		t.Fatalf("stale async link retained authority or lacked typed fault: %+v", handle.LogicalRoot().View())
	}
}

func TestAsyncLinkConcurrentDoubleReleaseIsTyped(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	scope := BeginAsyncLink(ctx, continuationTestLink())
	start := make(chan struct{})
	done := make(chan struct{}, 2)
	for release := 0; release < 2; release++ {
		go func() {
			<-start
			scope.Release(nil)
			done <- struct{}{}
		}()
	}
	close(start)
	<-done
	<-done
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultDoubleParticipantRelease {
		t.Fatalf("concurrent async double release was not typed: %s", fault)
	}
}

type asyncTestTracker struct {
	acquired atomic.Int32
	released atomic.Int32
}

type asyncTestLease struct{ tracker *asyncTestTracker }

func newAsyncTestTracker() *asyncTestTracker { return new(asyncTestTracker) }

func (t *asyncTestTracker) AcquireParticipant() task.ParticipantLease {
	t.acquired.Add(1)
	return &asyncTestLease{tracker: t}
}

func (l *asyncTestLease) AcquireParticipant() task.ParticipantLease {
	return l.tracker.AcquireParticipant()
}

func (l *asyncTestLease) Release(error) { l.tracker.released.Add(1) }
