package flow

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

func TestLoopbackContinuationRequiresExactLinkAndIsSingleUse(t *testing.T) {
	registry := newTestRegistry(t, 3, 3, 64)

	t.Run("exact", func(t *testing.T) {
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		ctx := ContextWithHandle(context.Background(), handle)
		link := continuationTestLink()
		ctx = ContextWithLinkBinding(ctx, handle, link, 0)
		ctx = ContextWithLoopbackContinuation(ctx, link)

		scope, internal := ConsumeLoopbackContinuation(ctx, link)
		if !internal || scope == nil || scope.Handle() != handle || scope.Depth() != 1 {
			t.Fatalf("exact continuation was not accepted: internal=%v scope=%+v", internal, scope)
		}
		if got := handle.LogicalRoot().View().LiveParticipantCount; got != 2 {
			t.Fatalf("child was not acquired before redispatch: got %d participants", got)
		}
		scope.Release(nil)
		if got := handle.LogicalRoot().View().LiveParticipantCount; got != 1 {
			t.Fatalf("child was not released after redispatch: got %d participants", got)
		}
	})

	t.Run("replay", func(t *testing.T) {
		handle := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
		ctx := ContextWithHandle(context.Background(), handle)
		link := continuationTestLink()
		ctx = ContextWithLinkBinding(ctx, handle, link, 0)
		ctx = ContextWithLoopbackContinuation(ctx, link)
		scope, _ := ConsumeLoopbackContinuation(ctx, link)
		if scope == nil {
			t.Fatal("first continuation consumption failed")
		}
		if replay, internal := ConsumeLoopbackContinuation(ctx, link); !internal || replay != nil {
			t.Fatalf("replayed continuation was accepted: internal=%v scope=%+v", internal, replay)
		}
		if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultContinuationReplay {
			t.Fatalf("replay fault not retained: %q", fault)
		}
		scope.Release(nil)
	})

	t.Run("foreign", func(t *testing.T) {
		handle := registry.AdmitTCP(context.Background(), "", "tcp:c:1", "", ByteScopeLogicalLinkAccepted)
		ctx := ContextWithHandle(context.Background(), handle)
		expected := continuationTestLink()
		foreign := continuationTestLink()
		ctx = ContextWithLinkBinding(ctx, handle, expected, 0)
		ctx = ContextWithLoopbackContinuation(ctx, foreign)
		if scope, internal := ConsumeLoopbackContinuation(ctx, foreign); !internal || scope != nil {
			t.Fatalf("foreign link was accepted: internal=%v scope=%+v", internal, scope)
		}
		if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultContinuationForeignLink {
			t.Fatalf("foreign-link fault not retained: %q", fault)
		}
	})
}

func TestLinkBindingIssuesOnlyOneContinuationConcurrently(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 128)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	link := continuationTestLink()
	ctx = ContextWithLinkBinding(ctx, handle, link, 0)
	const workers = 64
	var accepted atomic.Int32
	var waitGroup sync.WaitGroup
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			attempt := ContextWithLoopbackContinuation(ctx, link)
			if scope, _ := ConsumeLoopbackContinuation(attempt, link); scope != nil {
				accepted.Add(1)
				scope.Release(nil)
			}
		}()
	}
	waitGroup.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("one binding issued %d usable continuations, want 1", got)
	}
}

func TestRedispatchChildPreventsPrematureTerminal(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "loopback")
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithRootDispatchOwner(ctx, handle)
	link := continuationTestLink()
	ctx = ContextWithLinkBinding(ctx, handle, link, 0)
	ctx = ContextWithLoopbackContinuation(ctx, link)
	scope, _ := ConsumeLoopbackContinuation(ctx, link)
	if scope == nil {
		t.Fatal("continuation was not accepted")
	}
	childCtx := scope.Context(ctx)
	if RootDispatchOwnerFromContext(childCtx) != nil || RedispatchScopeFromContext(childCtx) != scope || HandleFromContext(childCtx) != handle {
		t.Fatal("child context did not mask owner authority or retain exact scope")
	}

	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	if got := registry.Snapshot().Records[0]; got.CompletionState == CompletionTerminal || got.IndeterminateReason != IndeterminateHandlerReturnedUnproven {
		t.Fatalf("owner return terminalized a live redispatch child: %+v", got)
	}
	scope.Release(nil)
	if got := registry.Snapshot().Records[0]; got.CompletionState != CompletionTerminal {
		t.Fatalf("released child did not permit terminal: %+v", got)
	}
}

func TestContinuationCannotReviveRetiredRoot(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "loopback")
	ctx := ContextWithHandle(context.Background(), handle)
	link := continuationTestLink()
	ctx = ContextWithLinkBinding(ctx, handle, link, 0)
	ctx = ContextWithLoopbackContinuation(ctx, link)
	terminalize(handle)
	if got := registry.Snapshot().Records[0].CompletionState; got != CompletionTerminal {
		t.Fatalf("test root did not retire: %s", got)
	}
	if scope, internal := ConsumeLoopbackContinuation(ctx, link); !internal || scope != nil {
		t.Fatalf("retired root was revived: internal=%v scope=%+v", internal, scope)
	}
}

func TestContinuationCannotStartAfterRegistryClose(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	link := continuationTestLink()
	ctx = ContextWithLinkBinding(ctx, handle, link, 0)
	ctx = ContextWithLoopbackContinuation(ctx, link)
	registry.Close()
	if scope, internal := ConsumeLoopbackContinuation(ctx, link); !internal || scope != nil {
		t.Fatalf("post-close continuation was accepted: internal=%v scope=%+v", internal, scope)
	}
}

func TestContinuationConsumeRacesRegistryCloseWithoutLeakingChild(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		registry, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 16})
		if err != nil {
			t.Fatal(err)
		}
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		ctx := ContextWithHandle(context.Background(), handle)
		link := continuationTestLink()
		ctx = ContextWithLinkBinding(ctx, handle, link, 0)
		ctx = ContextWithLoopbackContinuation(ctx, link)
		start := make(chan struct{})
		var scope *RedispatchScope
		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-start
			scope, _ = ConsumeLoopbackContinuation(ctx, link)
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			registry.Close()
		}()
		close(start)
		waitGroup.Wait()
		if scope != nil {
			scope.Release(nil)
		}
		if got := handle.LogicalRoot().View().LiveParticipantCount; got != 1 {
			t.Fatalf("iteration %d leaked redispatch child across close: %d", iteration, got)
		}
	}
}

func TestRedispatchScopeDoubleReleaseIsStickyFault(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	link := continuationTestLink()
	ctx = ContextWithLinkBinding(ctx, handle, link, 0)
	ctx = ContextWithLoopbackContinuation(ctx, link)
	scope, _ := ConsumeLoopbackContinuation(ctx, link)
	if scope == nil {
		t.Fatal("continuation was not accepted")
	}
	scope.Release(nil)
	scope.Release(nil)
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultDoubleParticipantRelease {
		t.Fatalf("double scope release was not retained: %q", fault)
	}
}

func TestObservationMaskPreservesParentContext(t *testing.T) {
	type valueKey struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), valueKey{}, "kept"))
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(parent, "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithRootDispatchOwner(ContextWithHandle(parent, handle), handle)
	masked := ContextWithoutFlowObservation(ctx)

	if masked.Value(valueKey{}) != "kept" || HandleFromContext(masked) != nil || RootDispatchOwnerFromContext(masked) != nil || task.AcquireParticipant(masked) != nil {
		t.Fatal("flow mask destroyed parent state or retained flow authority")
	}
	cancel()
	if masked.Err() != context.Canceled {
		t.Fatalf("flow mask lost cancellation: %v", masked.Err())
	}
}

func TestMissingContinuationIsTypedAndMasksInheritedAuthority(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithRootDispatchOwner(ContextWithHandle(context.Background(), handle), handle)
	masked := ContextWithoutUnprovenRedispatch(ctx)
	if HandleFromContext(masked) != nil || RootDispatchOwnerFromContext(masked) != nil {
		t.Fatal("unproven redispatch retained inherited flow authority")
	}
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultContinuationMissing {
		t.Fatalf("missing continuation was not typed: %q", fault)
	}
}

func TestHopPublicationNeverWaitsForRegistryMutex(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "root")
	registry.mu.Lock()
	done := make(chan struct{})
	go func() {
		handle.BeginRedispatch("final", "type", "rule", true, CarrierProofNotApplicable)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		registry.mu.Unlock()
		t.Fatal("hop publication waited for registry mutex")
	}
	registry.mu.Unlock()
	record := registry.Snapshot().Records[0]
	if len(record.Route.KnownHandlerChain) != 2 || record.Route.KnownHandlerChain[1].HandlerTag != "final" || record.Route.KnownHandlerChain[1].EntryKind != HandlerEntryLoopbackRedispatch {
		t.Fatalf("redispatch hop was not published: %+v", record.Route)
	}
}

func TestDepthFaultWaitsForAllReservedHopSlots(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	root := handle.root
	root.nextHop.Store(maxHandlerHops)
	for index := uint32(1); index < maxHandlerHops; index++ {
		root.hops[index].Store(&handlerHopReceipt{hop: HandlerHop{HandlerTag: "hop-" + encodeUint64(uint64(index)), EntryKind: HandlerEntryDialerProxy}, accountingSupported: true})
	}
	root.chainFault.Store(&chainFaultReceipt{disposition: ChainDispositionDepthExceeded, cutoff: maxHandlerHops})
	root.logical.markDirty()
	before := registry.Snapshot().Records[0]
	if before.Route.ChainDisposition == ChainDispositionDepthExceeded || len(before.Route.KnownHandlerChain) != 0 {
		t.Fatalf("depth fault overtook an unpublished reserved slot: %+v", before.Route)
	}
	root.hops[0].Store(&handlerHopReceipt{hop: HandlerHop{HandlerTag: "hop-0", EntryKind: HandlerEntryDialerProxy}, accountingSupported: true})
	root.logical.markDirty()
	after := registry.Snapshot().Records[0]
	if len(after.Route.KnownHandlerChain) != maxHandlerHops || after.Route.ChainDisposition != ChainDispositionDepthExceeded {
		t.Fatalf("committed hop prefix or depth fault was lost: %+v", after.Route)
	}
}

func continuationTestLink() *transport.Link {
	return &transport.Link{Reader: &buf.BufferedReader{}, Writer: buf.Discard}
}
