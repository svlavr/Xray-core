package flow

import (
	"context"
	"math"
	"sync"
	"testing"
)

func TestDetourScopeBindsExactChildAndExtendsOwnerLifetime(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "root", "type", "tcp:a:1", "", true, CarrierProofNotApplicable)
	parent := continuationTestLink()
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithRootDispatchOwner(ctx, handle)
	ctx = ContextWithLinkBinding(ctx, handle, parent, 0)
	child := continuationTestLink()
	scope := BeginDetour(ctx, child, "detour", "type", HandlerEntryDialerProxy)
	childCtx := scope.Context(ctx)
	binding, _ := childCtx.Value(linkBindingKey{}).(*linkBinding)
	if binding == nil || binding.expected != child || binding.handle != handle || binding.depth != 1 {
		t.Fatalf("detour did not bind exact child link: %+v", binding)
	}
	if RootDispatchOwnerFromContext(childCtx) != nil || ExternalOwnerScopeFromContext(childCtx) != nil || HandleFromContext(childCtx) != handle {
		t.Fatal("detour child inherited owner authority or lost root identity")
	}
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	if view := handle.LogicalRoot().View(); view.Phase == LifecyclePhaseTerminal || view.LiveParticipantCount != 1 {
		t.Fatalf("root terminalized before detour exit: %+v", view)
	}
	scope.Release(nil)
	if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseTerminal {
		t.Fatalf("detour exit did not release lifecycle: %+v", view)
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || len(snapshot.Records[0].Route.KnownHandlerChain) != 2 || snapshot.Records[0].Route.KnownHandlerChain[1].EntryKind != HandlerEntryDialerProxy {
		t.Fatalf("handler detour hop was not published: %+v", snapshot.Records)
	}
}

func TestMultipleDetourAttemptsAcquireParticipantsButPublishOneRouteEdge(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	first := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	second := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	if view := handle.LogicalRoot().View(); view.LiveParticipantCount != 3 || view.LifecycleFault != "" {
		t.Fatalf("legal parallel detours were rejected: %+v", view)
	}
	first.Release(nil)
	second.Release(nil)
	if snapshot := registry.Snapshot(); len(snapshot.Records[0].Route.KnownHandlerChain) != 1 || snapshot.Records[0].Route.ChainDisposition == ChainDispositionCycleDetected {
		t.Fatalf("parallel attempts became duplicate route edges: %+v", snapshot.Records[0].Route)
	}
}

func TestSiblingDetoursShareNextRouteLineage(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	firstA := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	secondA := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	firstB := BeginDetour(firstA.Context(ctx), continuationTestLink(), "b", "type", HandlerEntryDialerProxy)
	secondB := BeginDetour(secondA.Context(ctx), continuationTestLink(), "b", "type", HandlerEntryDialerProxy)
	secondB.Release(nil)
	firstB.Release(nil)
	secondA.Release(nil)
	firstA.Release(nil)
	snapshot := registry.Snapshot()
	chain := snapshot.Records[0].Route.KnownHandlerChain
	if len(chain) != 2 || chain[0].HandlerTag != "a" || chain[1].HandlerTag != "b" || snapshot.Records[0].Route.ChainDisposition == ChainDispositionCycleDetected {
		t.Fatalf("sibling retries fabricated a route cycle: %+v", snapshot.Records[0].Route)
	}
}

func TestPendingParentHopNeverPublishesNestedHopFirst(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	edgePublished := make(chan struct{})
	allowParentHop := make(chan struct{})
	firstDone := make(chan *DetourScope, 1)
	go func() {
		firstDone <- beginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy, func() {
			close(edgePublished)
			<-allowParentHop
		})
	}()
	<-edgePublished
	siblingA := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	nestedB := BeginDetour(siblingA.Context(ctx), continuationTestLink(), "b", "type", HandlerEntryDialerProxy)
	nestedB.Release(nil)
	siblingA.Release(nil)
	close(allowParentHop)
	firstA := <-firstDone
	firstA.Release(nil)
	snapshot := registry.Snapshot()
	if chain := snapshot.Records[0].Route.KnownHandlerChain; len(chain) != 1 || chain[0].HandlerTag != "a" {
		t.Fatalf("nested hop overtook pending parent: %+v", snapshot.Records[0].Route)
	}
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != "" {
		t.Fatalf("route-only pending proof blocked lifecycle: %s", fault)
	}
	if !detourRecordHasIssue(snapshot.Records[0], IssueDetourLineagePending) || snapshot.Records[0].Route.ChainCoverage != ChainCoveragePartial || snapshot.Records[0].CarrierProof != CarrierProofUnknown {
		t.Fatalf("pending lineage proof loss was not published as route-only: %+v", snapshot.Records[0])
	}

	readyA := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	readyB := BeginDetour(readyA.Context(ctx), continuationTestLink(), "b", "type", HandlerEntryDialerProxy)
	readyB.Release(nil)
	readyA.Release(nil)
	snapshot = registry.Snapshot()
	if chain := snapshot.Records[0].Route.KnownHandlerChain; len(chain) != 2 || chain[0].HandlerTag != "a" || chain[1].HandlerTag != "b" {
		t.Fatalf("ready lineage did not resume ordered proof: %+v", snapshot.Records[0].Route)
	}
	terminalize(handle)
	if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseTerminal {
		t.Fatalf("route-only pending proof prevented terminalization: %+v", view)
	}
	snapshot = registry.Snapshot()
	if snapshot.Records[0].CompletionState != CompletionTerminal || !detourRecordHasIssue(snapshot.Records[0], IssueDetourLineagePending) {
		t.Fatalf("terminal publication lost route-only pending proof: %+v", snapshot.Records[0])
	}
}

func TestPendingRouteProofAndTerminalPublishTogetherOnFirstSync(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	edgePublished := make(chan struct{})
	allowParentHop := make(chan struct{})
	firstDone := make(chan *DetourScope, 1)
	registry.mu.Lock()
	go func() {
		firstDone <- beginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy, func() {
			close(edgePublished)
			<-allowParentHop
		})
	}()
	<-edgePublished
	siblingA := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	nestedB := BeginDetour(siblingA.Context(ctx), continuationTestLink(), "b", "type", HandlerEntryDialerProxy)
	nestedB.Release(nil)
	siblingA.Release(nil)
	close(allowParentHop)
	firstA := <-firstDone
	firstA.Release(nil)
	terminalize(handle)
	registry.mu.Unlock()

	snapshot := registry.Snapshot()
	record := snapshot.Records[0]
	if record.CompletionState != CompletionTerminal || len(record.Route.KnownHandlerChain) != 1 || record.Route.KnownHandlerChain[0].HandlerTag != "a" || !detourRecordHasIssue(record, IssueDetourLineagePending) {
		t.Fatalf("first structural sync lost ordered route or terminal proof: %+v", record)
	}
}

func TestConcurrentSiblingDetoursNeverInvertRouteOrder(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		registry := newTestRegistry(t, 1, 1, 64)
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		ctx := ContextWithHandle(context.Background(), handle)
		ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for sibling := 0; sibling < 8; sibling++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				a := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
				b := BeginDetour(a.Context(ctx), continuationTestLink(), "b", "type", HandlerEntryDialerProxy)
				b.Release(nil)
				a.Release(nil)
			}()
		}
		close(start)
		wg.Wait()
		snapshot := registry.Snapshot()
		chain := snapshot.Records[0].Route.KnownHandlerChain
		if len(chain) == 0 || len(chain) > 2 || chain[0].HandlerTag != "a" || (len(chain) == 2 && chain[1].HandlerTag != "b") || snapshot.Records[0].Route.ChainDisposition == ChainDispositionCycleDetected {
			t.Fatalf("iteration %d published inverted route: %+v", iteration, snapshot.Records[0].Route)
		}
		registry.Close()
	}
}

func TestSiblingDetourTargetConflictIsTypedAndDeterministic(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	first := BeginDetour(ctx, continuationTestLink(), "a", "type", HandlerEntryDialerProxy)
	second := BeginDetour(ctx, continuationTestLink(), "different", "type", HandlerEntryDialerProxy)
	second.Release(nil)
	first.Release(nil)
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultDetourLineageConflict {
		t.Fatalf("conflicting sibling route was not typed: %s", fault)
	}
	snapshot := registry.Snapshot()
	if chain := snapshot.Records[0].Route.KnownHandlerChain; len(chain) != 1 || chain[0].HandlerTag != "a" {
		t.Fatalf("conflicting sibling replaced canonical edge: %+v", snapshot.Records[0].Route)
	}
}

func TestConcurrentConflictingSiblingTargetsKeepOneCanonicalEdge(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for attempt := 0; attempt < 32; attempt++ {
		tag := "a"
		if attempt%2 != 0 {
			tag = "b"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			scope := BeginDetour(ctx, continuationTestLink(), tag, "type", HandlerEntryDialerProxy)
			scope.Release(nil)
		}()
	}
	close(start)
	wg.Wait()
	snapshot := registry.Snapshot()
	chain := snapshot.Records[0].Route.KnownHandlerChain
	if len(chain) != 1 || (chain[0].HandlerTag != "a" && chain[0].HandlerTag != "b") {
		t.Fatalf("conflicting siblings published more than one canonical edge: %+v", snapshot.Records[0].Route)
	}
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultDetourLineageConflict {
		t.Fatalf("concurrent lineage conflict was not typed: %s", fault)
	}
}

func TestDetourMissingBindingMasksChildAndFailsObservationClosed(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	scope := BeginDetour(ctx, continuationTestLink(), "detour", "type", HandlerEntryDialerProxy)
	childCtx := scope.Context(ctx)
	if HasFlowObservation(childCtx) || handle.LogicalRoot().View().LifecycleFault != LifecycleFaultDetourContextMissing {
		t.Fatalf("missing detour binding inherited authority or lacked typed fault: %+v", handle.LogicalRoot().View())
	}
}

func TestDetourDepthOverflowDoesNotAcquireParticipant(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), math.MaxUint32)
	scope := BeginDetour(ctx, continuationTestLink(), "detour", "type", HandlerEntryDialerProxy)
	if HasFlowObservation(scope.Context(ctx)) || handle.LogicalRoot().View().LiveParticipantCount != 1 || handle.LogicalRoot().View().LifecycleFault != LifecycleFaultDetourDepthOverflow {
		t.Fatalf("depth-overflow detour acquired or inherited authority: %+v", handle.LogicalRoot().View())
	}
}

func TestNestedDetourUsesChildBindingAndDepth(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	first := BeginDetour(ctx, continuationTestLink(), "first", "type", HandlerEntryDialerProxy)
	second := BeginDetour(first.Context(ctx), continuationTestLink(), "second", "type", HandlerEntryDialerProxy)
	if view := handle.LogicalRoot().View(); view.LiveParticipantCount != 3 || view.LifecycleFault != "" {
		t.Fatalf("nested detour lost linear participation: %+v", view)
	}
	second.Release(nil)
	first.Release(nil)
	snapshot := registry.Snapshot()
	chain := snapshot.Records[0].Route.KnownHandlerChain
	if len(chain) != 2 || chain[0].HandlerTag != "first" || chain[1].HandlerTag != "second" {
		t.Fatalf("nested detour chain is not ordered: %+v", snapshot.Records[0].Route)
	}
}

func TestDetourAfterRegistryCloseMasksStaleAuthority(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	registry.Close()
	scope := BeginDetour(ctx, continuationTestLink(), "detour", "type", HandlerEntryDialerProxy)
	if HasFlowObservation(scope.Context(ctx)) || handle.LogicalRoot().View().LifecycleFault != LifecycleFaultDetourStaleRoot {
		t.Fatalf("stale detour inherited authority or lacked typed fault: %+v", handle.LogicalRoot().View())
	}
}

func TestDetourDoubleReleaseIsTyped(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	scope := BeginDetour(ctx, continuationTestLink(), "detour", "type", HandlerEntryDialerProxy)
	scope.Release(nil)
	scope.Release(nil)
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultDoubleParticipantRelease {
		t.Fatalf("double detour release was not typed: %s", fault)
	}
}

func TestDetourConcurrentDoubleReleaseIsTyped(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	ctx := ContextWithHandle(context.Background(), handle)
	ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
	scope := BeginDetour(ctx, continuationTestLink(), "detour", "type", HandlerEntryDialerProxy)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for release := 0; release < 2; release++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			scope.Release(nil)
		}()
	}
	close(start)
	wg.Wait()
	if fault := handle.LogicalRoot().View().LifecycleFault; fault != LifecycleFaultDoubleParticipantRelease {
		t.Fatalf("concurrent double release was not typed: %s", fault)
	}
}

func TestBeginDetourConcurrentWithRegistryClose(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		registry := newTestRegistry(t, 1, 1, 16)
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		ctx := ContextWithHandle(context.Background(), handle)
		ctx = ContextWithLinkBinding(ctx, handle, continuationTestLink(), 0)
		start := make(chan struct{})
		closed := make(chan struct{})
		go func() {
			<-start
			registry.Close()
			close(closed)
		}()
		close(start)
		scope := BeginDetour(ctx, continuationTestLink(), "detour", "type", HandlerEntryDialerProxy)
		scope.Release(nil)
		<-closed
		if !registry.closed {
			t.Fatalf("iteration %d did not close registry", iteration)
		}
	}
}

func detourRecordHasIssue(record Record, want Issue) bool {
	for _, issue := range record.Issues {
		if issue == want {
			return true
		}
	}
	return false
}
