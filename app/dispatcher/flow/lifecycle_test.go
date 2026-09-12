package flow

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/task"
)

func newTestRoot(t *testing.T) *LogicalFlowRoot {
	t.Helper()
	root, err := NewLogicalFlowRoot("runtime", "flow")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLogicalFlowRootRequiresCompleteTerminalPredicate(t *testing.T) {
	root := newTestRoot(t)
	child := root.AcquireParticipant()
	if child == nil {
		t.Fatal("failed to acquire child")
	}
	uplink := root.Uplink().Reserve()
	downlink := root.Downlink().Reserve()

	root.SealOwner(TerminalClassCompleted, "")
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed || view.LiveParticipantCount != 1 {
		t.Fatalf("terminal before child/bytes drained: %+v", view)
	}

	uplink.Complete(7)
	downlink.Complete(11)
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed {
		t.Fatalf("terminal before child release: %+v", view)
	}
	child.Release(nil)

	view := root.View()
	if view.Phase != LifecyclePhaseTerminal || view.Terminal == nil {
		t.Fatalf("root did not terminalize: %+v", view)
	}
	if testObservation(t, view.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 7 || testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 11 || view.LastByteSequence != 2 {
		t.Fatalf("unexpected counters: %+v", view)
	}
	if view.Terminal.Evidence != CompletionEvidenceRootLogicalLinkQuiesced || view.Terminal.LastByteSequence != 2 {
		t.Fatalf("unexpected terminal receipt: %+v", view.Terminal)
	}
}

func TestParticipantChildAcquireBeforeParentReleaseWins(t *testing.T) {
	root := newTestRoot(t)
	parent := root.AcquireParticipant()
	if parent == nil {
		t.Fatal("failed to acquire parent")
	}
	child := parent.AcquireParticipant()
	if child == nil {
		t.Fatal("failed to acquire child")
	}
	parent.Release(nil)
	if got := root.View().LiveParticipantCount; got != 2 {
		t.Fatalf("got %d participants, want owner+child", got)
	}
	child.Release(nil)
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	if view := root.View(); view.Phase != LifecyclePhaseTerminal || view.ProofState != ProofStateComplete {
		t.Fatalf("unexpected final view: %+v", view)
	}
}

func TestParticipantAcquireAfterReleaseFaultsWithoutSuppressingCaller(t *testing.T) {
	root := newTestRoot(t)
	parent := root.AcquireParticipant()
	parent.Release(nil)
	if child := parent.AcquireParticipant(); child != nil {
		t.Fatal("acquire after release returned a valid child")
	}
	view := root.View()
	if view.ProofState != ProofStateIndeterminate || view.LifecycleFault != LifecycleFaultLateParticipantAcquire {
		t.Fatalf("late acquire was not a sticky proof fault: %+v", view)
	}
}

func TestParticipantAcquireReleaseRaceNeverUnderflows(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		root := newTestRoot(t)
		parent := root.AcquireParticipant()
		var child task.ParticipantLease
		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			child = parent.AcquireParticipant()
		}()
		go func() {
			defer waitGroup.Done()
			parent.Release(nil)
		}()
		waitGroup.Wait()
		if child != nil {
			child.Release(nil)
		}
		if got := root.View().LiveParticipantCount; got != 1 {
			t.Fatalf("iteration %d: got %d live participants, want owner", iteration, got)
		}
	}
}

func TestDoubleParticipantReleaseDoesNotUnderflow(t *testing.T) {
	root := newTestRoot(t)
	child := root.AcquireParticipant()
	child.Release(nil)
	child.Release(nil)
	view := root.View()
	if view.LiveParticipantCount != 1 || view.LifecycleFault != LifecycleFaultDoubleParticipantRelease {
		t.Fatalf("double release corrupted count: %+v", view)
	}
}

func TestDirectionSealDrainsReservedOperationAndRejectsLateAccounting(t *testing.T) {
	root := newTestRoot(t)
	operation := root.Uplink().Reserve()
	root.Uplink().Seal()
	if state := root.View().UplinkState; state != DirectionStateSealed {
		t.Fatalf("got %s, want sealed while operation is live", state)
	}
	operation.Complete(13)
	if state := root.View().UplinkState; state != DirectionStateSealed {
		t.Fatalf("got %s, want sealed before native drain", state)
	}
	root.Uplink().MarkDrained()
	if state := root.View().UplinkState; state != DirectionStateQuiescent {
		t.Fatalf("got %s, want quiescent", state)
	}
	late := root.Uplink().Reserve()
	late.Complete(17)
	view := root.View()
	if testObservation(t, view.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Known || view.AccountingFault != AccountingFaultUnreservedBytes {
		t.Fatalf("late operation did not invalidate incomplete accounting: %+v", view)
	}
	if view.LifecycleFault != LifecycleFaultByteOperationAfterSeal {
		t.Fatalf("late operation did not fault lifecycle: %+v", view)
	}
}

func TestDirectionDrainBeforeSealStillPublishesQuiescence(t *testing.T) {
	root := newTestRoot(t)
	root.Uplink().MarkDrained()
	if state := root.View().UplinkState; state != DirectionStateOpen {
		t.Fatalf("drain without owner seal changed public direction state: %s", state)
	}
	root.Uplink().Seal()
	if state := root.View().UplinkState; state != DirectionStateQuiescent {
		t.Fatalf("got %s, want quiescent after drain-before-seal race", state)
	}
}

func TestHalfCloseDoesNotSealOppositeDirection(t *testing.T) {
	root := newTestRoot(t)
	root.Uplink().HalfClose()
	downlink := root.Downlink().Reserve()
	downlink.Complete(5)
	view := root.View()
	if view.UplinkState != DirectionStateHalfClosed || view.DownlinkState != DirectionStateOpen {
		t.Fatalf("half-close changed the wrong direction: %+v", view)
	}
	if testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 5 || view.Phase != LifecyclePhaseOpen {
		t.Fatalf("opposite-direction progress lost: %+v", view)
	}
}

func TestBytePathTransitionKeepsOneRootAndIndependentScopes(t *testing.T) {
	root := newTestRoot(t)
	logical := root.Downlink().Reserve()
	kernel := root.Downlink().transitionToF2Required(byteScopeSlotKernelDirectCopyAccepted)
	if !kernel.reserved {
		t.Fatal("direct-copy transition did not reserve the existing direction gate")
	}

	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	logical.Complete(5)
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed {
		t.Fatalf("terminal overtook direct-copy reservation: %+v", view)
	}
	kernel.Complete(0)

	view := root.View()
	logicalObservation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted)
	kernelObservation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if view.FlowID != root.FlowID() || view.Phase != LifecyclePhaseTerminal || logicalObservation.ObservedBytes != (OptionalUint64{Known: true, Value: 5}) || kernelObservation.State != ByteObservationStateF2Required || kernelObservation.ObservedBytes.Known {
		t.Fatalf("scope transition changed identity, coerced bytes, or fabricated zero: %+v", view)
	}
}

func TestProvenBytePathPublishesLiveProgressBeforeTerminal(t *testing.T) {
	root := newTestRoot(t)
	logical := root.Downlink().Reserve()
	kernel := root.Downlink().transitionToDeferred(byteScopeSlotKernelDirectCopyAccepted)
	if !kernel.reserved {
		t.Fatal("direct-copy progress did not reserve the existing direction gate")
	}

	kernel.Progress(3)
	kernel.Progress(5)
	progress := root.View()
	kernelObservation := testObservation(t, progress.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if kernelObservation.State != ByteObservationStateProven || kernelObservation.ObservedBytes != (OptionalUint64{Known: true, Value: 8}) || progress.LastByteSequence != 2 {
		t.Fatalf("live direct-copy progress was not published exactly: %+v", progress)
	}

	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	logical.Complete(2)
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed {
		t.Fatalf("terminal overtook live direct-copy progress operation: %+v", view)
	}
	kernel.Complete(0)

	final := root.View()
	if final.Phase != LifecyclePhaseTerminal || final.Terminal == nil || final.Terminal.LastByteSequence != 3 {
		t.Fatalf("direct-copy completion did not release the terminal barrier: %+v", final)
	}
	if got := testObservation(t, final.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted).ObservedBytes; got != (OptionalUint64{Known: true, Value: 8}) {
		t.Fatalf("terminal changed direct-copy progress: %+v", final)
	}
}

func TestProvenBytePathConcurrentProgressIsExact(t *testing.T) {
	root := newTestRoot(t)
	operation := root.Downlink().transitionToDeferred(byteScopeSlotKernelDirectCopyAccepted)
	const publishers = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(publishers)
	for index := 0; index < publishers; index++ {
		go func() {
			defer waitGroup.Done()
			operation.Progress(1)
		}()
	}
	waitGroup.Wait()
	operation.Complete(0)

	view := root.View()
	observation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if observation.State != ByteObservationStateProven || observation.ObservedBytes != (OptionalUint64{Known: true, Value: publishers}) || view.LastByteSequence != publishers || view.LifecycleFault != "" || view.AccountingFault != "" {
		t.Fatalf("concurrent direct-copy progress was lost or faulted: %+v", view)
	}
}

func TestProvenBytePathLateProgressCannotMutateTerminalReceipt(t *testing.T) {
	root := newTestRoot(t)
	operation := root.Downlink().transitionToDeferred(byteScopeSlotKernelDirectCopyAccepted)
	operation.Progress(9)
	operation.Complete(0)
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	before := root.View()

	operation.Progress(7)
	after := root.View()
	beforeObservation := testObservation(t, before.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	afterObservation := testObservation(t, after.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if after.Phase != LifecyclePhaseTerminal || afterObservation != beforeObservation || after.AccountingFault != before.AccountingFault || after.PostTerminalFaultCount != before.PostTerminalFaultCount+1 {
		t.Fatalf("late progress mutated terminal accounting: before=%+v after=%+v", before, after)
	}
}

func TestProvenBytePathLateProgressRaceCannotMutateTerminalReceipt(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		root := newTestRoot(t)
		operation := root.Downlink().transitionToDeferred(byteScopeSlotKernelDirectCopyAccepted)
		operation.Progress(9)
		operation.Complete(0)
		root.Uplink().Seal()
		root.Downlink().Seal()
		root.Uplink().MarkDrained()
		root.Downlink().MarkDrained()
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-start
			root.SealOwner(TerminalClassCompleted, "")
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			operation.Progress(7)
		}()
		close(start)
		waitGroup.Wait()

		view := root.View()
		observation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		if view.Phase == LifecyclePhaseTerminal {
			if observation.State != ByteObservationStateProven || observation.ObservedBytes != (OptionalUint64{Known: true, Value: 9}) || view.PostTerminalFaultCount != 1 {
				t.Fatalf("iteration %d: terminal receipt raced with a byte-cell mutation: %+v", iteration, view)
			}
			continue
		}
		if view.LifecycleFault != LifecycleFaultLateByteProgress || observation.State != ByteObservationStateIndeterminate || view.AccountingFault != AccountingFaultCallbackLost {
			t.Fatalf("iteration %d: pre-terminal late progress did not fail proof closed: %+v", iteration, view)
		}
	}
}

func TestProvenBytePathLateProgressTerminalAndLifecycleFaultRaceIsFailClosed(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		root := newTestRoot(t)
		operation := root.Downlink().transitionToDeferred(byteScopeSlotKernelDirectCopyAccepted)
		operation.Progress(9)
		operation.Complete(0)
		root.Uplink().Seal()
		root.Downlink().Seal()
		root.Uplink().MarkDrained()
		root.Downlink().MarkDrained()
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(3)
		go func() {
			defer waitGroup.Done()
			<-start
			root.SealOwner(TerminalClassCompleted, "")
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			operation.Progress(7)
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			operation.Complete(0)
		}()
		close(start)
		waitGroup.Wait()

		view := root.View()
		observation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		if view.Phase == LifecyclePhaseTerminal {
			if observation.State != ByteObservationStateProven || observation.ObservedBytes != (OptionalUint64{Known: true, Value: 9}) || view.PostTerminalFaultCount != 2 {
				t.Fatalf("iteration %d: terminal receipt raced with late lifecycle mutations: %+v", iteration, view)
			}
			continue
		}
		if view.ProofState != ProofStateIndeterminate || observation.State != ByteObservationStateIndeterminate || view.AccountingFault != AccountingFaultCallbackLost {
			t.Fatalf("iteration %d: non-terminal race retained a continuous byte claim: %+v", iteration, view)
		}
	}
}

func BenchmarkProvenBytePathProgress(b *testing.B) {
	root, err := NewLogicalFlowRoot("runtime", "flow")
	if err != nil {
		b.Fatal(err)
	}
	operation := root.Downlink().transitionToDeferred(byteScopeSlotKernelDirectCopyAccepted)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		operation.Progress(1)
	}
	b.StopTimer()
	operation.Complete(0)
}

func TestBytePathTransitionIsCASOrderedAgainstLaterLogicalReservation(t *testing.T) {
	root := newTestRoot(t)
	kernel := root.Downlink().transitionToF2Required(byteScopeSlotKernelDirectCopyAccepted)
	lateLogical := root.Downlink().Reserve()
	lateLogical.Complete(7)
	kernel.Complete(0)
	view := root.View()
	logical := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted)
	if logical.ObservedBytes.Known || logical.AccountingFault != AccountingFaultBoundaryUnproven {
		t.Fatalf("post-transition logical write was attributed to a raw scope: %+v", view)
	}
	if kernelObservation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted); kernelObservation.State != ByteObservationStateF2Required || kernelObservation.ObservedBytes.Known {
		t.Fatalf("typed direct-copy gap changed after late logical write: %+v", kernelObservation)
	}
}

func TestBytePathTransitionVisibilityComesFromReservationCAS(t *testing.T) {
	root := newTestRoot(t)
	root.Downlink().state.Store(uint64(byteScopeSlotKernelDirectCopyAccepted)<<directionScopeShift | 1)
	observation := testObservation(t, root.View().ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if observation.State != ByteObservationStateF2Required || observation.ObservedBytes.Known {
		t.Fatalf("CAS-visible transition was absent or numeric before cell publication: %+v", observation)
	}
}

func TestBytePathTransitionLosingToSealCannotMutateTerminalScopes(t *testing.T) {
	root := newTestRoot(t)
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	before := root.View()
	operation := root.Downlink().transitionToF2Required(byteScopeSlotKernelDirectCopyAccepted)
	operation.Complete(0)
	after := root.View()
	if after.Phase != LifecyclePhaseTerminal || len(after.ByteObservations) != len(before.ByteObservations) || after.PostTerminalFaultCount == 0 {
		t.Fatalf("seal-winning transition mutated terminal scopes or lost misuse evidence: before=%+v after=%+v", before, after)
	}
	for _, observation := range after.ByteObservations {
		if observation.ByteScope == ByteScopeKernelDirectCopyAccepted {
			t.Fatalf("failed post-terminal transition published a successful scope: %+v", after)
		}
	}
}

func TestTerminalOutcomePrecedenceAndImmutability(t *testing.T) {
	root := newTestRoot(t)
	root.RecordOutcome(TerminalClassRemoteEOF, "EOF")
	root.RecordOutcome(TerminalClassCancelled, "CANCELLED")
	root.RecordOutcome(TerminalClassCompleted, "")
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassRemoteError, "REMOTE")

	view := root.View()
	if view.Terminal == nil || view.Terminal.TerminalClass != TerminalClassCancelled {
		t.Fatalf("unexpected normalized outcome: %+v", view.Terminal)
	}
	terminalAt := view.Terminal.TerminalAtOffset
	if child := root.AcquireParticipant(); child != nil {
		t.Fatal("owner acquired a child after terminal")
	}
	after := root.View()
	if after.Terminal.TerminalAtOffset != terminalAt || after.Terminal.TerminalClass != TerminalClassCancelled {
		t.Fatalf("terminal receipt changed after publication: before=%+v after=%+v", view.Terminal, after.Terminal)
	}
	if after.PostTerminalFaultCount == 0 {
		t.Fatal("post-terminal misuse was not diagnosed")
	}
}

func TestTerminalWaitsForInFlightOutcomePublication(t *testing.T) {
	root := newTestRoot(t)
	if !root.beginOutcomeUpdate() {
		t.Fatal("failed to reserve outcome publication")
	}
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed || view.Terminal != nil {
		t.Fatalf("terminal published before reserved outcome: %+v", view)
	}
	root.publishOutcome(TerminalClassCancelled, "CANCELLED")
	root.endOutcomeUpdate()
	view := root.View()
	if view.Phase != LifecyclePhaseTerminal || view.Terminal == nil || view.Terminal.TerminalClass != TerminalClassCancelled {
		t.Fatalf("reserved outcome was not included in terminal receipt: %+v", view)
	}
}

func TestExternalOwnerScopeSealsExactlyOnceAfterOwnerAction(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	handle := registry.AdmitExternalTCP(context.Background(), "", "tcp:a:1", "", scope, continuationTestLink())
	scope.AfterOwnerClose(io.EOF, nil)
	scope.AfterOwnerClose(errors.New("late"), errors.New("late"))
	view := handle.LogicalRoot().View()
	if view.Phase != LifecyclePhaseTerminal || view.Terminal == nil {
		t.Fatalf("external owner scope did not complete the root: %+v", view)
	}
	if view.Terminal.TerminalClass != TerminalClassRemoteEOF || view.ProofState != ProofStateComplete {
		t.Fatalf("duplicate owner close changed proof: %+v", view)
	}
}

func TestFaultedQuiescentRootIsRetirableButNotTerminal(t *testing.T) {
	root := newTestRoot(t)
	child := root.AcquireParticipant()
	child.Release(nil)
	child.Release(nil)
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	view := root.View()
	if view.Phase == LifecyclePhaseTerminal || !root.RetirableIndeterminate() {
		t.Fatalf("faulted root was terminalized or retained forever: %+v", view)
	}
}

func TestLifecycleAndAccountingOverflowNeverWrap(t *testing.T) {
	root := newTestRoot(t)
	root.liveParticipants.Store(math.MaxUint64)
	if child := root.AcquireParticipant(); child != nil {
		t.Fatal("participant overflow returned a lease")
	}
	if view := root.View(); view.LiveParticipantCount != math.MaxUint64 || view.LifecycleFault != LifecycleFaultParticipantCapacityExceeded {
		t.Fatalf("participant overflow wrapped or lost fault: %+v", view)
	}

	bytesRoot := newTestRoot(t)
	bytesRoot.observationCell(DirectionUplink, byteScopeSlotLogicalLinkAccepted).bytes.Store(math.MaxUint64 - 1)
	operation := bytesRoot.Uplink().Reserve()
	operation.Complete(2)
	view := bytesRoot.View()
	if testObservation(t, view.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Known || view.AccountingFault != AccountingFaultCounterOverflow {
		t.Fatalf("counter overflow became a known wrapped value: %+v", view)
	}
}

func TestTaskRunParticipantsKeepRootOpenAfterFirstError(t *testing.T) {
	root := newTestRoot(t)
	ctx := task.ContextWithParticipantTracker(context.Background(), root)
	releaseLate := make(chan struct{})
	lateStarted := make(chan struct{})

	err := task.Run(ctx,
		func() error {
			<-lateStarted
			return context.Canceled
		},
		func() error {
			close(lateStarted)
			<-releaseLate
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed || view.LiveParticipantCount < 1 {
		t.Fatalf("late sibling was not retained: %+v", view)
	}
	close(releaseLate)
	for root.View().Phase != LifecyclePhaseTerminal {
	}
	if got := root.View().Terminal.TerminalClass; got != TerminalClassCancelled {
		t.Fatalf("got %s, want cancelled", got)
	}
}

func TestRunWithContextTaskCanAcquireChildAfterOwnerSeal(t *testing.T) {
	root := newTestRoot(t)
	ctx := task.ContextWithParticipantTracker(context.Background(), root)
	siblingStarted := make(chan struct{})
	allowAcquire := make(chan struct{})
	nestedResult := make(chan task.ParticipantLease, 1)

	err := task.RunWithContext(ctx,
		func(context.Context) error {
			<-siblingStarted
			return context.Canceled
		},
		func(taskCtx context.Context) error {
			close(siblingStarted)
			<-allowAcquire
			nestedResult <- task.AcquireParticipant(taskCtx)
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	close(allowAcquire)
	nested := <-nestedResult
	if nested == nil {
		t.Fatal("active task lease could not acquire child after owner seal")
	}
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed {
		t.Fatalf("root terminalized before nested child exit: %+v", view)
	}
	nested.Release(nil)
	for root.View().Phase != LifecyclePhaseTerminal {
	}
	if view := root.View(); view.LifecycleFault != "" {
		t.Fatalf("linear nested acquire faulted: %+v", view)
	}
}
