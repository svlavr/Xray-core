package flow

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/task"
)

const lifecyclePhaseMask uint32 = 0x3

const (
	lifecycleOpenWord uint32 = iota
	lifecycleOwnerSealedWord
	lifecycleTerminalWord
)

const lifecycleFaultBit uint32 = 1 << 31

const (
	participantReleasingBit uint64 = 1 << 63
	participantReleasedBit  uint64 = 1 << 62
	participantAcquireMask  uint64 = participantReleasedBit - 1
)

const (
	directionHalfClosedBit uint64 = 1 << 63
	directionSealedBit     uint64 = 1 << 62
	directionDrainedBit    uint64 = 1 << 61
	directionScopeShift           = 56
	directionScopeMask     uint64 = 0x1f << directionScopeShift
	directionCountMask     uint64 = 1<<directionScopeShift - 1
)

const (
	outcomeClosedBit uint64 = 1 << 63
	outcomeCountMask uint64 = outcomeClosedBit - 1
)

const (
	byteOperationCompletedBit uint64 = 1 << 63
	byteOperationProgressMask uint64 = byteOperationCompletedBit - 1
	lateProgressClosedBit     uint64 = 1 << 63
	lateProgressCountMask     uint64 = lateProgressClosedBit - 1
)

type lifecycleFaultReceipt struct {
	reason LifecycleFault
}

type accountingFaultReceipt struct {
	reason AccountingFault
}

type byteScopeSlot uint8

const (
	byteScopeSlotNone byteScopeSlot = iota
	byteScopeSlotLogicalLinkAccepted
	byteScopeSlotDispatcherExternalLinkIO
	byteScopeSlotKernelDirectCopyAccepted
	byteScopeSlotCount
)

const (
	byteCellUnpopulated uint32 = iota
	byteCellPending
	byteCellProven
	byteCellF2Required
	byteCellOverflowed
	byteCellIndeterminate
)

type byteObservationCell struct {
	bytes atomic.Uint64
	state atomic.Uint32
	fault atomic.Pointer[accountingFaultReceipt]
}

type outcomeReceipt struct {
	class    TerminalClass
	category string
	rank     uint32
}

// LogicalFlowRoot owns one platform-neutral logical lifecycle. Its hot-path
// state is atomic and independent from registry retention and event delivery.
type LogicalFlowRoot struct {
	runtimeInstanceID string
	flowID            string
	startedAt         time.Time
	lifecycleSequence atomic.Uint64
	sequenceSource    *atomic.Uint64

	phaseFault            atomic.Uint32
	liveParticipants      atomic.Uint64
	lastByteSequence      atomic.Uint64
	byteObservations      [MaxByteObservations]byteObservationCell
	dirty                 atomic.Bool
	ownerSealStarted      atomic.Bool
	postTerminalFaults    atomic.Uint64
	outcomeState          atomic.Uint64
	lateProgressState     atomic.Uint64
	terminalFaultMu       sync.Mutex
	dirtySignal           chan<- struct{}
	deferredDirty         *atomic.Bool
	optionalTerminalCause bool
	completionEvidence    CompletionEvidence

	lifecycleFault  atomic.Pointer[lifecycleFaultReceipt]
	accountingFault atomic.Pointer[accountingFaultReceipt]
	outcome         atomic.Pointer[outcomeReceipt]
	terminal        atomic.Pointer[TerminalReceipt]

	uplink   DirectionGate
	downlink DirectionGate
	owner    participantLease
}

// NewLogicalFlowRoot creates the one owner participant and two open direction
// gates. Runtime and flow identities must already be non-reused by the caller.
func NewLogicalFlowRoot(runtimeInstanceID, flowID string, initialByteScope ...ByteScope) (*LogicalFlowRoot, error) {
	return newLogicalFlowRoot(runtimeInstanceID, flowID, false, CompletionEvidenceRootLogicalLinkQuiesced, initialByteScope...)
}

func newLogicalFlowRoot(runtimeInstanceID, flowID string, optionalTerminalCause bool, completionEvidence CompletionEvidence, initialByteScope ...ByteScope) (*LogicalFlowRoot, error) {
	if runtimeInstanceID == "" || flowID == "" {
		return nil, errors.New("logical flow root requires runtime and flow identities")
	}
	root := &LogicalFlowRoot{
		runtimeInstanceID:     runtimeInstanceID,
		flowID:                flowID,
		startedAt:             time.Now(),
		optionalTerminalCause: optionalTerminalCause,
		completionEvidence:    completionEvidence,
	}
	root.sequenceSource = &root.lifecycleSequence
	root.liveParticipants.Store(1)
	scope := ByteScopeLogicalLinkAccepted
	if len(initialByteScope) != 0 {
		scope = initialByteScope[0]
	}
	slot := byteScopeSlotFor(scope)
	root.uplink = DirectionGate{root: root, direction: DirectionUplink, byteScope: slot}
	root.downlink = DirectionGate{root: root, direction: DirectionDownlink, byteScope: slot}
	root.initializeObservation(DirectionUplink, slot, byteCellProven)
	root.initializeObservation(DirectionDownlink, slot, byteCellProven)
	root.owner = participantLease{root: root, owner: true, omitNilOutcome: optionalTerminalCause}
	return root, nil
}

func (r *LogicalFlowRoot) RuntimeInstanceID() string { return r.runtimeInstanceID }
func (r *LogicalFlowRoot) FlowID() string            { return r.flowID }
func (r *LogicalFlowRoot) Uplink() *DirectionGate    { return &r.uplink }
func (r *LogicalFlowRoot) Downlink() *DirectionGate  { return &r.downlink }

// AcquireParticipant implements task.ParticipantTracker for work spawned by
// the root owner before owner seal.
func (r *LogicalFlowRoot) AcquireParticipant() task.ParticipantLease {
	if r == nil {
		return nil
	}
	return r.owner.AcquireParticipant()
}

// SealOwner passively records that the class owner has already completed its
// stock owner action. It neither closes traffic nor seals either direction.
func (r *LogicalFlowRoot) SealOwner(class TerminalClass, category string) {
	if r == nil || !r.ownerSealStarted.CompareAndSwap(false, true) {
		return
	}
	r.owner.release(class, category, true, true)
}

// SealXUDPRetainedLink configures the local retained-link receipt before any
// direction action can make terminalization observable.
func (r *LogicalFlowRoot) SealXUDPRetainedLink() {
	if r == nil {
		return
	}
	r.terminalFaultMu.Lock()
	if r.terminal.Load() != nil {
		r.terminalFaultMu.Unlock()
		return
	}
	r.completionEvidence = CompletionEvidenceXUDPRetainedLinkClosed
	r.terminalFaultMu.Unlock()
	r.Uplink().Seal()
	r.Downlink().Seal()
	r.Uplink().MarkDrained()
	r.Downlink().MarkDrained()
	r.SealOwner(TerminalClassCompleted, "")
}

func (r *LogicalFlowRoot) sealOwnerWithoutOutcome() {
	if r == nil || !r.ownerSealStarted.CompareAndSwap(false, true) {
		return
	}
	r.owner.release("", "", true, false)
}

// RecordOutcome publishes bounded completion evidence before a participant is
// released. The highest-precedence fact wins deterministically.
func (r *LogicalFlowRoot) RecordOutcome(class TerminalClass, category string) {
	if r == nil {
		return
	}
	r.recordOutcome(class, category)
}

func (r *LogicalFlowRoot) recordOutcome(class TerminalClass, category string) {
	if !r.beginOutcomeUpdate() {
		r.postTerminalFaults.Add(1)
		return
	}
	defer r.endOutcomeUpdate()
	r.publishOutcome(class, category)
}

func (r *LogicalFlowRoot) publishOutcome(class TerminalClass, category string) {
	candidate := &outcomeReceipt{class: class, category: boundedCategory(category), rank: outcomeRank(class)}
	for {
		current := r.outcome.Load()
		if current != nil && current.rank >= candidate.rank {
			return
		}
		if r.outcome.CompareAndSwap(current, candidate) {
			r.markDirty()
			return
		}
	}
}

func (r *LogicalFlowRoot) beginOutcomeUpdate() bool {
	for {
		state := r.outcomeState.Load()
		if state&outcomeClosedBit != 0 {
			return false
		}
		if state&outcomeCountMask == outcomeCountMask {
			r.markLifecycleFault(LifecycleFaultOutcomeCapacityExceeded)
			return false
		}
		if r.outcomeState.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (r *LogicalFlowRoot) endOutcomeUpdate() {
	for {
		state := r.outcomeState.Load()
		count := state & outcomeCountMask
		if count == 0 {
			r.markLifecycleFault(LifecycleFaultOutcomeUnderflow)
			return
		}
		next := state - 1
		if r.outcomeState.CompareAndSwap(state, next) {
			if next == outcomeClosedBit {
				r.finalizeTerminal()
			}
			return
		}
	}
}

func outcomeRank(class TerminalClass) uint32 {
	switch class {
	case TerminalClassLocalRejection:
		return 8
	case TerminalClassTimeout:
		return 7
	case TerminalClassCancelled:
		return 6
	case TerminalClassLocalError:
		return 5
	case TerminalClassRemoteError:
		return 4
	case TerminalClassRemoteEOF:
		return 3
	case TerminalClassCompleted:
		return 2
	default:
		return 1
	}
}

func outcomeFromError(err error) (TerminalClass, string) {
	switch {
	case err == nil:
		return TerminalClassCompleted, ""
	case errors.Is(err, context.DeadlineExceeded):
		return TerminalClassTimeout, "DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		return TerminalClassCancelled, "CONTEXT_CANCELLED"
	case errors.Is(err, io.EOF):
		return TerminalClassRemoteEOF, "EOF"
	default:
		return TerminalClassLocalError, "PARTICIPANT_ERROR"
	}
}

type participantLease struct {
	root           *LogicalFlowRoot
	owner          bool
	omitNilOutcome bool
	state          atomic.Uint64
	releaseClaim   atomic.Bool
}

func (p *participantLease) AcquireParticipant() task.ParticipantLease {
	if p == nil || p.root == nil {
		return nil
	}
	for {
		state := p.state.Load()
		if state&(participantReleasingBit|participantReleasedBit) != 0 {
			p.root.markLifecycleFault(LifecycleFaultLateParticipantAcquire)
			return nil
		}
		if state&participantAcquireMask == participantAcquireMask {
			p.root.markLifecycleFault(LifecycleFaultParticipantCapacityExceeded)
			return nil
		}
		if !p.state.CompareAndSwap(state, state+1) {
			continue
		}
		acquired := p.root.incrementParticipants()
		p.finishAcquisition()
		if !acquired {
			return nil
		}
		return &participantLease{root: p.root, omitNilOutcome: p.omitNilOutcome}
	}
}

func (p *participantLease) Release(err error) {
	if p == nil || p.root == nil {
		return
	}
	class, category := outcomeFromError(err)
	p.release(class, category, false, err != nil || !p.omitNilOutcome)
}

func (p *participantLease) release(class TerminalClass, category string, sealOwner bool, recordOutcome bool) {
	if !p.releaseClaim.CompareAndSwap(false, true) {
		p.root.markLifecycleFault(LifecycleFaultDoubleParticipantRelease)
		return
	}
	if recordOutcome {
		p.root.recordOutcome(class, category)
	}
	for {
		state := p.state.Load()
		if p.state.CompareAndSwap(state, state|participantReleasingBit) {
			break
		}
	}
	if sealOwner {
		p.root.sealOwnerPhase()
	}
	p.finishReleaseIfReady()
	if sealOwner {
		p.root.maybeTerminal()
	}
}

func (p *participantLease) finishAcquisition() {
	for {
		state := p.state.Load()
		reservations := state & participantAcquireMask
		if reservations == 0 {
			p.root.markLifecycleFault(LifecycleFaultParticipantUnderflow)
			return
		}
		if p.state.CompareAndSwap(state, state-1) {
			p.finishReleaseIfReady()
			return
		}
	}
}

func (p *participantLease) finishReleaseIfReady() {
	for {
		state := p.state.Load()
		if state&participantReleasingBit == 0 || state&participantAcquireMask != 0 || state&participantReleasedBit != 0 {
			return
		}
		if p.state.CompareAndSwap(state, state|participantReleasedBit) {
			p.root.decrementParticipants()
			p.root.maybeTerminal()
			return
		}
	}
}

func (r *LogicalFlowRoot) incrementParticipants() bool {
	for {
		current := r.liveParticipants.Load()
		if current == math.MaxUint64 {
			r.markLifecycleFault(LifecycleFaultParticipantCapacityExceeded)
			return false
		}
		if r.liveParticipants.CompareAndSwap(current, current+1) {
			r.markDirty()
			return true
		}
	}
}

func (r *LogicalFlowRoot) decrementParticipants() {
	for {
		current := r.liveParticipants.Load()
		if current == 0 {
			r.markLifecycleFault(LifecycleFaultParticipantUnderflow)
			return
		}
		if r.liveParticipants.CompareAndSwap(current, current-1) {
			r.markDirty()
			return
		}
	}
}

func (r *LogicalFlowRoot) sealOwnerPhase() {
	for {
		current := r.phaseFault.Load()
		if current&lifecyclePhaseMask != lifecycleOpenWord {
			return
		}
		next := current&^lifecyclePhaseMask | lifecycleOwnerSealedWord
		if r.phaseFault.CompareAndSwap(current, next) {
			r.markDirty()
			return
		}
	}
}

// DirectionGate is the lock-free operation barrier for one logical direction.
type DirectionGate struct {
	root       *LogicalFlowRoot
	direction  Direction
	byteScope  byteScopeSlot
	state      atomic.Uint64
	quiescence atomic.Pointer[QuiescenceReceipt]
}

// Reserve linearizes before delegated I/O. Invalid reservations never prevent
// the caller from executing I/O; they only lose observation proof.
func (g *DirectionGate) Reserve() *ByteOperation {
	if g == nil || g.root == nil {
		return &ByteOperation{}
	}
	return &ByteOperation{root: g.root, gate: g, scope: g.byteScope, reserved: g.reserve()}
}

func (g *DirectionGate) reserve() bool {
	for {
		current := g.state.Load()
		if current&directionSealedBit != 0 {
			g.root.markLifecycleFault(LifecycleFaultByteOperationAfterSeal)
			return false
		}
		if current&directionScopeMask != 0 {
			g.root.markObservationFault(g.direction, g.byteScope, AccountingFaultBoundaryUnproven)
			return false
		}
		count := current & directionCountMask
		if count == directionCountMask {
			g.root.markLifecycleFault(LifecycleFaultByteOperationCapacity)
			return false
		}
		if g.state.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (g *DirectionGate) recordAccepted(acceptedBytes uint64) {
	g.complete(g.reserve(), g.byteScope, acceptedBytes)
}

func (g *DirectionGate) complete(reserved bool, scope byteScopeSlot, acceptedBytes uint64) {
	if !reserved {
		if acceptedBytes > 0 {
			if g.root.phase() == LifecyclePhaseTerminal {
				g.root.postTerminalFaults.Add(1)
			} else {
				g.root.markObservationFault(g.direction, scope, AccountingFaultUnreservedBytes)
			}
		}
		return
	}
	if acceptedBytes > 0 {
		g.root.addAcceptedBytes(g.direction, scope, acceptedBytes)
		g.root.advanceByteSequence()
		g.root.markDirty()
	}
	g.releaseReservation()
}

// HalfClose records one-direction EOF/close without sealing the direction.
func (g *DirectionGate) HalfClose() {
	if g == nil || g.root == nil {
		return
	}
	for {
		current := g.state.Load()
		if current&directionHalfClosedBit != 0 {
			return
		}
		if g.state.CompareAndSwap(current, current|directionHalfClosedBit) {
			g.root.markDirty()
			return
		}
	}
}

// Seal records that the existing class owner action has made new successful
// operations illegal. It does not claim that already accepted native buffers
// were drained or discarded.
func (g *DirectionGate) Seal() {
	if g == nil || g.root == nil {
		return
	}
	for {
		current := g.state.Load()
		if current&directionSealedBit != 0 {
			g.publishQuiescence(current)
			return
		}
		next := current | directionSealedBit
		if g.state.CompareAndSwap(current, next) {
			g.root.markDirty()
			g.publishQuiescence(next)
			return
		}
	}
}

// MarkDrained records the native owner's proof that no accepted buffered data
// remains. It is separate from Seal because a graceful pipe close retains data
// until the reader drains it.
func (g *DirectionGate) MarkDrained() {
	if g == nil || g.root == nil {
		return
	}
	for {
		current := g.state.Load()
		if current&directionDrainedBit != 0 {
			g.publishQuiescence(current)
			return
		}
		next := current | directionDrainedBit
		if g.state.CompareAndSwap(current, next) {
			g.root.markDirty()
			g.publishQuiescence(next)
			return
		}
	}
}

func (g *DirectionGate) publishQuiescence(state uint64) {
	if state&(directionSealedBit|directionDrainedBit) != directionSealedBit|directionDrainedBit ||
		state&directionCountMask != 0 || g.quiescence.Load() != nil {
		return
	}
	receipt := &QuiescenceReceipt{
		RuntimeInstanceID: g.root.runtimeInstanceID,
		FlowID:            g.root.flowID,
		Direction:         g.direction,
		ObservedAtOffset:  time.Since(g.root.startedAt),
		LastByteSequence:  g.root.lastByteSequence.Load(),
	}
	if g.quiescence.CompareAndSwap(nil, receipt) {
		g.root.markDirty()
		g.root.maybeTerminal()
	}
}

func (g *DirectionGate) releaseReservation() {
	for {
		current := g.state.Load()
		count := current & directionCountMask
		if count == 0 {
			g.root.markLifecycleFault(LifecycleFaultByteOperationUnderflow)
			return
		}
		next := current - 1
		if g.state.CompareAndSwap(current, next) {
			g.publishQuiescence(next)
			g.root.maybeTerminal()
			return
		}
	}
}

func (g *DirectionGate) viewState() DirectionState {
	state := g.state.Load()
	if state&directionSealedBit != 0 {
		if state&directionCountMask == 0 && g.quiescence.Load() != nil {
			return DirectionStateQuiescent
		}
		return DirectionStateSealed
	}
	if state&directionHalfClosedBit != 0 {
		return DirectionStateHalfClosed
	}
	return DirectionStateOpen
}

// ByteOperation is a single-use direction reservation. Complete is called only
// after the delegated traffic operation has returned and stock delivery/wake-up
// has already happened.
type ByteOperation struct {
	root     *LogicalFlowRoot
	gate     *DirectionGate
	scope    byteScopeSlot
	reserved bool
	state    atomic.Uint64
}

// Progress publishes bytes accepted by the already-running delegated I/O
// operation without releasing its direction reservation. It is safe to call
// concurrently with Complete: the final progress publisher releases the
// reservation when completion has already been announced.
func (o *ByteOperation) Progress(acceptedBytes uint64) {
	if o == nil || o.root == nil || o.gate == nil || acceptedBytes == 0 {
		return
	}
	for {
		current := o.state.Load()
		if current&byteOperationCompletedBit != 0 {
			o.root.markLateByteProgressFault(o.gate.direction, o.scope)
			return
		}
		if current&byteOperationProgressMask == byteOperationProgressMask {
			o.root.markLifecycleFault(LifecycleFaultByteOperationCapacity)
			return
		}
		if o.state.CompareAndSwap(current, current+1) {
			break
		}
	}
	o.Prove()
	o.recordAccepted(acceptedBytes)
	if o.reserved {
		o.root.markDirtyDeferred()
	}
	o.releaseProgress()
}

func (r *LogicalFlowRoot) markLateByteProgressFault(direction Direction, scope byteScopeSlot) {
	if !r.beginLateProgressMutation() {
		r.postTerminalFaults.Add(1)
		return
	}
	defer r.endLateProgressMutation()
	r.markObservationFault(direction, scope, AccountingFaultCallbackLost)
	r.markLifecycleFault(LifecycleFaultLateByteProgress)
}

func (r *LogicalFlowRoot) beginLateProgressMutation() bool {
	for {
		current := r.lateProgressState.Load()
		if current&lateProgressClosedBit != 0 {
			return false
		}
		if current&lateProgressCountMask == lateProgressCountMask {
			r.markLifecycleFault(LifecycleFaultByteOperationCapacity)
			return false
		}
		if r.lateProgressState.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (r *LogicalFlowRoot) endLateProgressMutation() {
	for {
		current := r.lateProgressState.Load()
		count := current & lateProgressCountMask
		if count == 0 {
			r.markLifecycleFault(LifecycleFaultByteOperationUnderflow)
			return
		}
		next := current - 1
		if r.lateProgressState.CompareAndSwap(current, next) {
			if next == lateProgressClosedBit {
				r.finalizeTerminal()
			}
			return
		}
	}
}

func (r *LogicalFlowRoot) closeLateProgressMutations() bool {
	for {
		current := r.lateProgressState.Load()
		if current&lateProgressClosedBit != 0 {
			return current == lateProgressClosedBit
		}
		next := current | lateProgressClosedBit
		if r.lateProgressState.CompareAndSwap(current, next) {
			return next == lateProgressClosedBit
		}
	}
}

// Prove publishes an already-reserved pending byte scope once its concrete
// runtime boundary has been observed. It is intentionally separate from
// reservation so a zero-byte successful operation can still publish exact
// proof while an untouched fallback remains explicitly F2-required.
func (o *ByteOperation) Prove() {
	if o == nil || o.root == nil || o.gate == nil || !o.reserved {
		return
	}
	cell := o.root.observationCell(o.gate.direction, o.scope)
	if cell != nil && cell.state.CompareAndSwap(byteCellPending, byteCellProven) {
		o.root.markDirty()
	}
}

// RequireF2 publishes typed incompleteness for a deferred operation whose
// runtime path could not provide exact numeric proof.
func (o *ByteOperation) RequireF2() {
	if o == nil || o.root == nil || o.gate == nil || !o.reserved {
		return
	}
	if cell := o.root.observationCell(o.gate.direction, o.scope); cell != nil && cell.state.CompareAndSwap(byteCellPending, byteCellF2Required) {
		o.root.markDirty()
	}
}

func (o *ByteOperation) Complete(acceptedBytes uint64) {
	if o == nil || o.root == nil || o.gate == nil {
		return
	}
	var inFlightProgress uint64
	for {
		current := o.state.Load()
		if current&byteOperationCompletedBit != 0 {
			o.root.markLifecycleFault(LifecycleFaultDoubleByteOperationComplete)
			return
		}
		if current&byteOperationProgressMask == byteOperationProgressMask {
			o.root.markLifecycleFault(LifecycleFaultByteOperationCapacity)
			return
		}
		if o.state.CompareAndSwap(current, current+1|byteOperationCompletedBit) {
			inFlightProgress = current & byteOperationProgressMask
			break
		}
	}
	if acceptedBytes > 0 {
		o.Prove()
	} else if inFlightProgress == 0 {
		o.RequireF2()
	}
	o.recordAccepted(acceptedBytes)
	if o.reserved {
		o.root.markDirty()
	}
	o.releaseProgress()
}

func (o *ByteOperation) recordAccepted(acceptedBytes uint64) {
	if !o.reserved {
		o.gate.complete(false, o.scope, acceptedBytes)
		return
	}
	if acceptedBytes > 0 {
		o.root.addAcceptedBytes(o.gate.direction, o.scope, acceptedBytes)
		o.root.advanceByteSequence()
	}
}

func (o *ByteOperation) releaseProgress() {
	remaining := o.state.Add(^uint64(0))
	if remaining == byteOperationCompletedBit {
		o.gate.complete(o.reserved, o.scope, 0)
	}
}

func (r *LogicalFlowRoot) addAcceptedBytes(direction Direction, scope byteScopeSlot, delta uint64) {
	cell := r.observationCell(direction, scope)
	if cell == nil || cell.state.Load() != byteCellProven {
		return
	}
	counter := &cell.bytes
	for {
		current := counter.Load()
		if math.MaxUint64-current < delta {
			r.markObservationFault(direction, scope, AccountingFaultCounterOverflow)
			return
		}
		if counter.CompareAndSwap(current, current+delta) {
			return
		}
	}
}

func (r *LogicalFlowRoot) advanceByteSequence() {
	for {
		current := r.lastByteSequence.Load()
		if current == math.MaxUint64 {
			r.markAllObservationFaults(AccountingFaultSequenceOverflow)
			return
		}
		if r.lastByteSequence.CompareAndSwap(current, current+1) {
			return
		}
	}
}

func (r *LogicalFlowRoot) markLifecycleFault(reason LifecycleFault) {
	r.terminalFaultMu.Lock()
	defer r.terminalFaultMu.Unlock()
	r.markLifecycleFaultLocked(reason)
}

func (r *LogicalFlowRoot) markLifecycleFaultLocked(reason LifecycleFault) {
	r.lifecycleFault.CompareAndSwap(nil, &lifecycleFaultReceipt{reason: reason})
	for {
		current := r.phaseFault.Load()
		if current&lifecyclePhaseMask == lifecycleTerminalWord {
			r.postTerminalFaults.Add(1)
			return
		}
		if current&lifecycleFaultBit != 0 {
			return
		}
		if r.phaseFault.CompareAndSwap(current, current|lifecycleFaultBit) {
			r.markDirty()
			return
		}
	}
}

func (r *LogicalFlowRoot) markAccountingFault(reason AccountingFault) {
	r.accountingFault.CompareAndSwap(nil, &accountingFaultReceipt{reason: reason})
	r.markDirty()
}

func (r *LogicalFlowRoot) markObservationFault(direction Direction, scope byteScopeSlot, reason AccountingFault) {
	cell := r.observationCell(direction, scope)
	if cell == nil {
		r.markAccountingFault(reason)
		return
	}
	cell.fault.CompareAndSwap(nil, &accountingFaultReceipt{reason: reason})
	next := uint32(byteCellIndeterminate)
	if reason == AccountingFaultCounterOverflow {
		next = byteCellOverflowed
	}
	for {
		current := cell.state.Load()
		if current == byteCellOverflowed || current == byteCellIndeterminate || current == byteCellF2Required {
			break
		}
		if cell.state.CompareAndSwap(current, next) {
			break
		}
	}
	r.markAccountingFault(reason)
}

func (r *LogicalFlowRoot) markAllObservationFaults(reason AccountingFault) {
	for directionIndex := 0; directionIndex < 2; directionIndex++ {
		direction := DirectionUplink
		if directionIndex == 1 {
			direction = DirectionDownlink
		}
		for slot := byteScopeSlotLogicalLinkAccepted; slot < byteScopeSlotCount; slot++ {
			cell := r.observationCell(direction, slot)
			if cell != nil && cell.state.Load() != byteCellUnpopulated {
				r.markObservationFault(direction, slot, reason)
			}
		}
	}
}

func (r *LogicalFlowRoot) initializeObservation(direction Direction, scope byteScopeSlot, state uint32) {
	if cell := r.observationCell(direction, scope); cell != nil {
		cell.state.CompareAndSwap(byteCellUnpopulated, state)
	}
}

func (r *LogicalFlowRoot) observationCell(direction Direction, scope byteScopeSlot) *byteObservationCell {
	index, ok := byteObservationIndex(direction, scope)
	if !ok {
		return nil
	}
	return &r.byteObservations[index]
}

// transitionToF2Required reserves the existing direction barrier and marks the
// exact new scope in one CAS. It never controls whether stock I/O proceeds.
func (g *DirectionGate) transitionToF2Required(scope byteScopeSlot) *ByteOperation {
	return g.transitionToScope(scope, byteCellF2Required)
}

func (g *DirectionGate) transitionToDeferred(scope byteScopeSlot) *ByteOperation {
	return g.transitionToScope(scope, byteCellPending)
}

func (g *DirectionGate) transitionToScope(scope byteScopeSlot, cellState uint32) *ByteOperation {
	operation := &ByteOperation{scope: scope}
	if g == nil || g.root == nil || scope == byteScopeSlotNone {
		return operation
	}
	operation.root = g.root
	operation.gate = g
	if cellState == byteCellPending {
		g.root.initializeObservation(g.direction, scope, cellState)
	}
	encodedScope := uint64(scope) << directionScopeShift
	for {
		current := g.state.Load()
		if current&directionSealedBit != 0 {
			g.root.markLifecycleFault(LifecycleFaultByteOperationAfterSeal)
			if g.root.phase() != LifecyclePhaseTerminal {
				g.root.markObservationFault(g.direction, g.byteScope, AccountingFaultBoundaryUnproven)
			}
			return operation
		}
		currentScope := current & directionScopeMask
		if currentScope != 0 && currentScope != encodedScope {
			g.root.markObservationFault(g.direction, scope, AccountingFaultBoundaryUnproven)
			return operation
		}
		count := current & directionCountMask
		if count == directionCountMask {
			g.root.markLifecycleFault(LifecycleFaultByteOperationCapacity)
			return operation
		}
		next := current + 1
		if currentScope == 0 {
			next |= encodedScope
		}
		if g.state.CompareAndSwap(current, next) {
			operation.reserved = true
			if cellState != byteCellPending {
				g.root.initializeObservation(g.direction, scope, cellState)
			}
			g.root.markDirty()
			return operation
		}
	}
}

func (r *LogicalFlowRoot) maybeTerminal() {
	if r.liveParticipants.Load() != 0 || r.uplink.quiescence.Load() == nil || r.downlink.quiescence.Load() == nil {
		return
	}
	current := r.phaseFault.Load()
	if current != lifecycleOwnerSealedWord {
		return
	}
	r.closeOutcome()
}

func (r *LogicalFlowRoot) closeOutcome() {
	for {
		state := r.outcomeState.Load()
		if state&outcomeClosedBit != 0 {
			if state == outcomeClosedBit {
				r.finalizeTerminal()
			}
			return
		}
		next := state | outcomeClosedBit
		if r.outcomeState.CompareAndSwap(state, next) {
			if next == outcomeClosedBit {
				r.finalizeTerminal()
			}
			return
		}
	}
}

func (r *LogicalFlowRoot) finalizeTerminal() {
	r.terminalFaultMu.Lock()
	defer r.terminalFaultMu.Unlock()

	if r.phaseFault.Load() != lifecycleOwnerSealedWord {
		return
	}
	if !r.closeLateProgressMutations() {
		return
	}
	outcome := r.outcome.Load()
	if outcome == nil && !r.optionalTerminalCause {
		outcome = &outcomeReceipt{class: TerminalClassUnknown, rank: outcomeRank(TerminalClassUnknown)}
	}
	receipt := &TerminalReceipt{
		RuntimeInstanceID: r.runtimeInstanceID,
		FlowID:            r.flowID,
		Evidence:          r.completionEvidence,
		TerminalAtOffset:  time.Since(r.startedAt),
		LastByteSequence:  r.lastByteSequence.Load(),
	}
	if outcome != nil {
		receipt.TerminalClass = outcome.class
		receipt.TechnicalErrorCategory = outcome.category
	}
	receipt.publicationSequence = r.sequenceSource.Add(1)
	if !r.terminal.CompareAndSwap(nil, receipt) {
		return
	}
	if r.phaseFault.CompareAndSwap(lifecycleOwnerSealedWord, lifecycleTerminalWord) {
		r.markDirty()
	}
}

func (r *LogicalFlowRoot) phase() LifecyclePhase {
	switch r.phaseFault.Load() & lifecyclePhaseMask {
	case lifecycleOwnerSealedWord:
		return LifecyclePhaseOwnerSealed
	case lifecycleTerminalWord:
		return LifecyclePhaseTerminal
	default:
		return LifecyclePhaseOpen
	}
}

// ConsumeDirty clears the coalesced structural-publication flag.
func (r *LogicalFlowRoot) ConsumeDirty() bool {
	return r != nil && r.dirty.Swap(false)
}

func (r *LogicalFlowRoot) markDirty() {
	if r == nil {
		return
	}
	r.dirty.Store(true)
	if r.dirtySignal != nil {
		select {
		case r.dirtySignal <- struct{}{}:
		default:
		}
	}
}

func (r *LogicalFlowRoot) markDirtyDeferred() {
	if r == nil {
		return
	}
	r.dirty.Store(true)
	if r.deferredDirty != nil {
		r.deferredDirty.Store(true)
	}
}

// RetirableIndeterminate freezes late byte-progress mutations for a fully
// quiescent proof-faulted root before the registry removes it from the live
// set. A mutation already in flight postpones retirement; one starting after
// this boundary is classified as post-retirement misuse and cannot rewrite the
// frozen byte evidence.
func (r *LogicalFlowRoot) RetirableIndeterminate() bool {
	if r == nil {
		return false
	}
	r.terminalFaultMu.Lock()
	defer r.terminalFaultMu.Unlock()
	if r.liveParticipants.Load() != 0 {
		return false
	}
	state := r.phaseFault.Load()
	if state&lifecyclePhaseMask != lifecycleOwnerSealedWord ||
		state&lifecycleFaultBit == 0 ||
		r.uplink.quiescence.Load() == nil ||
		r.downlink.quiescence.Load() == nil {
		return false
	}
	return r.closeLateProgressMutations()
}

func (r *LogicalFlowRoot) View() LifecycleView {
	if r == nil {
		return LifecycleView{}
	}
	phaseFault := r.phaseFault.Load()
	accountingFault := r.accountingFault.Load()
	view := LifecycleView{
		RuntimeInstanceID:      r.runtimeInstanceID,
		FlowID:                 r.flowID,
		Phase:                  phaseFromWord(phaseFault),
		ProofState:             ProofStateComplete,
		LiveParticipantCount:   r.liveParticipants.Load(),
		UplinkState:            r.uplink.viewState(),
		DownlinkState:          r.downlink.viewState(),
		LastByteSequence:       r.lastByteSequence.Load(),
		UplinkQuiescence:       cloneQuiescenceReceipt(r.uplink.quiescence.Load()),
		DownlinkQuiescence:     cloneQuiescenceReceipt(r.downlink.quiescence.Load()),
		PostTerminalFaultCount: r.postTerminalFaults.Load(),
	}
	view.ByteObservations = r.snapshotByteObservations()
	if phaseFault&lifecycleFaultBit != 0 {
		fault := r.lifecycleFault.Load()
		view.ProofState = ProofStateIndeterminate
		if fault != nil {
			view.LifecycleFault = fault.reason
		}
	}
	if accountingFault != nil {
		view.AccountingFault = accountingFault.reason
	}
	if view.Phase == LifecyclePhaseTerminal {
		view.Terminal = cloneTerminalReceipt(r.terminal.Load())
	}
	return view
}

func (r *LogicalFlowRoot) snapshotByteObservations() []ByteObservation {
	observations := make([]ByteObservation, 0, MaxByteObservations)
	for directionIndex := 0; directionIndex < 2; directionIndex++ {
		direction := DirectionUplink
		gate := &r.uplink
		if directionIndex == 1 {
			direction = DirectionDownlink
			gate = &r.downlink
		}
		transitionScope := byteScopeSlot((gate.state.Load() & directionScopeMask) >> directionScopeShift)
		for slot := byteScopeSlotLogicalLinkAccepted; slot < byteScopeSlotCount; slot++ {
			cell := r.observationCell(direction, slot)
			if cell == nil {
				continue
			}
			for {
				state := cell.state.Load()
				if state == byteCellPending {
					break
				}
				if state == byteCellUnpopulated && transitionScope == slot {
					state = byteCellF2Required
				}
				if state == byteCellUnpopulated {
					break
				}
				observation := ByteObservation{
					Direction: direction,
					ByteScope: byteScopeForSlot(slot),
					State:     byteObservationStateForCell(state),
				}
				if state == byteCellProven {
					observation.ObservedBytes = OptionalUint64{Known: true, Value: cell.bytes.Load()}
				}
				if state == byteCellOverflowed || state == byteCellIndeterminate {
					if fault := cell.fault.Load(); fault != nil {
						observation.AccountingFault = fault.reason
					}
				}
				finalState := cell.state.Load()
				if finalState == byteCellUnpopulated && transitionScope == slot {
					finalState = byteCellF2Required
				}
				if finalState != state {
					continue
				}
				observations = append(observations, observation)
				break
			}
		}
	}
	return observations
}

func byteScopeSlotFor(scope ByteScope) byteScopeSlot {
	switch scope {
	case ByteScopeLogicalLinkAccepted:
		return byteScopeSlotLogicalLinkAccepted
	case ByteScopeDispatcherExternalLinkIO:
		return byteScopeSlotDispatcherExternalLinkIO
	case ByteScopeKernelDirectCopyAccepted:
		return byteScopeSlotKernelDirectCopyAccepted
	default:
		return byteScopeSlotNone
	}
}

func byteScopeForSlot(slot byteScopeSlot) ByteScope {
	switch slot {
	case byteScopeSlotLogicalLinkAccepted:
		return ByteScopeLogicalLinkAccepted
	case byteScopeSlotDispatcherExternalLinkIO:
		return ByteScopeDispatcherExternalLinkIO
	case byteScopeSlotKernelDirectCopyAccepted:
		return ByteScopeKernelDirectCopyAccepted
	default:
		return ByteScopeUnknown
	}
}

func byteObservationIndex(direction Direction, scope byteScopeSlot) (int, bool) {
	if scope <= byteScopeSlotNone || scope >= byteScopeSlotCount {
		return 0, false
	}
	directionIndex := 0
	if direction == DirectionDownlink {
		directionIndex = 1
	} else if direction != DirectionUplink {
		return 0, false
	}
	return directionIndex*int(byteScopeSlotCount-1) + int(scope-1), true
}

func byteObservationStateForCell(state uint32) ByteObservationState {
	switch state {
	case byteCellProven:
		return ByteObservationStateProven
	case byteCellF2Required:
		return ByteObservationStateF2Required
	case byteCellOverflowed:
		return ByteObservationStateOverflowed
	default:
		return ByteObservationStateIndeterminate
	}
}

func phaseFromWord(word uint32) LifecyclePhase {
	switch word & lifecyclePhaseMask {
	case lifecycleOwnerSealedWord:
		return LifecyclePhaseOwnerSealed
	case lifecycleTerminalWord:
		return LifecyclePhaseTerminal
	default:
		return LifecyclePhaseOpen
	}
}

func cloneQuiescenceReceipt(receipt *QuiescenceReceipt) *QuiescenceReceipt {
	if receipt == nil {
		return nil
	}
	copy := *receipt
	return &copy
}

func cloneTerminalReceipt(receipt *TerminalReceipt) *TerminalReceipt {
	if receipt == nil {
		return nil
	}
	copy := *receipt
	return &copy
}

var (
	_ task.ParticipantTracker = (*LogicalFlowRoot)(nil)
	_ task.ParticipantLease   = (*participantLease)(nil)
)
