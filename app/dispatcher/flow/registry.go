package flow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxRecords                   = 4096
	defaultMaxSeries                    = 1024
	defaultMaxEvents                    = 8192
	maxEventBatch                       = 1024
	maxTextBytes                        = 512
	maxTagBytes                         = 256
	maxIssues                           = 8
	maxHandlerHops                      = 16
	deferredProgressSyncInterval        = time.Second
	admissionClosedBit           uint64 = 1 << 63
	admissionCountMask                  = admissionClosedBit - 1
)

type Config struct {
	MaxRecords int
	MaxSeries  int
	MaxEvents  int
}

type Registry struct {
	mu sync.Mutex

	runtimeInstanceID     string
	startedAt             time.Time
	lifecycleSequence     atomic.Uint64
	pendingAdmissionDrops atomic.Uint64
	pendingCapacityDrops  atomic.Uint64
	pendingCarrierDrops   [2]atomic.Uint64
	admissionState        atomic.Uint64
	stopLifecycleSequence uint64
	maxRecords            int
	maxSeries             int
	maxEvents             int
	nextFlow              atomic.Uint64
	nextCarrier           atomic.Uint64
	nextSeries            uint64
	nextSequence          uint64
	records               map[string]*recordState
	carriers              map[string]*recordStateCarrier
	carrierOrder          []string
	droppedCarriers       uint64
	evictedCarriers       uint64
	carrierCoverage       [4]CarrierAccountingCoverage
	carrierSeries         [4]*carrierSeriesState
	carrierMembershipLost [4]bool
	recordOrder           []string
	roots                 map[string]*rootState
	series                map[string]*seriesState
	seriesByKey           map[seriesMapKey]string
	seriesOrder           []string
	events                []Event
	eventHead             int
	coverage              AccountingCoverage
	droppedFlows          uint64
	evictedRecords        uint64
	evictedSeries         uint64
	sequenceExhausted     bool
	closed                bool
	dirtySignal           chan struct{}
	pendingAdmissions     chan *pendingAdmission
	pendingCarriers       chan *carrierSidecar
	admissionsDrained     chan struct{}
	stopSignal            chan struct{}
	stopped               chan struct{}
	closeOnce             sync.Once
	admissionDrainOnce    sync.Once
	continuationsClosed   atomic.Bool
	deferredDirty         atomic.Bool
	xudpTransitionCredits atomic.Int64
}

type pendingAdmission struct {
	record     *recordState
	root       *rootState
	handle     *Handle
	onRejected func()
}

type recordState struct {
	record Record
}
type recordStateCarrier struct {
	carrier *carrierSidecar
	record  CarrierRecord
}
type carrierSeriesState struct {
	series CarrierCounterSeries
	active uint64
}

type rootState struct {
	record                         *recordState
	logical                        *LogicalFlowRoot
	observationBindings            [MaxByteObservations]observationBinding
	selection                      atomic.Pointer[selectionReceipt]
	selectedOutboundCarrier        atomic.Pointer[carrierReferenceReceipt]
	rejection                      atomic.Pointer[rejectionReceipt]
	pendingOutcome                 atomic.Pointer[pendingOutcomeReceipt]
	ownerPending                   atomic.Pointer[ownerPendingReceipt]
	ownedRootLink                  atomic.Bool
	retired                        atomic.Bool
	nextHop                        atomic.Uint32
	hops                           [maxHandlerHops]atomic.Pointer[handlerHopReceipt]
	chainFault                     atomic.Pointer[chainFaultReceipt]
	routeProofPartial              atomic.Bool
	selectionApplied               bool
	selectedOutboundCarrierApplied bool
	appliedHops                    uint32
	chainFaultApplied              bool
	routeProofPartialApplied       bool
	presenceOnly                   bool
	lastAppliedSequence            uint64
	xudp                           *XUDPScope
}

type carrierReferenceReceipt struct {
	reference string
}

type observationBinding struct {
	seriesID    string
	lastApplied uint64
	lastState   ByteObservationState
}

type handlerHopReceipt struct {
	hop                 HandlerHop
	accountingSupported bool
	carrierProof        CarrierProof
	issues              []Issue
}

type chainFaultReceipt struct {
	disposition ChainDisposition
	cutoff      uint32
}

type selectionReceipt struct {
	ruleTag              string
	outboundTag          string
	handlerType          string
	effectiveDestination string
	protocol             string
	accountingSupported  bool
	attributionSupported bool
	carrierProof         CarrierProof
	issues               []Issue
}

type rejectionReceipt struct {
	category string
}

type pendingOutcomeReceipt struct {
	class    TerminalClass
	category string
}

type ownerPendingReceipt struct {
	reason               IndeterminateReason
	effectiveDestination string
}

type seriesState struct {
	series      CounterSeries
	activeRoots uint64
}

type seriesMapKey struct {
	coordinateKnown bool
	coordinate      string
	outbound        string
	origin          Origin
	direction       Direction
	byteScope       ByteScope
}

type Handle struct {
	registry          *Registry
	runtimeInstanceID string
	flowID            string
	root              *rootState
}

// LogicalRoot returns the exact lifecycle root owned by this admission.
func (h *Handle) LogicalRoot() *LogicalFlowRoot {
	if h == nil || h.root == nil {
		return nil
	}
	return h.root.logical
}

func NewRegistry(config Config) (*Registry, error) {
	maxRecords := config.MaxRecords
	if maxRecords == 0 {
		maxRecords = defaultMaxRecords
	}
	maxSeries := config.MaxSeries
	if maxSeries == 0 {
		maxSeries = defaultMaxSeries
	}
	maxEvents := config.MaxEvents
	if maxEvents == 0 {
		maxEvents = defaultMaxEvents
	}
	if maxRecords < 1 || maxSeries < 1 || maxEvents < 1 {
		return nil, errors.New("flow registry limits must be positive")
	}

	runtimeIDBytes := make([]byte, 16)
	if _, err := rand.Read(runtimeIDBytes); err != nil {
		return nil, errors.New("generate flow runtime instance ID: " + err.Error())
	}

	registry := &Registry{
		runtimeInstanceID: hex.EncodeToString(runtimeIDBytes),
		startedAt:         time.Now(),
		maxRecords:        maxRecords,
		maxSeries:         maxSeries,
		maxEvents:         maxEvents,
		records:           make(map[string]*recordState, maxRecords),
		carriers:          make(map[string]*recordStateCarrier, maxRecords),
		roots:             make(map[string]*rootState, maxRecords),
		series:            make(map[string]*seriesState, maxSeries),
		seriesByKey:       make(map[seriesMapKey]string, maxSeries),
		dirtySignal:       make(chan struct{}, 1),
		pendingAdmissions: make(chan *pendingAdmission, maxRecords),
		pendingCarriers:   make(chan *carrierSidecar, maxRecords),
		admissionsDrained: make(chan struct{}),
		stopSignal:        make(chan struct{}),
		stopped:           make(chan struct{}),
		coverage: AccountingCoverage{
			Generation: 1,
			State:      AccountingCoverageComplete,
		},
	}
	for _, kind := range []CarrierKind{CarrierKindServerMuxFrameLink, CarrierKindClientMuxFrameLink} {
		for _, d := range []Direction{DirectionUplink, DirectionDownlink} {
			i := carrierKindDirectionIndex(kind, d)
			registry.carrierCoverage[i] = CarrierAccountingCoverage{Generation: 1, Key: CarrierCounterSeriesKey{CarrierKind: kind, Direction: d, ByteScope: ByteScopeCarrierConnectionIO}, State: AccountingCoverageComplete}
		}
	}
	registry.xudpTransitionCredits.Store(int64(maxEvents))
	go registry.runWorker()
	return registry, nil
}

func (r *Registry) AdmitTCP(ctx context.Context, source, originalDestination, protocol string, byteScope ByteScope) *Handle {
	if r == nil || !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	admission := r.prepareTCPAdmission(ctx, source, originalDestination, protocol, byteScope)
	if admission == nil {
		return nil
	}
	return r.publishAdmission(admission)
}

// AdmitUDPAssociation creates one logical root for an independently created,
// non-multiplexed Dispatch UDP link. Packet destinations remain metadata on
// that link and never become flow identity.
func (r *Registry) AdmitUDPAssociation(ctx context.Context, source, originalDestination, protocol string) *Handle {
	if r == nil || !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	admission := r.prepareNativeLinkAdmission(ctx, KindUDPAssociation, source, originalDestination, protocol, ByteScopeLogicalLinkAccepted)
	if admission == nil {
		return nil
	}
	return r.publishAdmission(admission)
}

func (r *Registry) prepareTCPAdmission(ctx context.Context, source, originalDestination, protocol string, byteScope ByteScope) *pendingAdmission {
	return r.prepareNativeLinkAdmission(ctx, KindTCP, source, originalDestination, protocol, byteScope)
}

func (r *Registry) prepareNativeLinkAdmission(ctx context.Context, kind Kind, source, originalDestination, protocol string, byteScope ByteScope) *pendingAdmission {
	flowNumber, ok := r.nextFlowNumber()
	if !ok {
		r.recordAdmissionCapacityLoss()
		return nil
	}
	flowID := r.runtimeInstanceID + "-" + encodeUint64(flowNumber)
	now := r.offsetLocked()
	marker := admissionFromContext(ctx)
	record := Record{
		RuntimeInstanceID:    r.runtimeInstanceID,
		FlowID:               flowID,
		FlowKind:             kind,
		CarrierProof:         CarrierProofNotApplicable,
		TrafficOrigin:        marker.origin,
		OriginProof:          marker.proof,
		OpaqueAndroidUID:     marker.admission.OpaqueAndroidUID,
		Source:               boundedText(source, maxTextBytes),
		OriginalDestination:  boundedText(originalDestination, maxTextBytes),
		EffectiveDestination: boundedText(originalDestination, maxTextBytes),
		Protocol:             boundedText(protocol, maxTagBytes),
		Route: RouteFacts{
			DispatchDisposition: DispatchDispositionUnknown,
			ChainCoverage:       ChainCoverageUnknown,
			ChainDisposition:    ChainDispositionUnknown,
		},
		ActivityState:      ActivityAdmitted,
		CompletionState:    CompletionOpen,
		CompletionEvidence: CompletionEvidenceNone,
		TerminalClass:      TerminalClassUnknown,
		AdmittedAtOffset:   now,
		UpdatedAtOffset:    now,
	}
	if len(marker.admission.Coordinate) > 0 {
		record.AdmissionCoordinate = OptionalBytes{Known: true, Value: cloneBytes(marker.admission.Coordinate)}
	}
	if source != "" && record.Source == "" || originalDestination != "" && record.OriginalDestination == "" || protocol != "" && record.Protocol == "" {
		addIssue(&record, IssueFieldOversize)
	}
	recordEntry := &recordState{record: record}
	logical, err := NewLogicalFlowRoot(r.runtimeInstanceID, flowID, byteScope)
	if err != nil {
		r.recordAdmissionCapacityLoss()
		return nil
	}
	// Registry records and lifecycle receipts share one monotonic runtime
	// origin so shutdown can order proof without wall-clock inference.
	logical.startedAt = r.startedAt
	logical.sequenceSource = &r.lifecycleSequence
	logical.dirtySignal = r.dirtySignal
	logical.deferredDirty = &r.deferredDirty
	recordEntry.record.ByteObservations = logical.View().ByteObservations
	root := &rootState{record: recordEntry, logical: logical}
	handle := &Handle{registry: r, runtimeInstanceID: r.runtimeInstanceID, flowID: flowID, root: root}
	return &pendingAdmission{record: recordEntry, root: root, handle: handle}
}

func (r *Registry) prepareMuxSessionAdmission(source, originalDestination, carrierReference string) *pendingAdmission {
	flowNumber, ok := r.nextFlowNumber()
	if !ok {
		r.recordAdmissionCapacityLoss()
		return nil
	}
	flowID := r.runtimeInstanceID + "-" + encodeUint64(flowNumber)
	now := r.offsetLocked()
	boundedCarrier := boundedText(carrierReference, maxTagBytes)
	boundedDestination := boundedText(originalDestination, maxTextBytes)
	boundedSource := boundedText(source, maxTextBytes)
	if boundedCarrier == "" || boundedDestination == "" || source != "" && boundedSource == "" {
		r.recordAdmissionCapacityLoss()
		return nil
	}
	record := Record{
		RuntimeInstanceID:   r.runtimeInstanceID,
		FlowID:              flowID,
		FlowKind:            KindMUXLogical,
		CarrierReference:    boundedCarrier,
		Source:              boundedSource,
		OriginalDestination: boundedDestination,
		ActivityState:       ActivityAdmitted,
		CompletionState:     CompletionOpen,
		AdmittedAtOffset:    now,
		UpdatedAtOffset:     now,
	}
	recordEntry := &recordState{record: record}
	logical, err := newLogicalFlowRoot(r.runtimeInstanceID, flowID, true, CompletionEvidenceProvenLogicalSessionClosed, ByteScopeLogicalLinkAccepted)
	if err != nil {
		r.recordAdmissionCapacityLoss()
		return nil
	}
	logical.startedAt = r.startedAt
	logical.sequenceSource = &r.lifecycleSequence
	logical.dirtySignal = r.dirtySignal
	logical.deferredDirty = &r.deferredDirty
	recordEntry.record.ByteObservations = logical.View().ByteObservations
	root := &rootState{record: recordEntry, logical: logical, presenceOnly: true}
	handle := &Handle{registry: r, runtimeInstanceID: r.runtimeInstanceID, flowID: flowID, root: root}
	return &pendingAdmission{record: recordEntry, root: root, handle: handle}
}

func (r *Registry) publishAdmission(admission *pendingAdmission) *Handle {
	if r.mu.TryLock() {
		// The traffic goroutine may publish only the O(1) uncontended case. It
		// never drains backlog, evicts records or advances coverage/events for
		// other roots; those are observer worker/read/close responsibilities.
		registered := !r.closed && len(r.pendingAdmissions) == 0 && len(r.records) < r.maxRecords && r.registerAdmissionLocked(admission)
		r.mu.Unlock()
		if registered {
			return admission.handle
		}
	}
	select {
	case r.pendingAdmissions <- admission:
		r.signalDirty()
		return admission.handle
	default:
		admission.root.retired.Store(true)
		if admission.onRejected != nil {
			admission.onRejected()
		}
		r.recordAdmissionContention()
		return nil
	}
}

func (r *Registry) registerAdmissionLocked(admission *pendingAdmission) bool {
	if admission == nil || admission.root == nil || admission.record == nil || admission.handle == nil || r.closed {
		if admission != nil && admission.root != nil {
			admission.root.retired.Store(true)
			if admission.onRejected != nil {
				admission.onRejected()
			}
		}
		return false
	}
	if len(r.records) >= r.maxRecords && !r.evictOldestTerminalRecordLocked() {
		admission.root.retired.Store(true)
		if admission.onRejected != nil {
			admission.onRejected()
		}
		r.addDroppedFlowsLocked(1)
		r.loseCoverageLocked(DiscontinuityAccountingCapacityExceeded)
		return false
	}
	flowID := admission.handle.flowID
	r.records[flowID] = admission.record
	r.recordOrder = append(r.recordOrder, flowID)
	r.roots[flowID] = admission.root
	r.appendRecordEventLocked(EventAdmitted, admission.record)
	admission.root.logical.markDirty()
	return true
}

func (r *Registry) drainAdmissionsLocked() {
	for {
		select {
		case admission := <-r.pendingAdmissions:
			r.registerAdmissionLocked(admission)
		default:
			return
		}
	}
}

func (r *Registry) nextFlowNumber() (uint64, bool) {
	for {
		current := r.nextFlow.Load()
		if current == math.MaxUint64 {
			return 0, false
		}
		if r.nextFlow.CompareAndSwap(current, current+1) {
			return current + 1, true
		}
	}
}

func (r *Registry) beginAdmission() bool {
	for {
		state := r.admissionState.Load()
		if state&admissionClosedBit != 0 || state&admissionCountMask == admissionCountMask {
			return false
		}
		if r.admissionState.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (r *Registry) endAdmission() {
	for {
		state := r.admissionState.Load()
		count := state & admissionCountMask
		if count == 0 {
			return
		}
		next := state - 1
		if r.admissionState.CompareAndSwap(state, next) {
			if next == admissionClosedBit {
				r.admissionDrainOnce.Do(func() { close(r.admissionsDrained) })
			}
			return
		}
	}
}

func (r *Registry) closeAdmissions() {
	for {
		state := r.admissionState.Load()
		if state&admissionClosedBit != 0 {
			break
		}
		if r.admissionState.CompareAndSwap(state, state|admissionClosedBit) {
			break
		}
	}
	if r.admissionState.Load() == admissionClosedBit {
		r.admissionDrainOnce.Do(func() { close(r.admissionsDrained) })
	}
	<-r.admissionsDrained
}

func (r *Registry) recordAdmissionContention() {
	r.incrementPendingLoss(&r.pendingAdmissionDrops)
	r.signalDirty()
}

func (r *Registry) recordAdmissionCapacityLoss() {
	r.incrementPendingLoss(&r.pendingCapacityDrops)
	r.signalDirty()
}

func (r *Registry) incrementPendingLoss(counter *atomic.Uint64) {
	for {
		current := counter.Load()
		if current == math.MaxUint64 || counter.CompareAndSwap(current, current+1) {
			break
		}
	}
}

func (r *Registry) signalDirty() {
	select {
	case r.dirtySignal <- struct{}{}:
	default:
	}
}

func (r *Registry) applyPendingAdmissionLossLocked() {
	for i := range r.pendingCarrierDrops {
		if lost := r.pendingCarrierDrops[i].Swap(0); lost != 0 {
			r.addDroppedCarriersLocked(lost)
			kind := CarrierKindServerMuxFrameLink
			if i == 1 {
				kind = CarrierKindClientMuxFrameLink
			}
			r.loseCarrierMembershipLockedKind(kind)
		}
	}
	if lost := r.pendingCapacityDrops.Swap(0); lost != 0 {
		r.addDroppedFlowsLocked(lost)
		r.loseCoverageLocked(DiscontinuityAccountingCapacityExceeded)
	}
	if lost := r.pendingAdmissionDrops.Swap(0); lost != 0 {
		r.addDroppedFlowsLocked(lost)
		r.loseCoverageLocked(DiscontinuityAdmissionContention)
	}
}

func (r *Registry) addDroppedFlowsLocked(delta uint64) {
	if math.MaxUint64-r.droppedFlows < delta {
		r.droppedFlows = math.MaxUint64
		return
	}
	r.droppedFlows += delta
}

func (r *Registry) Owns(handle *Handle) bool {
	if handle == nil || handle.registry != r || handle.runtimeInstanceID != r.runtimeInstanceID {
		return false
	}
	return !r.continuationsClosed.Load() && handle.root != nil && !handle.root.retired.Load()
}

func (r *Registry) MarkAccountingCallbackLost() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loseCoverageLocked(DiscontinuityAccountingCallbackLost)
}

func (h *Handle) TrackOwnedRootLink() {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	h.root.ownedRootLink.Store(true)
	h.root.logical.markDirty()
}

func (h *Handle) SelectRoot(ruleTag, outboundTag, handlerType, effectiveDestination, protocol string, accountingSupported bool, carrierProof CarrierProof, issues ...Issue) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	receiptIssues := append([]Issue(nil), issues...)
	attributionSupported := outboundTag != "" && len(outboundTag) <= maxTagBytes
	if len(ruleTag) > maxTagBytes || len(outboundTag) > maxTagBytes || len(handlerType) > maxTagBytes || len(effectiveDestination) > maxTextBytes || len(protocol) > maxTagBytes {
		receiptIssues = append(receiptIssues, IssueFieldOversize)
	}
	if !attributionSupported {
		receiptIssues = append(receiptIssues, IssueSelectedOutboundUnknown)
	}
	receipt := &selectionReceipt{
		ruleTag:              boundedText(ruleTag, maxTagBytes),
		outboundTag:          boundedText(outboundTag, maxTagBytes),
		handlerType:          boundedText(handlerType, maxTagBytes),
		effectiveDestination: boundedText(effectiveDestination, maxTextBytes),
		protocol:             boundedText(protocol, maxTagBytes),
		accountingSupported:  accountingSupported,
		attributionSupported: attributionSupported,
		carrierProof:         carrierProof,
		issues:               receiptIssues,
	}
	if h.root.selection.CompareAndSwap(nil, receipt) {
		if !accountingSupported {
			h.root.logical.markAccountingFault(AccountingFaultBoundaryUnproven)
		}
		h.root.logical.markDirty()
	}
}

func (h *Handle) AppendHop(tag, handlerType string, entryKind HandlerEntryKind, ruleTag string) {
	if h == nil || h.root == nil || h.root.logical == nil || h.root.retired.Load() {
		return
	}
	h.root.recordHop(&handlerHopReceipt{hop: HandlerHop{
		HandlerTag:           boundedText(tag, maxTagBytes),
		HandlerType:          boundedText(handlerType, maxTagBytes),
		EntryKind:            entryKind,
		MatchedNativeRuleTag: boundedText(ruleTag, maxTagBytes),
	}, accountingSupported: true})
}

func (h *Handle) BeginRedispatch(tag, handlerType, ruleTag string, accountingSupported bool, carrierProof CarrierProof, issues ...Issue) {
	if h == nil || h.root == nil || h.root.logical == nil || h.root.retired.Load() {
		return
	}
	h.root.recordHop(&handlerHopReceipt{
		hop: HandlerHop{
			HandlerTag:           boundedText(tag, maxTagBytes),
			HandlerType:          boundedText(handlerType, maxTagBytes),
			EntryKind:            HandlerEntryLoopbackRedispatch,
			MatchedNativeRuleTag: boundedText(ruleTag, maxTagBytes),
		},
		accountingSupported: accountingSupported,
		carrierProof:        carrierProof,
		issues:              append([]Issue(nil), issues...),
	})
}

func (root *rootState) recordHop(receipt *handlerHopReceipt) {
	if root == nil || root.logical == nil || receipt == nil || root.retired.Load() {
		return
	}
	var index uint32
	for {
		index = root.nextHop.Load()
		if index >= maxHandlerHops {
			root.chainFault.CompareAndSwap(nil, &chainFaultReceipt{disposition: ChainDispositionDepthExceeded, cutoff: maxHandlerHops})
			root.logical.markDirty()
			return
		}
		if root.nextHop.CompareAndSwap(index, index+1) {
			break
		}
	}
	root.hops[index].Store(receipt)
	if root.retired.Load() {
		root.logical.markLifecycleFault(LifecycleFaultContinuationStaleRoot)
	}
	root.logical.markDirty()
}

// RecordOutcome publishes a child-owner outcome without sealing the root owner.
func (h *Handle) RecordOutcome(class TerminalClass, category string) {
	if h == nil || h.root == nil || h.root.logical == nil || h.root.retired.Load() {
		return
	}
	h.root.logical.RecordOutcome(class, category)
}

func (r *Registry) markRootAccountingIndeterminateLocked(root *rootState, _ DiscontinuityReason) {
	root.logical.markAllObservationFaults(AccountingFaultBoundaryUnproven)
}

func (h *Handle) RecordDialerProxy(tag, handlerType string) {
	h.AppendHop(tag, handlerType, HandlerEntryDialerProxy, "")
}

func (h *Handle) markRouteProofPartial() {
	if h == nil || h.root == nil || h.root.logical == nil || h.root.retired.Load() {
		return
	}
	h.root.routeProofPartial.Store(true)
	h.root.logical.markDirty()
}

func (h *Handle) Rejected(category string) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	receipt := &rejectionReceipt{category: boundedCategory(category)}
	h.root.rejection.CompareAndSwap(nil, receipt)
	if !h.root.ownedRootLink.Load() {
		h.root.logical.Uplink().Seal()
		h.root.logical.Downlink().Seal()
		h.root.logical.Uplink().MarkDrained()
		h.root.logical.Downlink().MarkDrained()
	}
	h.root.logical.SealOwner(TerminalClassLocalRejection, receipt.category)
}

// RejectedByExternalOwner records pre-invocation rejection but leaves owner
// sealing to the external class after its existing close action.
func (h *Handle) RejectedByExternalOwner(category string) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	receipt := &rejectionReceipt{category: boundedCategory(category)}
	h.root.rejection.CompareAndSwap(nil, receipt)
	h.root.logical.RecordOutcome(TerminalClassLocalRejection, receipt.category)
}

func (h *Handle) AddUplink(bytes uint64)   { h.addBytes(bytes, true) }
func (h *Handle) AddDownlink(bytes uint64) { h.addBytes(bytes, false) }

func (h *Handle) addBytes(bytes uint64, uplink bool) {
	if h == nil || h.root == nil || h.root.logical == nil || bytes == 0 {
		return
	}
	gate := h.root.logical.Downlink()
	if uplink {
		gate = h.root.logical.Uplink()
	}
	gate.recordAccepted(bytes)
}

func (h *Handle) MarkAccountingBoundaryUnproven() {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	h.root.logical.markAllObservationFaults(AccountingFaultBoundaryUnproven)
}

func (h *Handle) MarkDirectionAccountingBoundaryUnproven(direction Direction) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	gate := h.root.logical.Downlink()
	if direction == DirectionUplink {
		gate = h.root.logical.Uplink()
	} else if direction != DirectionDownlink {
		return
	}
	h.root.logical.markObservationFault(direction, gate.byteScope, AccountingFaultBoundaryUnproven)
}

// BeginF2RequiredBytePath atomically reserves the existing direction lifecycle
// and publishes an exact typed-incomplete scope. The caller must Complete the
// returned operation after the stock I/O operation exits, even though PR-F1
// supplies no numeric bytes for this scope.
func (h *Handle) BeginF2RequiredBytePath(direction Direction, scope ByteScope) *ByteOperation {
	if h == nil || h.root == nil || h.root.logical == nil {
		return &ByteOperation{}
	}
	slot := byteScopeSlotFor(scope)
	if slot == byteScopeSlotNone {
		h.root.logical.markAllObservationFaults(AccountingFaultBoundaryUnproven)
		return &ByteOperation{}
	}
	gate := h.root.logical.Downlink()
	if direction == DirectionUplink {
		gate = h.root.logical.Uplink()
	} else if direction != DirectionDownlink {
		return &ByteOperation{}
	}
	return gate.transitionToF2Required(slot)
}

// BeginDeferredBytePath reserves the existing direction lifecycle without
// publishing a scope state. The concrete runtime path must call Prove or
// RequireF2 before Complete, so observers never see an F2-to-proven upgrade.
func (h *Handle) BeginDeferredBytePath(direction Direction, scope ByteScope) *ByteOperation {
	if h == nil || h.root == nil || h.root.logical == nil {
		return &ByteOperation{}
	}
	slot := byteScopeSlotFor(scope)
	if slot == byteScopeSlotNone {
		h.root.logical.markAllObservationFaults(AccountingFaultBoundaryUnproven)
		return &ByteOperation{}
	}
	gate := h.root.logical.Downlink()
	if direction == DirectionUplink {
		gate = h.root.logical.Uplink()
	} else if direction != DirectionDownlink {
		return &ByteOperation{}
	}
	return gate.transitionToDeferred(slot)
}

// SubmitError implements session.TrackedRequestErrorFeedback without retaining
// error strings, destinations, or credentials.
func (h *Handle) SubmitError(err error) {
	if h == nil || h.root == nil || h.root.logical == nil || err == nil {
		return
	}
	class, _ := outcomeFromError(err)
	category := classifyError(err)
	h.root.pendingOutcome.CompareAndSwap(nil, &pendingOutcomeReceipt{class: class, category: category})
	h.RecordOutcome(class, category)
	h.root.logical.markDirty()
}

func (h *Handle) HandlerReturned(ctx context.Context, effectiveDestination string) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	reason := IndeterminateHandlerReturnedUnproven
	if ctx != nil && ctx.Err() != nil {
		reason = IndeterminateCancellationRequested
	}
	h.root.ownerPending.CompareAndSwap(nil, &ownerPendingReceipt{
		reason:               reason,
		effectiveDestination: boundedText(effectiveDestination, maxTextBytes),
	})
	class, category := TerminalClassCompleted, ""
	if pending := h.root.pendingOutcome.Load(); pending != nil {
		class, category = pending.class, pending.category
	} else if ctx != nil && ctx.Err() != nil {
		class, category = outcomeFromError(ctx.Err())
	}
	h.root.logical.SealOwner(class, category)
}

func (h *Handle) UplinkQuiesced()   { h.directionQuiesced(true) }
func (h *Handle) DownlinkQuiesced() { h.directionQuiesced(false) }

func (h *Handle) directionQuiesced(uplink bool) {
	if h == nil || h.root == nil || h.root.logical == nil {
		return
	}
	gate := h.root.logical.Downlink()
	if uplink {
		gate = h.root.logical.Uplink()
	}
	gate.Seal()
	gate.MarkDrained()
}

func (r *Registry) runWorker() {
	defer close(r.stopped)
	ticker := time.NewTicker(deferredProgressSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopSignal:
			r.mu.Lock()
			r.syncAllLocked()
			r.mu.Unlock()
			return
		default:
		}
		select {
		case <-r.dirtySignal:
			r.mu.Lock()
			r.syncDirtyLocked()
			r.mu.Unlock()
		case <-ticker.C:
			if r.deferredDirty.Swap(false) {
				r.mu.Lock()
				r.syncDirtyLocked()
				r.mu.Unlock()
			}
		case <-r.stopSignal:
			r.mu.Lock()
			r.syncAllLocked()
			r.mu.Unlock()
			return
		}
	}
}

func (r *Registry) syncDirtyLocked() {
	r.applyPendingAdmissionLossLocked()
	r.drainAdmissionsLocked()
	r.drainCarrierAdmissionsLocked()
	r.syncCarriersLocked()
	for _, flowID := range r.orderedRootIDsLocked() {
		root := r.roots[flowID]
		if root.logical != nil && root.logical.ConsumeDirty() {
			r.syncRootLocked(flowID, root)
		}
	}
}

func (r *Registry) syncAllLocked() {
	r.applyPendingAdmissionLossLocked()
	r.drainAdmissionsLocked()
	r.drainCarrierAdmissionsLocked()
	r.syncCarriersLocked()
	for _, flowID := range r.orderedRootIDsLocked() {
		root := r.roots[flowID]
		if root.logical != nil {
			root.logical.ConsumeDirty()
			r.syncRootLocked(flowID, root)
		}
	}
}

func (r *Registry) orderedRootIDsLocked() []string {
	ids := make([]string, 0, len(r.roots))
	for flowID := range r.roots {
		ids = append(ids, flowID)
	}
	sort.Strings(ids)
	return ids
}

func (r *Registry) syncRootLocked(flowID string, root *rootState) {
	if root == nil || root.logical == nil || r.roots[flowID] != root {
		return
	}
	record := &root.record.record
	// Read the lifecycle barrier before loading route receipts. Selection and
	// hop receipts are published before traffic can reach terminal. Reading
	// them first allowed a worker to miss a concurrent receipt, then observe a
	// later terminal state and retire the root without ever attaching its byte
	// series.
	lifecycleBarrierView := root.logical.View()
	changed := r.applySelectionLocked(root)
	if root.xudp != nil && root.xudp.syncLocked(root, r.offsetLocked()) {
		changed = true
	}
	if r.applySelectedOutboundCarrierLocked(root) {
		changed = true
	}
	if r.applyHopsLocked(root) {
		changed = true
	}

	// Route receipts may have invalidated an exact byte boundary. Refresh the
	// fixed atomic cells before applying their independent series deltas. This
	// newer view must not authorize retirement: a route receipt can race after
	// the barrier and before the route loads above, while terminal becomes
	// visible here. The next pass will then observe both in order.
	accountingView := root.logical.View()
	if r.syncByteObservationsLocked(root, accountingView) {
		changed = true
	}

	if rejection := root.rejection.Load(); rejection != nil {
		record.Route.DispatchDisposition = DispatchDispositionRejectedLocally
		if lifecycleBarrierView.Phase != LifecyclePhaseTerminal {
			r.indeterminateLocked(root, IndeterminateLocalRejectionDraining)
		}
	}
	if pending := root.ownerPending.Load(); pending != nil && pending.effectiveDestination != "" {
		record.EffectiveDestination = pending.effectiveDestination
	}
	if changed {
		record.UpdatedAtOffset = r.offsetLocked()
		r.appendRecordEventLocked(EventUpdated, root.record)
	}

	// Runtime stop is sticky at the publication boundary. A terminal receipt
	// created no later than the stop boundary remains valid even if the worker
	// had not copied it yet. Later owner receipts cannot rewrite RUNTIME_STOPPED.
	r.applyLifecycleBarrierLocked(flowID, root, lifecycleBarrierView)
}

func (r *Registry) applySelectedOutboundCarrierLocked(root *rootState) bool {
	if root.selectedOutboundCarrierApplied {
		return false
	}
	receipt := root.selectedOutboundCarrier.Load()
	if receipt == nil {
		return false
	}
	root.selectedOutboundCarrierApplied = true
	root.record.record.SelectedOutboundCarrierReference = receipt.reference
	return true
}

func (r *Registry) applyLifecycleBarrierLocked(flowID string, root *rootState, view LifecycleView) {
	if r.closed {
		if view.Phase == LifecyclePhaseTerminal && view.Terminal != nil && view.Terminal.publicationSequence < r.stopLifecycleSequence {
			evidence := view.Terminal.Evidence
			if root.rejection.Load() != nil {
				evidence = CompletionEvidenceLocalRejectionBeforeInvoke
			}
			r.terminalLocked(flowID, root, view.Terminal.TerminalClass, view.Terminal.TechnicalErrorCategory, evidence)
			return
		}
		r.indeterminateLocked(root, IndeterminateRuntimeStopped)
		return
	}
	if view.Phase == LifecyclePhaseTerminal && view.Terminal != nil {
		evidence := view.Terminal.Evidence
		if root.rejection.Load() != nil {
			evidence = CompletionEvidenceLocalRejectionBeforeInvoke
		}
		r.terminalLocked(flowID, root, view.Terminal.TerminalClass, view.Terminal.TechnicalErrorCategory, evidence)
		return
	}
	if view.ProofState == ProofStateIndeterminate {
		reason := IndeterminateCompletionCallbackLost
		if view.LifecycleFault != "" {
			reason = IndeterminateReason(view.LifecycleFault)
		}
		r.indeterminateLocked(root, reason)
		if view.LiveParticipantCount == 0 && view.Phase == LifecyclePhaseOwnerSealed &&
			view.UplinkQuiescence != nil && view.DownlinkQuiescence != nil &&
			root.logical.RetirableIndeterminate() {
			frozenView := root.logical.View()
			if r.syncByteObservationsLocked(root, frozenView) {
				root.record.record.UpdatedAtOffset = r.offsetLocked()
				r.appendRecordEventLocked(EventUpdated, root.record)
			}
			r.retireIndeterminateLocked(flowID, root)
			return
		}
	} else if view.Phase == LifecyclePhaseOwnerSealed && !root.presenceOnly {
		reason := IndeterminateHandlerReturnedUnproven
		if pending := root.ownerPending.Load(); pending != nil && pending.reason != "" {
			reason = pending.reason
		}
		r.indeterminateLocked(root, reason)
	} else if view.UplinkState == DirectionStateQuiescent || view.DownlinkState == DirectionStateQuiescent {
		reason := IndeterminateOneDirectionClosed
		if view.UplinkState == DirectionStateQuiescent && view.DownlinkState == DirectionStateQuiescent {
			reason = IndeterminateHandlerInvocationStillRunning
		}
		r.indeterminateLocked(root, reason)
	}
}

func (r *Registry) syncByteObservationsLocked(root *rootState, view LifecycleView) bool {
	record := &root.record.record
	observations := cloneByteObservations(view.ByteObservations)
	if view.LastByteSequence < root.lastAppliedSequence {
		r.loseCoverageLocked(DiscontinuityAccountingCallbackLost)
	}
	if r.coverage.State != AccountingCoverageComplete {
		for index := range observations {
			if observations[index].State == ByteObservationStateProven {
				observations[index].State = ByteObservationStateIndeterminate
				observations[index].ObservedBytes = OptionalUint64{}
			}
		}
	}

	changed := !byteObservationsEqual(record.ByteObservations, observations)
	record.ByteObservations = observations
	for index := range observations {
		observation := &observations[index]
		slot := byteScopeSlotFor(observation.ByteScope)
		bindingIndex, ok := byteObservationIndex(observation.Direction, slot)
		if !ok {
			continue
		}
		binding := &root.observationBindings[bindingIndex]
		if observation.State == ByteObservationStateF2Required {
			addIssue(record, IssueDirectSpliceF2Required)
		} else if observation.State == ByteObservationStateIndeterminate || observation.State == ByteObservationStateOverflowed {
			addIssue(record, IssueWriteAcceptanceUnknown)
		}
		if !root.selectionApplied || r.coverage.State != AccountingCoverageComplete {
			continue
		}

		if binding.seriesID == "" {
			seriesID, capacityExceeded := r.attachSeriesLocked(record, *observation)
			if capacityExceeded {
				addIssue(record, IssueAccountingCapacityExceeded)
			}
			if seriesID == "" {
				continue
			}
			binding.seriesID = seriesID
			binding.lastState = observation.State
			if observation.ObservedBytes.Known {
				binding.lastApplied = observation.ObservedBytes.Value
				if observation.ObservedBytes.Value != 0 && record.ActivityState == ActivityDispatched {
					record.ActivityState = ActivityActive
					record.ActiveAtOffset = r.offsetLocked()
					changed = true
				}
			}
			continue
		}

		series := r.series[binding.seriesID]
		if series == nil {
			r.loseCoverageLocked(DiscontinuityAccountingCallbackLost)
			continue
		}
		if observation.State != ByteObservationStateProven {
			if binding.lastState != observation.State {
				r.markSeriesObservationStateLocked(series, *observation)
				binding.lastState = observation.State
			}
			continue
		}
		if binding.lastState != ByteObservationStateProven || !observation.ObservedBytes.Known || observation.ObservedBytes.Value < binding.lastApplied {
			r.loseCoverageLocked(DiscontinuityAccountingCallbackLost)
			continue
		}
		delta := observation.ObservedBytes.Value - binding.lastApplied
		if delta != 0 {
			r.addSeriesBytesLocked(series, delta)
			binding.lastApplied = observation.ObservedBytes.Value
			changed = true
			if record.ActivityState == ActivityDispatched {
				record.ActivityState = ActivityActive
				record.ActiveAtOffset = r.offsetLocked()
			}
		}
	}
	if r.coverage.State != AccountingCoverageComplete {
		for index := range record.ByteObservations {
			if record.ByteObservations[index].State == ByteObservationStateProven {
				record.ByteObservations[index].State = ByteObservationStateIndeterminate
				record.ByteObservations[index].ObservedBytes = OptionalUint64{}
				changed = true
			}
		}
	}
	root.lastAppliedSequence = view.LastByteSequence
	return changed
}

func (r *Registry) markSeriesObservationStateLocked(state *seriesState, observation ByteObservation) {
	reason := DiscontinuityAccountingScopeUnproven
	seriesStateValue := SeriesStateIndeterminate
	switch observation.State {
	case ByteObservationStateF2Required:
		reason = DiscontinuityF2Required
		seriesStateValue = SeriesStateF2Required
	case ByteObservationStateOverflowed:
		reason = DiscontinuityCounterOverflow
		seriesStateValue = SeriesStateOverflowed
	}
	state.series.State = seriesStateValue
	state.series.CumulativeBytes = OptionalUint64{}
	state.series.DiscontinuityReason = reason
	state.series.SampledAtOffset = r.offsetLocked()
	r.appendSeriesEventLocked(EventCoverageDiscontinuity, state, reason)
}

func (r *Registry) detachRootSeriesLocked(root *rootState, now time.Duration) {
	for index := range root.observationBindings {
		binding := &root.observationBindings[index]
		if binding.seriesID == "" {
			continue
		}
		series := r.series[binding.seriesID]
		if series == nil || series.activeRoots == 0 {
			r.loseCoverageLocked(DiscontinuityAccountingCallbackLost)
			binding.seriesID = ""
			continue
		}
		series.activeRoots--
		if series.series.ActiveFlowCount.Known {
			if series.series.ActiveFlowCount.Value == 0 {
				r.loseCoverageLocked(DiscontinuityAccountingCallbackLost)
			} else {
				series.series.ActiveFlowCount.Value--
			}
		}
		series.series.SampledAtOffset = now
		binding.seriesID = ""
	}
}

func (r *Registry) applyHopsLocked(root *rootState) bool {
	changed := false
	for root.appliedHops < maxHandlerHops {
		receipt := root.hops[root.appliedHops].Load()
		if receipt == nil {
			break
		}
		root.appliedHops++
		record := &root.record.record
		beforeLen := len(record.Route.KnownHandlerChain)
		beforeDisposition := record.Route.ChainDisposition
		r.appendHopLocked(record, receipt.hop)
		if !root.presenceOnly && receipt.carrierProof != "" {
			record.CarrierProof = mergeCarrierProof(record.CarrierProof, receipt.carrierProof)
		}
		if !root.presenceOnly {
			for _, issue := range receipt.issues {
				addIssue(record, issue)
			}
		}
		if !receipt.accountingSupported {
			r.markRootAccountingIndeterminateLocked(root, DiscontinuityAccountingScopeUnproven)
		}
		if len(record.Route.KnownHandlerChain) != beforeLen || record.Route.ChainDisposition != beforeDisposition ||
			!root.presenceOnly && (receipt.carrierProof != "" || len(receipt.issues) != 0) || !receipt.accountingSupported {
			changed = true
		}
	}
	if fault := root.chainFault.Load(); fault != nil && !root.chainFaultApplied && root.appliedHops >= fault.cutoff {
		root.chainFaultApplied = true
		record := &root.record.record
		if record.Route.ChainDisposition != ChainDispositionCycleDetected {
			record.Route.ChainDisposition = fault.disposition
			record.Route.ChainCoverage = ChainCoveragePartial
			record.Route.TerminalHandlerTag = ""
			if !root.presenceOnly {
				record.CarrierProof = CarrierProofUnknown
			}
			changed = true
		}
	}
	if root.routeProofPartial.Load() && !root.routeProofPartialApplied {
		root.routeProofPartialApplied = true
		record := &root.record.record
		record.Route.ChainCoverage = ChainCoveragePartial
		record.Route.TerminalHandlerTag = ""
		if !root.presenceOnly {
			record.CarrierProof = CarrierProofUnknown
			addIssue(record, IssueDetourLineagePending)
		}
		changed = true
	}
	return changed
}

func (r *Registry) applySelectionLocked(root *rootState) bool {
	if root.selectionApplied {
		return false
	}
	selection := root.selection.Load()
	if selection == nil {
		return false
	}
	root.selectionApplied = true
	record := &root.record.record
	record.Route.MatchedNativeRuleTag = selection.ruleTag
	record.Route.SelectedTopLevelOutboundTag = selection.outboundTag
	record.Route.SelectedHandlerType = selection.handlerType
	record.Route.DispatchDisposition = DispatchDispositionInvoked
	if !root.presenceOnly {
		record.Route.ChainCoverage = ChainCoveragePartial
		record.Route.ChainDisposition = ChainDispositionOK
	}
	r.appendHopLocked(record, HandlerHop{HandlerTag: selection.outboundTag, HandlerType: selection.handlerType, EntryKind: HandlerEntryRootSelection, MatchedNativeRuleTag: selection.ruleTag})
	if selection.effectiveDestination != "" {
		record.EffectiveDestination = selection.effectiveDestination
	}
	if !root.presenceOnly && selection.protocol != "" {
		record.Protocol = selection.protocol
	}
	if !root.presenceOnly && selection.carrierProof != "" {
		record.CarrierProof = mergeCarrierProof(record.CarrierProof, selection.carrierProof)
	}
	if !root.presenceOnly {
		addIssue(record, IssueTerminalUnproven)
		for _, issue := range selection.issues {
			addIssue(record, issue)
		}
	}
	record.DispatchedAtOffset = r.offsetLocked()
	record.ActivityState = ActivityDispatched
	if !selection.accountingSupported {
		root.logical.markAllObservationFaults(AccountingFaultBoundaryUnproven)
		return true
	}
	if !selection.attributionSupported {
		r.loseCoverageLocked(DiscontinuityAccountingScopeUnproven)
	}
	return true
}

func (r *Registry) retireIndeterminateLocked(flowID string, root *rootState) {
	r.detachRootSeriesLocked(root, r.offsetLocked())
	root.retired.Store(true)
	delete(r.roots, flowID)
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	r.syncAllLocked()
	takenAt := r.offsetLocked()
	snapshot := Snapshot{
		RuntimeInstanceID:              r.runtimeInstanceID,
		Watermark:                      r.nextSequence,
		TakenAtOffset:                  takenAt,
		AccountingCoverage:             r.coverage,
		DroppedFlowCount:               r.droppedFlows,
		EvictedRecordCount:             r.evictedRecords,
		EvictedSeriesCount:             r.evictedSeries,
		Records:                        make([]Record, 0, len(r.records)),
		CounterSeries:                  make([]CounterSeries, 0, len(r.series)),
		CarrierRecords:                 make([]CarrierRecord, 0, len(r.carriers)),
		CarrierAccountingCoverage:      append([]CarrierAccountingCoverage(nil), r.carrierCoverage[:]...),
		DroppedCarrierObservationCount: r.droppedCarriers,
		EvictedCarrierRecordCount:      r.evictedCarriers,
	}
	for _, id := range r.recordOrder {
		if state := r.records[id]; state != nil {
			snapshot.Records = append(snapshot.Records, cloneRecord(state.record))
		}
	}
	for _, id := range r.seriesOrder {
		if state := r.series[id]; state != nil {
			series := cloneSeries(state.series)
			series.SampledAtOffset = takenAt
			snapshot.CounterSeries = append(snapshot.CounterSeries, series)
		}
	}
	for _, id := range r.carrierOrder {
		if state := r.carriers[id]; state != nil {
			snapshot.CarrierRecords = append(snapshot.CarrierRecords, cloneCarrierRecord(state.record))
		}
	}
	for _, state := range r.carrierSeries {
		if state != nil {
			series := state.series
			series.SampledAtOffset = takenAt
			snapshot.CarrierCounterSeries = append(snapshot.CarrierCounterSeries, series)
		}
	}
	r.mu.Unlock()
	sort.Slice(snapshot.CounterSeries, func(i, j int) bool {
		left, right := snapshot.CounterSeries[i], snapshot.CounterSeries[j]
		if left.Key.SelectedTopLevelOutboundTag != right.Key.SelectedTopLevelOutboundTag {
			return left.Key.SelectedTopLevelOutboundTag < right.Key.SelectedTopLevelOutboundTag
		}
		if left.Key.TrafficOrigin != right.Key.TrafficOrigin {
			return left.Key.TrafficOrigin < right.Key.TrafficOrigin
		}
		if string(left.Key.AdmissionCoordinate.Value) != string(right.Key.AdmissionCoordinate.Value) {
			return string(left.Key.AdmissionCoordinate.Value) < string(right.Key.AdmissionCoordinate.Value)
		}
		if left.Key.Direction != right.Key.Direction {
			return left.Key.Direction < right.Key.Direction
		}
		if left.Key.ByteScope != right.Key.ByteScope {
			return left.Key.ByteScope < right.Key.ByteScope
		}
		return left.SeriesID < right.SeriesID
	})
	sort.Slice(snapshot.CarrierCounterSeries, func(i, j int) bool {
		a, b := snapshot.CarrierCounterSeries[i], snapshot.CarrierCounterSeries[j]
		if a.Key.CarrierKind != b.Key.CarrierKind {
			return a.Key.CarrierKind < b.Key.CarrierKind
		}
		if a.Key.Direction != b.Key.Direction {
			return a.Key.Direction < b.Key.Direction
		}
		if a.Key.ByteScope != b.Key.ByteScope {
			return a.Key.ByteScope < b.Key.ByteScope
		}
		return a.SeriesID < b.SeriesID
	})
	sort.Slice(snapshot.CarrierAccountingCoverage, func(i, j int) bool {
		a, b := snapshot.CarrierAccountingCoverage[i], snapshot.CarrierAccountingCoverage[j]
		if a.Key.CarrierKind != b.Key.CarrierKind {
			return a.Key.CarrierKind < b.Key.CarrierKind
		}
		if a.Key.Direction != b.Key.Direction {
			return a.Key.Direction < b.Key.Direction
		}
		return a.Key.ByteScope < b.Key.ByteScope
	})
	return snapshot
}

func (r *Registry) EventsAfter(after uint64, limit int) EventBatch {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncAllLocked()
	if limit <= 0 || limit > maxEventBatch {
		limit = maxEventBatch
	}
	batch := EventBatch{
		RuntimeInstanceID:        r.runtimeInstanceID,
		RequestedAfterSequence:   after,
		AvailableThroughSequence: r.nextSequence,
		DeliveredThroughSequence: after,
		GapReason:                EventGapNone,
	}
	if r.sequenceExhausted {
		batch.ResyncRequired = true
		batch.GapReason = EventGapSequenceExhausted
	}
	if len(r.events) > 0 && after < r.events[r.eventHead].Sequence-1 {
		batch.ResyncRequired = true
		batch.GapReason = EventGapRetentionExceeded
	}
	for index := 0; index < len(r.events); index++ {
		event := r.events[(r.eventHead+index)%len(r.events)]
		if event.Sequence <= after {
			continue
		}
		batch.Events = append(batch.Events, cloneEvent(event))
		batch.DeliveredThroughSequence = event.Sequence
		if len(batch.Events) == limit {
			break
		}
	}
	return batch
}

func (r *Registry) Close() {
	r.closeOnce.Do(func() {
		r.continuationsClosed.Store(true)
		r.closeAdmissions()
		r.mu.Lock()
		r.applyPendingAdmissionLossLocked()
		r.drainAdmissionsLocked()
		r.rejectPendingCarrierAdmissionsLocked()
		r.syncCarriersLocked()
		r.stopLifecycleSequence = r.lifecycleSequence.Add(1)
		r.stopCarriersLocked()
		r.closed = true
		r.syncAllLocked()
		for _, root := range r.roots {
			if root.xudp != nil {
				root.xudp.revokeForRegistryClose()
			}
			if root.record.record.CompletionState != CompletionTerminal {
				r.indeterminateLocked(root, IndeterminateRuntimeStopped)
			}
		}
		r.mu.Unlock()
		close(r.stopSignal)
		<-r.stopped
	})
}

func (r *Registry) mutableRootLocked(handle *Handle) *rootState {
	if handle.registry != r || handle.runtimeInstanceID != r.runtimeInstanceID {
		return nil
	}
	return r.roots[handle.flowID]
}

func (r *Registry) indeterminateLocked(root *rootState, reason IndeterminateReason) {
	record := &root.record.record
	if record.CompletionState == CompletionTerminal {
		return
	}
	changed := record.CompletionState != CompletionIndeterminate || record.IndeterminateReason != reason
	record.CompletionState = CompletionIndeterminate
	record.CompletionEvidence = CompletionEvidenceNone
	record.IndeterminateReason = reason
	record.UpdatedAtOffset = r.offsetLocked()
	if changed {
		r.appendRecordEventLocked(EventUpdated, root.record)
	}
}

func (r *Registry) terminalLocked(flowID string, root *rootState, class TerminalClass, category string, evidence CompletionEvidence) {
	record := &root.record.record
	if record.CompletionState == CompletionTerminal {
		return
	}
	now := r.offsetLocked()
	record.CompletionState = CompletionTerminal
	record.CompletionEvidence = evidence
	record.IndeterminateReason = ""
	record.TerminalClass = class
	record.TechnicalErrorCategory = boundedCategory(category)
	removeIssue(record, IssueTerminalUnproven)
	record.TerminalAtOffset = now
	record.UpdatedAtOffset = now
	r.detachRootSeriesLocked(root, now)
	root.retired.Store(true)
	delete(r.roots, flowID)
	r.appendRecordEventLocked(EventTerminal, root.record)
}

func (r *Registry) appendHopLocked(record *Record, hop HandlerHop) {
	if record.Route.ChainDisposition == ChainDispositionCycleDetected || record.Route.ChainDisposition == ChainDispositionDepthExceeded {
		return
	}
	hop.HandlerTag = boundedText(hop.HandlerTag, maxTagBytes)
	hop.HandlerType = boundedText(hop.HandlerType, maxTagBytes)
	hop.MatchedNativeRuleTag = boundedText(hop.MatchedNativeRuleTag, maxTagBytes)
	if hop.HandlerTag == "" {
		record.Route.ChainCoverage = ChainCoveragePartial
		return
	}
	for _, existing := range record.Route.KnownHandlerChain {
		if existing.HandlerTag == hop.HandlerTag {
			record.Route.ChainDisposition = ChainDispositionCycleDetected
			record.Route.ChainCoverage = ChainCoveragePartial
			record.Route.TerminalHandlerTag = ""
			if record.FlowKind != KindMUXLogical {
				record.CarrierProof = CarrierProofUnknown
			}
			return
		}
	}
	if len(record.Route.KnownHandlerChain) >= maxHandlerHops {
		record.Route.ChainDisposition = ChainDispositionDepthExceeded
		record.Route.ChainCoverage = ChainCoveragePartial
		record.Route.TerminalHandlerTag = ""
		if record.FlowKind != KindMUXLogical {
			record.CarrierProof = CarrierProofUnknown
		}
		return
	}
	record.Route.KnownHandlerChain = append(record.Route.KnownHandlerChain, hop)
}

func (r *Registry) attachSeriesLocked(record *Record, observation ByteObservation) (seriesID string, capacityExceeded bool) {
	if r.coverage.State != AccountingCoverageComplete {
		return "", false
	}
	key := CounterSeriesKey{
		AdmissionCoordinate:         cloneOptionalBytes(record.AdmissionCoordinate),
		SelectedTopLevelOutboundTag: record.Route.SelectedTopLevelOutboundTag,
		TrafficOrigin:               record.TrafficOrigin,
		Direction:                   observation.Direction,
		ByteScope:                   observation.ByteScope,
	}
	encodedKey := comparableSeriesKey(key)
	if id := r.seriesByKey[encodedKey]; id != "" {
		state := r.series[id]
		expectedState := seriesStateForObservation(observation.State)
		if state != nil && state.series.State == expectedState && state.series.CoverageGeneration == r.coverage.Generation {
			if state.activeRoots == math.MaxUint64 || !state.series.ActiveFlowCount.Known || state.series.ActiveFlowCount.Value == math.MaxUint64 {
				r.loseCoverageLocked(DiscontinuityAccountingCapacityExceeded)
				return "", true
			}
			state.activeRoots++
			state.series.ActiveFlowCount.Value++
			if observation.ObservedBytes.Known {
				state.series.CumulativeBytes = addOptionalCounter(state.series.CumulativeBytes, observation.ObservedBytes.Value)
				if !state.series.CumulativeBytes.Known {
					state.series.State = SeriesStateOverflowed
					state.series.DiscontinuityReason = DiscontinuityCounterOverflow
					r.appendSeriesEventLocked(EventCoverageDiscontinuity, state, DiscontinuityCounterOverflow)
				}
			}
			state.series.SampledAtOffset = r.offsetLocked()
			return id, false
		}
		if state != nil && state.activeRoots != 0 {
			if state.series.State == SeriesStateContinuous || state.series.State == SeriesStateF2Required {
				state.series.State = SeriesStateIndeterminate
				state.series.CumulativeBytes = OptionalUint64{}
				state.series.DiscontinuityReason = DiscontinuityAccountingScopeUnproven
				state.series.SampledAtOffset = r.offsetLocked()
				r.appendSeriesEventLocked(EventCoverageDiscontinuity, state, DiscontinuityAccountingScopeUnproven)
			}
			if state.activeRoots == math.MaxUint64 || !state.series.ActiveFlowCount.Known || state.series.ActiveFlowCount.Value == math.MaxUint64 {
				r.loseCoverageLocked(DiscontinuityAccountingCapacityExceeded)
				return "", true
			}
			state.activeRoots++
			state.series.ActiveFlowCount.Value++
			return id, false
		}
		if state != nil {
			r.evictSeriesLocked(id, state)
		}
	}
	if len(r.series) >= r.maxSeries && !r.evictOldestInactiveSeriesLocked() {
		r.loseCoverageLocked(DiscontinuityAccountingCapacityExceeded)
		return "", true
	}
	if r.nextSeries == math.MaxUint64 {
		r.loseCoverageLocked(DiscontinuityAccountingCapacityExceeded)
		return "", true
	}
	r.nextSeries++
	now := r.offsetLocked()
	startReason := SeriesStartFirstObserved
	if r.coverage.State == AccountingCoverageIndeterminate {
		startReason = SeriesStartAfterCoverageLoss
	}
	series := CounterSeries{
		RuntimeInstanceID:   r.runtimeInstanceID,
		SeriesID:            r.runtimeInstanceID + "-series-" + encodeUint64(r.nextSeries),
		CoverageGeneration:  r.coverage.Generation,
		Key:                 key,
		CumulativeBytes:     observation.ObservedBytes,
		ActiveFlowCount:     OptionalUint64{Known: true, Value: 1},
		StartedAtOffset:     now,
		SampledAtOffset:     now,
		State:               seriesStateForObservation(observation.State),
		StartReason:         startReason,
		DiscontinuityReason: DiscontinuitySeriesCreated,
	}
	if observation.State == ByteObservationStateF2Required {
		series.DiscontinuityReason = DiscontinuityF2Required
	} else if observation.State == ByteObservationStateOverflowed {
		series.DiscontinuityReason = DiscontinuityCounterOverflow
	} else if observation.State == ByteObservationStateIndeterminate {
		series.DiscontinuityReason = DiscontinuityAccountingScopeUnproven
	}
	state := &seriesState{series: series, activeRoots: 1}
	r.series[series.SeriesID] = state
	if series.State == SeriesStateContinuous || series.State == SeriesStateF2Required {
		r.seriesByKey[encodedKey] = series.SeriesID
	}
	r.seriesOrder = append(r.seriesOrder, series.SeriesID)
	r.appendSeriesEventLocked(EventCounterSeriesStarted, state, series.DiscontinuityReason)
	return series.SeriesID, false
}

func (r *Registry) addSeriesBytesLocked(state *seriesState, bytes uint64) {
	if state.series.State != SeriesStateContinuous || bytes == 0 {
		return
	}
	counter := &state.series.CumulativeBytes
	if !counter.Known {
		return
	}
	if math.MaxUint64-counter.Value < bytes {
		counter.Known = false
		counter.Value = 0
		state.series.State = SeriesStateOverflowed
		state.series.DiscontinuityReason = DiscontinuityCounterOverflow
		state.series.SampledAtOffset = r.offsetLocked()
		r.appendSeriesEventLocked(EventCoverageDiscontinuity, state, DiscontinuityCounterOverflow)
		return
	}
	counter.Value += bytes
	state.series.SampledAtOffset = r.offsetLocked()
}

func (r *Registry) loseCoverageLocked(reason DiscontinuityReason) {
	if reason == "" {
		return
	}
	if r.coverage.Generation < math.MaxUint64 {
		r.coverage.Generation++
	}
	r.coverage.State = AccountingCoverageIndeterminate
	r.coverage.Reason = reason
	r.coverage.ChangedAtOffset = r.offsetLocked()
	for _, state := range r.series {
		state.series.State = SeriesStateIndeterminate
		state.series.CumulativeBytes = OptionalUint64{}
		state.series.ActiveFlowCount.Known = false
		state.series.DiscontinuityReason = reason
		state.series.SampledAtOffset = r.coverage.ChangedAtOffset
	}
	clear(r.seriesByKey)
	r.appendEventLocked(Event{Type: EventCoverageDiscontinuity, Reason: reason})
}

func (r *Registry) evictOldestTerminalRecordLocked() bool {
	for index, id := range r.recordOrder {
		state := r.records[id]
		if state != nil && state.record.CompletionState == CompletionTerminal {
			record := cloneRecord(state.record)
			delete(r.records, id)
			r.recordOrder = append(r.recordOrder[:index], r.recordOrder[index+1:]...)
			r.evictedRecords++
			r.appendEventLocked(Event{Type: EventFlowDetailEvicted, Record: &record})
			return true
		}
	}
	return false
}

func (r *Registry) evictOldestInactiveSeriesLocked() bool {
	for index, id := range r.seriesOrder {
		state := r.series[id]
		if state == nil || state.activeRoots != 0 {
			continue
		}
		r.evictSeriesAtLocked(index, id, state)
		return true
	}
	return false
}

func (r *Registry) evictSeriesLocked(id string, state *seriesState) {
	for index, orderedID := range r.seriesOrder {
		if orderedID == id {
			r.evictSeriesAtLocked(index, id, state)
			return
		}
	}
}

func (r *Registry) evictSeriesAtLocked(index int, id string, state *seriesState) {
	r.appendSeriesEventLocked(EventCounterSeriesEnded, state, DiscontinuitySeriesEvicted)
	key := comparableSeriesKey(state.series.Key)
	if r.seriesByKey[key] == id {
		delete(r.seriesByKey, key)
	}
	delete(r.series, id)
	r.seriesOrder = append(r.seriesOrder[:index], r.seriesOrder[index+1:]...)
	r.evictedSeries++
}

func (r *Registry) appendRecordEventLocked(eventType EventType, state *recordState) {
	record := cloneRecord(state.record)
	r.appendEventLocked(Event{Type: eventType, Record: &record})
}

func (r *Registry) appendSeriesEventLocked(eventType EventType, state *seriesState, reason DiscontinuityReason) {
	series := cloneSeries(state.series)
	r.appendEventLocked(Event{Type: eventType, Series: &series, Reason: reason})
}

func (r *Registry) appendEventLocked(event Event) {
	if r.nextSequence == math.MaxUint64 {
		r.sequenceExhausted = true
		return
	}
	r.nextSequence++
	event.Sequence = r.nextSequence
	if len(r.events) == r.maxEvents {
		r.events[r.eventHead] = event
		r.eventHead = (r.eventHead + 1) % len(r.events)
		return
	}
	r.events = append(r.events, event)
}

func (r *Registry) offsetLocked() time.Duration { return time.Since(r.startedAt) }

func classifyError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "CONTEXT_CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return "DEADLINE_EXCEEDED"
	case errors.Is(err, io.EOF):
		return "EOF"
	default:
		return "OUTBOUND_ERROR"
	}
}

func boundedText(value string, limit int) string {
	if len(value) > limit {
		return ""
	}
	return value
}

func boundedCategory(value string) string { return boundedText(value, maxTagBytes) }

func addIssue(record *Record, issue Issue) {
	for _, existing := range record.Issues {
		if existing == issue {
			return
		}
	}
	if len(record.Issues) < maxIssues {
		record.Issues = append(record.Issues, issue)
	}
}

func removeIssue(record *Record, issue Issue) {
	for index, existing := range record.Issues {
		if existing == issue {
			record.Issues = append(record.Issues[:index], record.Issues[index+1:]...)
			return
		}
	}
}

func mergeCarrierProof(current, next CarrierProof) CarrierProof {
	if current == CarrierProofUnknown || next == CarrierProofUnknown {
		return CarrierProofUnknown
	}
	if current == CarrierProofProven || next == CarrierProofProven {
		return CarrierProofProven
	}
	if next != "" {
		return next
	}
	return current
}

func addOptionalCounter(current OptionalUint64, delta uint64) OptionalUint64 {
	if !current.Known || delta == 0 {
		return current
	}
	if math.MaxUint64-current.Value < delta {
		return OptionalUint64{}
	}
	current.Value += delta
	return current
}

func cloneRecord(record Record) Record {
	record.AdmissionCoordinate = cloneOptionalBytes(record.AdmissionCoordinate)
	record.Route.KnownHandlerChain = append([]HandlerHop(nil), record.Route.KnownHandlerChain...)
	record.ByteObservations = cloneByteObservations(record.ByteObservations)
	record.Issues = append([]Issue(nil), record.Issues...)
	record.XUDPBindings = append([]XUDPBinding(nil), record.XUDPBindings...)
	return record
}

func cloneSeries(series CounterSeries) CounterSeries {
	series.Key.AdmissionCoordinate = cloneOptionalBytes(series.Key.AdmissionCoordinate)
	return series
}

func cloneOptionalBytes(value OptionalBytes) OptionalBytes {
	return OptionalBytes{Known: value.Known, Value: cloneBytes(value.Value)}
}

func cloneEvent(event Event) Event {
	if event.Record != nil {
		record := cloneRecord(*event.Record)
		event.Record = &record
	}
	if event.Series != nil {
		series := cloneSeries(*event.Series)
		event.Series = &series
	}
	if event.XUDPBinding != nil {
		binding := *event.XUDPBinding
		event.XUDPBinding = &binding
	}
	if event.Carrier != nil {
		x := cloneCarrierRecord(*event.Carrier)
		event.Carrier = &x
	}
	if event.CarrierSeries != nil {
		x := *event.CarrierSeries
		event.CarrierSeries = &x
	}
	if event.CarrierCoverage != nil {
		x := *event.CarrierCoverage
		event.CarrierCoverage = &x
	}
	return event
}

func cloneCarrierRecord(x CarrierRecord) CarrierRecord {
	x.ByteObservations = cloneByteObservations(x.ByteObservations)
	return x
}
func cloneCarrierRecordPtr(x CarrierRecord) *CarrierRecord { x = cloneCarrierRecord(x); return &x }
func carrierDirectionIndex(d Direction) int {
	if d == DirectionDownlink {
		return 1
	}
	return 0
}

func carrierKindForIndex(i int) CarrierKind {
	if i >= 2 {
		return CarrierKindClientMuxFrameLink
	}
	return CarrierKindServerMuxFrameLink
}

func carrierKindDirectionIndex(kind CarrierKind, d Direction) int {
	switch kind {
	case CarrierKindServerMuxFrameLink:
		return carrierDirectionIndex(d)
	case CarrierKindClientMuxFrameLink:
		return 2 + carrierDirectionIndex(d)
	default:
		return -1
	}
}

func (r *Registry) loseCarrierDirectionLocked(d Direction, reason DiscontinuityReason, state SeriesState) {
	r.loseCarrierDirectionLockedKind(CarrierKindServerMuxFrameLink, d, reason, state)
}

func (r *Registry) loseCarrierDirectionLockedKind(kind CarrierKind, d Direction, reason DiscontinuityReason, state SeriesState) {
	i := carrierKindDirectionIndex(kind, d)
	if i < 0 {
		return
	}
	c := &r.carrierCoverage[i]
	if c.State == AccountingCoverageIndeterminate {
		return
	}
	if c.Generation < math.MaxUint64 {
		c.Generation++
	}
	c.State = AccountingCoverageIndeterminate
	c.Reason = reason
	c.ChangedAtOffset = r.offsetLocked()
	if series := r.carrierSeries[i]; series != nil {
		series.series.State = state
		series.series.CumulativeBytes = OptionalUint64{}
		series.series.ActiveCarrierCount = OptionalUint64{}
		series.series.DiscontinuityReason = c.Reason
		series.series.SampledAtOffset = c.ChangedAtOffset
		copy := series.series
		r.appendEventLocked(Event{Type: EventCoverageDiscontinuity, Reason: c.Reason, CarrierSeries: &copy})
	}
	r.appendEventLocked(Event{Type: EventCoverageDiscontinuity, Reason: c.Reason, CarrierCoverage: c})
}

func (r *Registry) loseCarrierCoverageLocked() {
	r.loseCarrierDirectionLocked(DirectionUplink, DiscontinuityAccountingScopeUnproven, SeriesStateIndeterminate)
	r.loseCarrierDirectionLocked(DirectionDownlink, DiscontinuityAccountingScopeUnproven, SeriesStateIndeterminate)
}

func (r *Registry) loseCarrierMembershipLocked() {
	r.loseCarrierMembershipLockedKind(CarrierKindServerMuxFrameLink)
}

func (r *Registry) loseCarrierMembershipLockedKind(kind CarrierKind) {
	for _, direction := range []Direction{DirectionUplink, DirectionDownlink} {
		i := carrierKindDirectionIndex(kind, direction)
		if i < 0 {
			continue
		}
		r.carrierMembershipLost[i] = true
		r.loseCarrierDirectionLockedKind(kind, direction, DiscontinuityAccountingScopeUnproven, SeriesStateIndeterminate)
	}
}

func comparableSeriesKey(key CounterSeriesKey) seriesMapKey {
	return seriesMapKey{
		coordinateKnown: key.AdmissionCoordinate.Known,
		coordinate:      string(key.AdmissionCoordinate.Value),
		outbound:        key.SelectedTopLevelOutboundTag,
		origin:          key.TrafficOrigin,
		direction:       key.Direction,
		byteScope:       key.ByteScope,
	}
}

func cloneByteObservations(observations []ByteObservation) []ByteObservation {
	return append([]ByteObservation(nil), observations...)
}

func byteObservationsEqual(left, right []ByteObservation) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func seriesStateForObservation(state ByteObservationState) SeriesState {
	switch state {
	case ByteObservationStateF2Required:
		return SeriesStateF2Required
	case ByteObservationStateOverflowed:
		return SeriesStateOverflowed
	case ByteObservationStateIndeterminate:
		return SeriesStateIndeterminate
	default:
		return SeriesStateContinuous
	}
}

func encodeUint64(value uint64) string {
	var raw [8]byte
	for index := len(raw) - 1; index >= 0; index-- {
		raw[index] = byte(value)
		value >>= 8
	}
	return hex.EncodeToString(raw[:])
}
