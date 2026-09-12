// Package flow contains the bounded passive-flow observation model owned by
// the dispatcher. It intentionally contains no product policy or node mapping.
package flow

import "time"

const (
	MaxAdmissionCoordinateBytes = 128
	// MaxByteObservations is the closed PR-F1 representation bound: two
	// directions multiplied by the three byte scopes known to this model.
	MaxByteObservations = 6
)

type Kind string

const (
	KindTCP            Kind = "TCP"
	KindUDPAssociation Kind = "UDP_ASSOCIATION"
	KindMUXLogical     Kind = "MUX_LOGICAL"
	KindXUDPLogical    Kind = "XUDP_LOGICAL"
)

// CarrierKind identifies a non-logical carrier record. It is deliberately not
// a flow kind: carrier records have no route, origin, or logical identity.
type CarrierKind string

const (
	CarrierKindServerMuxFrameLink CarrierKind = "SERVER_MUX_FRAME_LINK"
	CarrierKindClientMuxFrameLink CarrierKind = "CLIENT_MUX_FRAME_LINK"
)

type Origin string

const (
	OriginUnknown               Origin = "UNKNOWN"
	OriginUser                  Origin = "USER"
	OriginControlledMeasurement Origin = "CONTROLLED_MEASUREMENT"
)

type OriginProof string

const (
	OriginProofNone                 OriginProof = "NONE"
	OriginProofTrustedIngressMarker OriginProof = "TRUSTED_INGRESS_MARKER"
	OriginProofMeasurementAdmission OriginProof = "MEASUREMENT_ADMISSION"
)

type CarrierProof string

const (
	CarrierProofProven        CarrierProof = "PROVEN"
	CarrierProofNotApplicable CarrierProof = "NOT_APPLICABLE"
	CarrierProofUnknown       CarrierProof = "UNKNOWN"
)

// CarrierObservation is an immutable, bounded descriptor computed by a
// concrete outbound owner when it is constructed. The dispatcher may read it
// in O(1) without serializing configuration or invoking transport code.
type CarrierObservation struct {
	Proof                     CarrierProof
	MuxF2Required             bool
	CarrierF2Required         bool
	DialerProxyCarrierUnknown bool
}

type ChainCoverage string

const (
	ChainCoverageComplete ChainCoverage = "COMPLETE"
	ChainCoveragePartial  ChainCoverage = "PARTIAL"
	ChainCoverageUnknown  ChainCoverage = "UNKNOWN"
)

type DispatchDisposition string

const (
	DispatchDispositionInvoked         DispatchDisposition = "INVOKED"
	DispatchDispositionRejectedLocally DispatchDisposition = "REJECTED_LOCALLY"
	DispatchDispositionUnknown         DispatchDisposition = "UNKNOWN"
)

type ByteScope string

const (
	// ByteScopeLogicalLinkAccepted counts bytes accepted by dispatcher-owned
	// logical Xray pipes after a successful write.
	ByteScopeLogicalLinkAccepted ByteScope = "XRAY_LOGICAL_LINK_ACCEPTED"
	// ByteScopeDispatcherExternalLinkIO counts uplink bytes returned by the
	// exact external Link.Reader into the dispatcher's timeout wrapper and
	// downlink buffers accepted by the exact external Link.Writer whose
	// WriteMultiBuffer completed successfully. It is neither payload nor
	// remote-delivery evidence.
	ByteScopeDispatcherExternalLinkIO ByteScope = "XRAY_DISPATCHER_EXTERNAL_LINK_IO"
	// ByteScopeKernelDirectCopyAccepted identifies destination-side bytes
	// accepted by the Linux/Android kernel direct-copy path. PR-F1 publishes
	// this scope as F2_REQUIRED without a numeric value.
	ByteScopeKernelDirectCopyAccepted ByteScope = "KERNEL_DIRECT_COPY_ACCEPTED"
	ByteScopeCarrierConnectionIO      ByteScope = "CARRIER_CONNECTION_IO"
	ByteScopeUnknown                  ByteScope = "UNKNOWN"
)

type ByteObservationState string

const (
	ByteObservationStateProven        ByteObservationState = "PROVEN"
	ByteObservationStateF2Required    ByteObservationState = "F2_REQUIRED"
	ByteObservationStateOverflowed    ByteObservationState = "OVERFLOWED"
	ByteObservationStateIndeterminate ByteObservationState = "INDETERMINATE"
)

// ByteObservation is one exact raw counter cell. Distinct directions or scopes
// are never projected into this value.
type ByteObservation struct {
	Direction       Direction
	ByteScope       ByteScope
	ObservedBytes   OptionalUint64
	State           ByteObservationState
	AccountingFault AccountingFault
}

type HandlerEntryKind string

const (
	HandlerEntryRootSelection      HandlerEntryKind = "ROOT_SELECTION"
	HandlerEntryLoopbackRedispatch HandlerEntryKind = "LOOPBACK_REDISPATCH"
	HandlerEntryDialerProxy        HandlerEntryKind = "DIALER_PROXY"
)

type ChainDisposition string

const (
	ChainDispositionOK            ChainDisposition = "OK"
	ChainDispositionCycleDetected ChainDisposition = "CYCLE_DETECTED"
	ChainDispositionDepthExceeded ChainDisposition = "DEPTH_EXCEEDED"
	ChainDispositionUnknown       ChainDisposition = "UNKNOWN"
)

type ActivityState string

const (
	ActivityAdmitted   ActivityState = "ADMITTED"
	ActivityDispatched ActivityState = "DISPATCHED"
	ActivityActive     ActivityState = "ACTIVE"
)

type LifecyclePhase string

const (
	LifecyclePhaseOpen        LifecyclePhase = "OPEN"
	LifecyclePhaseOwnerSealed LifecyclePhase = "OWNER_SEALED"
	LifecyclePhaseTerminal    LifecyclePhase = "TERMINAL"
)

type ProofState string

const (
	ProofStateComplete      ProofState = "COMPLETE"
	ProofStateIndeterminate ProofState = "INDETERMINATE"
)

type Direction string

const (
	DirectionUplink   Direction = "UPLINK"
	DirectionDownlink Direction = "DOWNLINK"
)

type DirectionState string

const (
	DirectionStateOpen       DirectionState = "OPEN"
	DirectionStateHalfClosed DirectionState = "HALF_CLOSED"
	DirectionStateSealed     DirectionState = "SEALED"
	DirectionStateQuiescent  DirectionState = "QUIESCENT"
)

type LifecycleFault string

const (
	LifecycleFaultParticipantCapacityExceeded LifecycleFault = "PARTICIPANT_CAPACITY_EXCEEDED"
	LifecycleFaultParticipantUnderflow        LifecycleFault = "PARTICIPANT_UNDERFLOW"
	LifecycleFaultLateParticipantAcquire      LifecycleFault = "LATE_PARTICIPANT_ACQUIRE"
	LifecycleFaultDoubleParticipantRelease    LifecycleFault = "DOUBLE_PARTICIPANT_RELEASE"
	LifecycleFaultByteOperationCapacity       LifecycleFault = "BYTE_OPERATION_CAPACITY_EXCEEDED"
	LifecycleFaultByteOperationUnderflow      LifecycleFault = "BYTE_OPERATION_UNDERFLOW"
	LifecycleFaultByteOperationAfterSeal      LifecycleFault = "BYTE_OPERATION_AFTER_SEAL"
	LifecycleFaultDoubleByteOperationComplete LifecycleFault = "DOUBLE_BYTE_OPERATION_COMPLETE"
	LifecycleFaultLateByteProgress            LifecycleFault = "LATE_BYTE_PROGRESS"
	LifecycleFaultOutcomeCapacityExceeded     LifecycleFault = "OUTCOME_CAPACITY_EXCEEDED"
	LifecycleFaultOutcomeUnderflow            LifecycleFault = "OUTCOME_UNDERFLOW"
	LifecycleFaultContinuationForeignLink     LifecycleFault = "CONTINUATION_FOREIGN_LINK"
	LifecycleFaultContinuationMissing         LifecycleFault = "CONTINUATION_MISSING"
	LifecycleFaultContinuationReplay          LifecycleFault = "CONTINUATION_REPLAY"
	LifecycleFaultContinuationStaleRoot       LifecycleFault = "CONTINUATION_STALE_ROOT"
	LifecycleFaultContinuationParticipantLost LifecycleFault = "CONTINUATION_PARTICIPANT_LOST"
	LifecycleFaultContinuationDepthOverflow   LifecycleFault = "CONTINUATION_DEPTH_OVERFLOW"
	LifecycleFaultExternalOwnerReplay         LifecycleFault = "EXTERNAL_OWNER_REPLAY"
	LifecycleFaultDetourContextMissing        LifecycleFault = "DETOUR_CONTEXT_MISSING"
	LifecycleFaultDetourParticipantLost       LifecycleFault = "DETOUR_PARTICIPANT_LOST"
	LifecycleFaultDetourStaleRoot             LifecycleFault = "DETOUR_STALE_ROOT"
	LifecycleFaultDetourDepthOverflow         LifecycleFault = "DETOUR_DEPTH_OVERFLOW"
	LifecycleFaultDetourLineageConflict       LifecycleFault = "DETOUR_LINEAGE_CONFLICT"
	LifecycleFaultAsyncLinkContextMissing     LifecycleFault = "ASYNC_LINK_CONTEXT_MISSING"
	LifecycleFaultAsyncLinkParticipantLost    LifecycleFault = "ASYNC_LINK_PARTICIPANT_LOST"
	LifecycleFaultAsyncLinkStaleRoot          LifecycleFault = "ASYNC_LINK_STALE_ROOT"
)

type AccountingFault string

const (
	AccountingFaultCounterOverflow  AccountingFault = "COUNTER_OVERFLOW"
	AccountingFaultSequenceOverflow AccountingFault = "BYTE_SEQUENCE_OVERFLOW"
	AccountingFaultUnreservedBytes  AccountingFault = "UNRESERVED_BYTE_OPERATION"
	AccountingFaultCallbackLost     AccountingFault = "ACCOUNTING_CALLBACK_LOST"
	AccountingFaultBoundaryUnproven AccountingFault = "ACCOUNTING_BOUNDARY_UNPROVEN"
)

type CompletionState string

const (
	CompletionOpen          CompletionState = "OPEN"
	CompletionIndeterminate CompletionState = "INDETERMINATE"
	CompletionTerminal      CompletionState = "TERMINAL"
)

type CompletionEvidence string

const (
	CompletionEvidenceNone                       CompletionEvidence = "NONE"
	CompletionEvidenceLocalRejectionBeforeInvoke CompletionEvidence = "LOCAL_REJECTION_BEFORE_INVOKE"
	CompletionEvidenceRootLogicalLinkQuiesced    CompletionEvidence = "ROOT_LOGICAL_LINK_QUIESCED"
	CompletionEvidenceProvenLogicalSessionClosed CompletionEvidence = "PROVEN_LOGICAL_SESSION_CLOSED"
	CompletionEvidenceXUDPRetainedLinkClosed     CompletionEvidence = "XUDP_RETAINED_LINK_CLOSED"
)

type TerminalClass string

const (
	TerminalClassCompleted      TerminalClass = "COMPLETED"
	TerminalClassCancelled      TerminalClass = "CANCELLED"
	TerminalClassTimeout        TerminalClass = "TIMEOUT"
	TerminalClassLocalRejection TerminalClass = "LOCAL_REJECTION"
	TerminalClassLocalError     TerminalClass = "LOCAL_ERROR"
	TerminalClassRemoteEOF      TerminalClass = "REMOTE_EOF"
	TerminalClassRemoteError    TerminalClass = "REMOTE_ERROR"
	TerminalClassUnknown        TerminalClass = "UNKNOWN"
)

type QuiescenceReceipt struct {
	RuntimeInstanceID string
	FlowID            string
	Direction         Direction
	ObservedAtOffset  time.Duration
	LastByteSequence  uint64
}

type TerminalReceipt struct {
	RuntimeInstanceID      string
	FlowID                 string
	TerminalClass          TerminalClass
	TechnicalErrorCategory string
	Evidence               CompletionEvidence
	TerminalAtOffset       time.Duration
	LastByteSequence       uint64
	publicationSequence    uint64
}

type LifecycleView struct {
	RuntimeInstanceID      string
	FlowID                 string
	Phase                  LifecyclePhase
	ProofState             ProofState
	LifecycleFault         LifecycleFault
	AccountingFault        AccountingFault
	LiveParticipantCount   uint64
	UplinkState            DirectionState
	DownlinkState          DirectionState
	ByteObservations       []ByteObservation
	LastByteSequence       uint64
	UplinkQuiescence       *QuiescenceReceipt
	DownlinkQuiescence     *QuiescenceReceipt
	Terminal               *TerminalReceipt
	PostTerminalFaultCount uint64
}

type EventType string

const (
	EventAdmitted              EventType = "ADMITTED"
	EventUpdated               EventType = "UPDATED"
	EventTerminal              EventType = "TERMINAL"
	EventFlowDetailEvicted     EventType = "FLOW_DETAIL_EVICTED"
	EventCarrierDetailEvicted  EventType = "CARRIER_DETAIL_EVICTED"
	EventCounterSeriesStarted  EventType = "COUNTER_SERIES_STARTED"
	EventCounterSeriesEnded    EventType = "COUNTER_SERIES_ENDED"
	EventCoverageDiscontinuity EventType = "COVERAGE_DISCONTINUITY"
	EventXUDPBindingTransition EventType = "XUDP_BINDING_TRANSITION"
)

type EventGapReason string

const (
	EventGapNone              EventGapReason = "NONE"
	EventGapRetentionExceeded EventGapReason = "EVENT_RETENTION_EXCEEDED"
	EventGapSequenceExhausted EventGapReason = "EVENT_SEQUENCE_EXHAUSTED"
)

type SeriesState string

const (
	SeriesStateContinuous    SeriesState = "CONTINUOUS"
	SeriesStateF2Required    SeriesState = "F2_REQUIRED"
	SeriesStateOverflowed    SeriesState = "OVERFLOWED"
	SeriesStateIndeterminate SeriesState = "INDETERMINATE"
)

type SeriesStartReason string

const (
	SeriesStartFirstObserved     SeriesStartReason = "FIRST_OBSERVED"
	SeriesStartSourceReset       SeriesStartReason = "SOURCE_RESET"
	SeriesStartAfterCoverageLoss SeriesStartReason = "AFTER_COVERAGE_LOSS"
)

type DiscontinuityReason string

const (
	DiscontinuitySeriesCreated              DiscontinuityReason = "SERIES_CREATED"
	DiscontinuitySeriesEvicted              DiscontinuityReason = "SERIES_EVICTED"
	DiscontinuitySourceReset                DiscontinuityReason = "SOURCE_RESET"
	DiscontinuityCounterOverflow            DiscontinuityReason = "COUNTER_OVERFLOW"
	DiscontinuityAccountingCapacityExceeded DiscontinuityReason = "ACCOUNTING_CAPACITY_EXCEEDED"
	DiscontinuityAdmissionContention        DiscontinuityReason = "ACCOUNTING_ADMISSION_CONTENTION"
	DiscontinuityAccountingCallbackLost     DiscontinuityReason = "ACCOUNTING_CALLBACK_LOST"
	DiscontinuityAccountingScopeUnproven    DiscontinuityReason = "ACCOUNTING_SCOPE_UNPROVEN"
	DiscontinuityF2Required                 DiscontinuityReason = "F2_REQUIRED"
)

type IndeterminateReason string

const (
	IndeterminateHandlerReturnedUnproven       IndeterminateReason = "HANDLER_RETURNED_UNPROVEN"
	IndeterminateCancellationRequested         IndeterminateReason = "CANCELLATION_REQUESTED_UNPROVEN"
	IndeterminateOneDirectionClosed            IndeterminateReason = "ONE_DIRECTION_CLOSED"
	IndeterminateAsyncSessionUnobserved        IndeterminateReason = "ASYNC_SESSION_UNOBSERVED"
	IndeterminateRuntimeStopped                IndeterminateReason = "RUNTIME_STOPPED_BEFORE_PROOF"
	IndeterminateCompletionCallbackLost        IndeterminateReason = "COMPLETION_CALLBACK_LOST"
	IndeterminateHandlerInvocationStillRunning IndeterminateReason = "HANDLER_INVOCATION_RUNNING"
	IndeterminateLocalRejectionDraining        IndeterminateReason = "LOCAL_REJECTION_DRAINING"
)

type AccountingCoverageState string

const (
	AccountingCoverageComplete      AccountingCoverageState = "COMPLETE"
	AccountingCoverageIndeterminate AccountingCoverageState = "INDETERMINATE"
)

type Issue string

const (
	IssueFieldOversize               Issue = "FIELD_OVERSIZE"
	IssueTerminalUnproven            Issue = "TERMINAL_HANDLER_UNPROVEN"
	IssueDirectSpliceF2Required      Issue = "DIRECT_SPLICE_F2_REQUIRED"
	IssueMuxCarrierF2Required        Issue = "MUX_CARRIER_ACCOUNTING_F2_REQUIRED"
	IssueCarrierF2Required           Issue = "CARRIER_ACCOUNTING_F2_REQUIRED"
	IssueDialerProxyCarrierUnknown   Issue = "DIALER_PROXY_CARRIER_UNKNOWN"
	IssueCarrierProofUnknown         Issue = "CARRIER_PROOF_UNKNOWN"
	IssueSenderSettingsUninspectable Issue = "SENDER_SETTINGS_UNINSPECTABLE"
	IssueExternalLinkUnsupported     Issue = "EXTERNAL_LINK_ACCOUNTING_UNSUPPORTED"
	IssueWriteAcceptanceUnknown      Issue = "WRITE_ACCEPTANCE_UNKNOWN"
	IssueAccountingCapacityExceeded  Issue = "ACCOUNTING_CAPACITY_EXCEEDED"
	IssueDetourLineagePending        Issue = "DETOUR_LINEAGE_PENDING"
	IssueSelectedOutboundUnknown     Issue = "SELECTED_OUTBOUND_UNKNOWN"
)

type OptionalBytes struct {
	Known bool
	Value []byte
}

type OptionalUint64 struct {
	Known bool
	Value uint64
}

type HandlerHop struct {
	HandlerTag           string
	HandlerType          string
	EntryKind            HandlerEntryKind
	MatchedNativeRuleTag string
}

type RouteFacts struct {
	MatchedNativeRuleTag        string
	SelectedTopLevelOutboundTag string
	SelectedHandlerType         string
	DispatchDisposition         DispatchDisposition
	KnownHandlerChain           []HandlerHop
	ChainCoverage               ChainCoverage
	ChainDisposition            ChainDisposition
	TerminalHandlerTag          string
}

type Record struct {
	RuntimeInstanceID string
	FlowID            string
	FlowKind          Kind

	AdmissionCoordinate              OptionalBytes
	OpaqueAndroidUID                 OptionalUint64
	CarrierReference                 string
	SelectedOutboundCarrierReference string
	CarrierProof                     CarrierProof

	TrafficOrigin Origin
	OriginProof   OriginProof

	Source               string
	OriginalDestination  string
	EffectiveDestination string
	Protocol             string
	Route                RouteFacts

	ByteObservations []ByteObservation

	ActivityState          ActivityState
	CompletionState        CompletionState
	CompletionEvidence     CompletionEvidence
	IndeterminateReason    IndeterminateReason
	TerminalClass          TerminalClass
	TechnicalErrorCategory string
	Issues                 []Issue

	AdmittedAtOffset   time.Duration
	DispatchedAtOffset time.Duration
	ActiveAtOffset     time.Duration
	TerminalAtOffset   time.Duration
	UpdatedAtOffset    time.Duration

	XUDPBindings                  []XUDPBinding
	XUDPHistoryTruncated          bool
	XUDPFirstRetainedOrdinal      OptionalUint64
	XUDPNextBindingOrdinal        uint64
	XUDPTransitionIncomplete      bool
	XUDPLostTransitionFirst       OptionalUint64
	XUDPLostTransitionLast        OptionalUint64
	XUDPLostTransitionFirstAction XUDPBindingAction
	XUDPLostTransitionLastAction  XUDPBindingAction
	XUDPTransitionState           XUDPTransitionEvidence
	XUDPTransitionLossReason      XUDPTransitionLossReason
}

type CarrierRecord struct {
	RuntimeInstanceID      string
	CarrierReference       string
	CarrierKind            CarrierKind
	ByteObservations       []ByteObservation
	ActivityState          ActivityState
	CompletionState        CompletionState
	IndeterminateReason    IndeterminateReason
	TerminalClass          TerminalClass
	TechnicalErrorCategory string
	AdmittedAtOffset       time.Duration
	ActiveAtOffset         time.Duration
	TerminalAtOffset       time.Duration
	UpdatedAtOffset        time.Duration
}

type CarrierCounterSeriesKey struct {
	CarrierKind CarrierKind
	Direction   Direction
	ByteScope   ByteScope
}
type CarrierCounterSeries struct {
	RuntimeInstanceID   string
	SeriesID            string
	CoverageGeneration  uint64
	Key                 CarrierCounterSeriesKey
	CumulativeBytes     OptionalUint64
	ActiveCarrierCount  OptionalUint64
	StartedAtOffset     time.Duration
	SampledAtOffset     time.Duration
	State               SeriesState
	StartReason         SeriesStartReason
	DiscontinuityReason DiscontinuityReason
}
type CarrierAccountingCoverage struct {
	Generation      uint64
	Key             CarrierCounterSeriesKey
	State           AccountingCoverageState
	Reason          DiscontinuityReason
	ChangedAtOffset time.Duration
}

type XUDPBinding struct {
	Ordinal          uint64
	CarrierReference string
	AttachedAtOffset time.Duration
	DetachedAtOffset time.Duration
	DetachTransition string
}
type XUDPBindingAction string

const (
	XUDPBindingActionAttach XUDPBindingAction = "ATTACH"
	XUDPBindingActionDetach XUDPBindingAction = "DETACH"
)

type XUDPDetachTransition string

const (
	XUDPDetachTransitionNone       XUDPDetachTransition = "NONE"
	XUDPDetachTransitionToExpiring XUDPDetachTransition = "TO_EXPIRING"
	XUDPDetachTransitionForRebind  XUDPDetachTransition = "FOR_REBIND"
	XUDPDetachTransitionRootClose  XUDPDetachTransition = "ROOT_CLOSE"
)

type XUDPTransitionEvidence string

const (
	XUDPTransitionEvidenceComplete   XUDPTransitionEvidence = "COMPLETE"
	XUDPTransitionEvidenceIncomplete XUDPTransitionEvidence = "INCOMPLETE"
)

type XUDPTransitionLossReason string

const (
	XUDPTransitionLossNone                 XUDPTransitionLossReason = "NONE"
	XUDPTransitionLossCapacityExceeded     XUDPTransitionLossReason = "BINDING_TRANSITION_CAPACITY_EXCEEDED"
	XUDPTransitionLossAuthorityUnavailable XUDPTransitionLossReason = "BINDING_AUTHORITY_UNAVAILABLE"
	XUDPTransitionLossReaderExitUnproven   XUDPTransitionLossReason = "BINDING_READER_EXIT_UNPROVEN"
)

type XUDPTransitionKey struct {
	Ordinal uint64
	Action  XUDPBindingAction
}

type Event struct {
	Sequence        uint64
	Type            EventType
	Record          *Record
	Series          *CounterSeries
	Reason          DiscontinuityReason
	XUDPBinding     *XUDPBindingTransition
	Carrier         *CarrierRecord
	CarrierSeries   *CarrierCounterSeries
	CarrierCoverage *CarrierAccountingCoverage
}

type XUDPBindingTransition struct {
	RuntimeInstanceID string
	FlowID            string
	Ordinal           uint64
	Action            XUDPBindingAction
	CarrierReference  string
	ObservedAtOffset  time.Duration
	DetachTransition  XUDPDetachTransition
}

type CounterSeriesKey struct {
	AdmissionCoordinate         OptionalBytes
	SelectedTopLevelOutboundTag string
	TrafficOrigin               Origin
	Direction                   Direction
	ByteScope                   ByteScope
}

type CounterSeries struct {
	RuntimeInstanceID   string
	SeriesID            string
	CoverageGeneration  uint64
	Key                 CounterSeriesKey
	CumulativeBytes     OptionalUint64
	ActiveFlowCount     OptionalUint64
	StartedAtOffset     time.Duration
	SampledAtOffset     time.Duration
	State               SeriesState
	StartReason         SeriesStartReason
	DiscontinuityReason DiscontinuityReason
}

type AccountingCoverage struct {
	Generation      uint64
	State           AccountingCoverageState
	Reason          DiscontinuityReason
	ChangedAtOffset time.Duration
}

type Snapshot struct {
	RuntimeInstanceID              string
	Watermark                      uint64
	TakenAtOffset                  time.Duration
	Records                        []Record
	CounterSeries                  []CounterSeries
	AccountingCoverage             AccountingCoverage
	DroppedFlowCount               uint64
	EvictedRecordCount             uint64
	EvictedSeriesCount             uint64
	CarrierRecords                 []CarrierRecord
	CarrierCounterSeries           []CarrierCounterSeries
	CarrierAccountingCoverage      []CarrierAccountingCoverage
	DroppedCarrierObservationCount uint64
	EvictedCarrierRecordCount      uint64
}

type EventBatch struct {
	RuntimeInstanceID        string
	RequestedAfterSequence   uint64
	AvailableThroughSequence uint64
	DeliveredThroughSequence uint64
	ResyncRequired           bool
	GapReason                EventGapReason
	Events                   []Event
}

type Observer interface {
	Snapshot() Snapshot
	EventsAfter(after uint64, limit int) EventBatch
}

type Provider interface {
	FlowObserver() Observer
}
