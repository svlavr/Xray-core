package stats

import (
	"context"
	"errors"
	"time"

	"github.com/xtls/xray-core/common/net"
)

var (
	ErrInspectionLimit          = errors.New("inspection limit exceeded")
	ErrInspectionUnavailable    = errors.New("inspection unavailable")
	ErrInspectionClosed         = errors.New("inspection closed")
	ErrInspectionAlreadyEnabled = errors.New("inspection already enabled")
	ErrInspectionTooLate        = errors.New("inspection enablement is too late")
	ErrInspectionEntropy        = errors.New("inspection runtime entropy unavailable")
)

// TrafficOrigin is the low-level admission-origin fact. Session metadata
// aliases this type; inspection does not infer an origin from identity or tags.
type TrafficOrigin uint8

const (
	TrafficOriginUnknown TrafficOrigin = iota
	TrafficOriginUser
	TrafficOriginInternal
	TrafficOriginControlledMeasurement
)

type RuntimeID [16]byte

type FlowRef struct {
	Runtime RuntimeID
	ID      uint64
}

type OutboundRef struct {
	Runtime      RuntimeID
	Serial       uint64
	Tag          string
	TagTruncated bool
}

type ObservationOptions struct {
	MaxLive         uint32
	MaxTerminals    uint32
	MaxBuckets      uint32
	MaxClose        uint32
	MaxRouteSteps   uint32
	MaxDestinations uint32
}

type InspectionInfo struct {
	Runtime RuntimeID
	Limits  ObservationOptions
	Closed  bool
}

type ByteFact struct {
	Known      uint64
	Incomplete bool
}

type Sample struct {
	Runtime RuntimeID
	At      time.Duration
}

type SelectionKind uint8

const (
	SelectionUnknown SelectionKind = iota
	SelectionForced
	SelectionRule
	SelectionDefault
	SelectionRejected
)

type RouteStep struct {
	Leg            uint64
	Selection      SelectionKind
	Outbound       OutboundRef
	RuleTag        string
	Original       net.Destination
	RouteTarget    net.Destination
	SelectedTarget net.Destination
	Effective      net.Destination
	Truncated      bool
}

type FlowKind uint8

const (
	FlowKindUnknown FlowKind = iota
	FlowKindTCP
	FlowKindUDPAssociation
)

type FlowState uint8

const (
	FlowStateOpen FlowState = iota
	FlowStateStopRequested
	FlowStateEnded
)

type FlowRecord struct {
	Ref                FlowRef
	Kind               FlowKind
	Origin             TrafficOrigin
	Source             net.Destination
	InitialDestination net.Destination
	Opened             time.Duration
	AccountingRoute    RouteStep
	Routes             []RouteStep
	Destinations       []net.Destination
	Uplink             ByteFact
	Downlink           ByteFact
	State              FlowState
	MetadataTruncated  bool
}

type EndReason uint8

const (
	EndReasonUnknown EndReason = iota
	EndReasonEOF
	EndReasonLocalStop
	EndReasonTimeout
	EndReasonReadError
	EndReasonWriteError
	EndReasonRejected
)

type TerminalRecord struct {
	Flow   FlowRecord
	Ended  time.Duration
	Reason EndReason
}

type TotalRecord struct {
	Outbound OutboundRef
	Origin   TrafficOrigin
	Uplink   ByteFact
	Downlink ByteFact
}

type LossFacts struct {
	UntrackedAdmissions uint64
	BucketAdmissionLoss uint64
	TerminalOverwrite   uint64
	Saturated           bool
	MetadataTruncated   bool
}

type LiveSnapshot struct {
	Sample Sample
	Rows   []FlowRecord
	Loss   LossFacts
}

type TotalsSnapshot struct {
	Sample Sample
	Rows   []TotalRecord
	Loss   LossFacts
}

type TerminalSnapshot struct {
	Sample Sample
	Rows   []TerminalRecord
	Loss   LossFacts
}

type CloseCode uint8

const (
	CloseCodeAccepted CloseCode = iota
	CloseCodeAlreadyRequested
	CloseCodeAlreadyEnded
	CloseCodeStaleRuntime
	CloseCodeNotFound
	CloseCodeUnsupportedOwner
	CloseCodeFailed
	CloseCodeNotStartedCanceled
)

type CloseOutcome struct {
	Ref  FlowRef
	Code CloseCode
}

// FlowInspection is the optional direct-Go observation and local-control
// capability implemented by the native statistics manager.
type FlowInspection interface {
	Info() InspectionInfo
	ReadLive(context.Context) (LiveSnapshot, error)
	ReadTerminals(context.Context) (TerminalSnapshot, error)
	ReadTotals(context.Context) (TotalsSnapshot, error)
	CloseFlows(context.Context, []FlowRef) ([]CloseOutcome, error)
}

// ObservationProvider is an optional Manager capability. Observation returns
// nil unless collection was enabled before the instance started.
type ObservationProvider interface {
	Observation() AdmissionStore
	EnableInspection(ObservationOptions) (FlowInspection, error)
}

// AdmissionStore admits one decoded logical exchange. A nil stop callback
// keeps observation available while making exact local stop unsupported.
type AdmissionStore interface {
	Info() InspectionInfo
	Begin(FlowKind, TrafficOrigin, net.Destination, net.Destination, func() error) Exchange
	// PrepareTCP keeps endpoint facts local until the consuming role is known.
	// BindRoute/Unassign (or genuine failed completion) registers it once.
	PrepareTCP(TrafficOrigin, net.Destination, net.Destination, func() error) Exchange
}

// Exchange is the one logical receipt target shared by the endpoint, route and
// native owner. Root Finish publishes the current snapshot once; later byte
// facts still update the bound aggregate without changing that snapshot.
type Exchange interface {
	Ref() FlowRef
	// ExcludeCarrier suppresses an unregistered physical carrier's facts. False
	// means it was already registered;
	// an existing logical flow is never erased or claimed by this operation.
	ExcludeCarrier() bool
	// Rebind validates a retained endpoint's new carrier before enqueue. A
	// conflicting runtime/origin freezes later byte and destination attribution.
	Rebind(RuntimeID, TrafficOrigin)
	// NewLeg reserves one native UDP ray or one TCP request attempt under this
	// root. Its receipts keep their own consuming route, but share the root
	// reference and byte facts. Finish it after pending attribution is known.
	// Returns nil after stop. Do not mix root receipts with child legs.
	NewLeg() Exchange
	Route(RouteStep)
	// BindRoute is called by the consuming owner, after forwarding selections.
	BindRoute()
	// Unassign preserves known bytes when no consuming owner is proven.
	Unassign()
	Effective(net.Destination)
	// SetSource fills a source unavailable at admission once its native
	// association identifies the peer. It never changes an existing source.
	SetSource(net.Destination)
	// PacketDestination records requested logical destinations, not egress IPs.
	PacketDestination(net.Destination)
	AddUplink(uint64)
	AddDownlink(uint64)
	MarkUplinkIncomplete()
	MarkDownlinkIncomplete()
	SetEndReason(EndReason)
	Finish()
}
