package stats

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/net"
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

// OutboundRef identifies a handler within its owning FlowInspection view.
type OutboundRef struct {
	Serial uint64
	Tag    string
}

type ObservationOptions struct {
	MaxLive      uint32
	MaxTerminals uint32
	MaxBuckets   uint32
}

type FlowRecord struct {
	Ref                  FlowRef
	Kind                 net.Network
	Origin               TrafficOrigin
	Source               net.Destination
	InitialDestination   net.Destination
	Opened               time.Duration
	Outbound             OutboundRef
	EffectiveDestination net.Destination
	LatestDestination    net.Destination
	Uplink               uint64
	Downlink             uint64
}

type TerminalRecord struct {
	Flow  FlowRecord
	Ended time.Duration
}

type TotalRecord struct {
	Outbound OutboundRef
	Origin   TrafficOrigin
	Uplink   uint64
	Downlink uint64
}

type LiveSnapshot struct {
	At   time.Duration
	Rows []FlowRecord
}

type TotalsSnapshot struct {
	At   time.Duration
	Rows []TotalRecord
}

type TerminalSnapshot struct {
	At   time.Duration
	Rows []TerminalRecord
}

// FlowInspection is the optional direct-Go observation and local-control
// capability implemented by the native statistics manager.
type FlowInspection interface {
	Runtime() RuntimeID
	ReadLive() (LiveSnapshot, error)
	ReadTerminals() (TerminalSnapshot, error)
	ReadTotals() (TotalsSnapshot, error)
	// CloseFlows returns one error per input ref, in the same order.
	// Nil includes an already absent or stopped flow; a closed store returns
	// a top-level error without per-flow results.
	CloseFlows(context.Context, []FlowRef) ([]error, error)
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
	Runtime() RuntimeID
	Begin(net.Network, TrafficOrigin, net.Destination, net.Destination, func() error) Exchange
	// PrepareTCP keeps endpoint facts local until the consuming role is known.
	// BindRoute/Unassign (or genuine failed completion) registers it once.
	PrepareTCP(TrafficOrigin, net.Destination, net.Destination, func() error) Exchange
}

// Exchange is the one logical receipt target shared by the endpoint, route and
// native owner. Root Finish publishes the current snapshot once; later byte
// facts still update the bound aggregate without changing that snapshot.
type Exchange interface {
	Ref() FlowRef
	// ExcludeCarrier suppresses an unregistered physical carrier's facts.
	// False means it was already registered and cannot be erased.
	ExcludeCarrier() bool
	// Rebind fences later attribution if a retained endpoint changes runtime or origin.
	Rebind(RuntimeID, TrafficOrigin)
	// NewLeg reserves one native UDP ray or TCP attempt under this root.
	// Legs share the root reference and byte facts, but own their route and Finish.
	// Returns nil after stop.
	NewLeg() Exchange
	Route(OutboundRef)
	// BindRoute is called after the consuming owner is selected.
	BindRoute()
	Unassign()
	Effective(net.Destination)
	// SetSource fills a previously unknown source once.
	SetSource(net.Destination)
	// PacketDestination records the latest requested packet destination.
	PacketDestination(net.Destination)
	AddUplink(uint64)
	AddDownlink(uint64)
	Finish()
}
