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

// OutboundRef identifies the selected logical outbound tag.
type OutboundRef struct {
	Tag string
}

type ObservationOptions struct {
	MaxLive    uint32
	MaxBuckets uint32
}

type FlowRecord struct {
	Ref         FlowRef
	Kind        net.Network
	Origin      TrafficOrigin
	Source      net.Destination
	Destination net.Destination
	Opened      time.Duration
	Outbound    OutboundRef
	Uplink      uint64
	Downlink    uint64
}

// TotalRecord accumulates USER decoded I/O associated with one selected tag.
// Uplink enters when the selected execution consumes input (including sniff
// replay once); downlink enters at its actual decoded endpoint/callback output
// receipt. Selection alone and queued input add no bytes. Tag reuse continues
// the series. These boundaries need not equal User and imply no remote delivery.
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
	At time.Duration
	// User includes known decoded USER bytes independently of tag/live capacity,
	// including unassigned bytes and late receipts. Prepared TCP bytes enter on
	// logical classification (selection/unassignment/failed Finish), excluding
	// carriers. No coherent endpoint or remote-delivery view is promised.
	User ClientTotals
	// BucketsOmitted counts lifetime nonempty USER tag bindings refused by
	// MaxBuckets, not distinct tags or bytes. Existing buckets remain usable.
	BucketsOmitted uint64
	Rows           []TotalRecord
}

// ClientTotals is the store-lifetime decoded USER volume at existing endpoint
// receipt boundaries. Native counter resets do not reset it; a new store does.
type ClientTotals struct {
	Uplink   uint64
	Downlink uint64
}

// FlowInspection is the optional direct-Go observation and local-control
// capability implemented by the native statistics manager.
type FlowInspection interface {
	Runtime() RuntimeID
	// ReadLiveInto samples the full live inventory into caller-owned storage.
	// Pass nil for initial storage; retain returned Rows for subsequent reads.
	// Each reader owns its backing array exclusively. Passing it again invalidates
	// all prior aliases, including on error or replacement for capacity growth.
	// Pass previous Rows without shortening its length: occupied entries are
	// overwritten or cleared, including on error/replacement; spare capacity is
	// caller-managed. Retired rows are cleared once when the inventory shrinks.
	// Readers that retain earlier results must give later calls separate storage.
	// No cross-row atomicity is promised to the caller.
	ReadLiveInto(storage []FlowRecord) (LiveSnapshot, error)
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
	// PrepareTCP keeps endpoint facts local until a logical route is selected.
	// Route/Unassign (or genuine failed completion) registers it once.
	PrepareTCP(TrafficOrigin, net.Destination, net.Destination, func() error) Exchange
}

// Exchange is the one logical receipt target shared by the endpoint, route and
// native owner. Root Finish removes the live entry once; later byte facts still
// update the bound aggregate.
type Exchange interface {
	Ref() FlowRef
	// ExcludeCarrier suppresses a prepared physical carrier's facts.
	// False means it was already admitted as logical work and cannot be erased,
	// even if MaxLive prevented indexing it.
	ExcludeCarrier() bool
	// Rebind fences later attribution if a retained endpoint changes runtime or origin.
	Rebind(RuntimeID, TrafficOrigin)
	// NewLeg reserves one native UDP ray under this association root.
	// Legs share the root reference and byte facts, with independent route binding.
	// They have no separate observation lifetime; their Finish is a no-op.
	// Returns nil after stop.
	NewLeg() Exchange
	// Route captures the first selection for this exchange or UDP ray.
	// A UDP association displays the latest ray selection.
	Route(OutboundRef)
	Unassign()
	// SetSource fills a previously unknown source once.
	SetSource(net.Destination)
	// PacketDestination records the latest requested packet destination.
	PacketDestination(net.Destination)
	// RecordPacketInput commits one decoded packet's destination and uplink
	// bytes together for live sampling and provenance fencing.
	// Invalid destinations preserve the prior address; zero-byte packets may
	// still update it. Late bytes continue to update totals after root Finish.
	// Concurrent packets are ordered by commit, not arrival or route completion.
	RecordPacketInput(net.Destination, uint64)
	AddUplink(uint64)
	// AddSelectedUplink records decoded input returned to selected execution,
	// independently of general input admission. Cache/sniff and queue submission
	// do not call it; replay calls it once without repeating AddUplink.
	AddSelectedUplink(uint64)
	AddDownlink(uint64)
	Finish()
}
