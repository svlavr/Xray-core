package dispatcher

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
)

// UserConnection is one explicitly admitted TCP dispatch, not a carrier or
// remote session. IDs are unique only within this dispatcher. Byte counts use
// the declared reader/writer boundary; they are not transport-completion receipts.
type UserConnection struct {
	ID                   uint64
	Started              time.Time
	Source               string
	InboundTag           string
	Destination          string
	RouteTarget          string
	OutboundTag          string
	OutboundSelected     bool
	RuleTag              string
	UplinkReadBytes      int64
	DownlinkWrittenBytes int64
	UplinkCoverage       ByteCoverage
	DownlinkCoverage     ByteCoverage
}

// ByteCoverage qualifies a count; only BytesExact permits interpreting zero
// at its declared boundary. Counts are sampled independently across directions.
type ByteCoverage uint8

const (
	BytesUnavailable ByteCoverage = iota
	BytesExact
	BytesDeferredRawCopy
	BytesOverflow
)

type flowByteCounter struct {
	appstats.Counter
	forward  stats.Counter
	deferred atomic.Bool
	overflow atomic.Bool
	tracker  *connectionTracker
	total    atomic.Pointer[outboundByteTotal]
	// Resolved also covers a selected request omitted by totals capacity.
	totalBindingResolved atomic.Bool
}

func (c *flowByteCounter) addOwn(n int64) int64 {
	if c.tracker != nil && !c.totalBindingResolved.Load() {
		c.tracker.Lock()
		defer c.tracker.Unlock()
		if c.tracker.closed {
			c.totalBindingResolved.Store(true)
		}
	}
	if total := c.total.Load(); total != nil {
		total.add(n)
	}
	value := c.Counter.Add(n)
	if n < 0 || value < 0 {
		c.overflow.Store(true)
	}
	return value
}

func (c *flowByteCounter) Add(n int64) int64 {
	value := c.addOwn(n)
	if c.forward != nil {
		c.forward.Add(n)
	}
	return value
}

func (c *flowByteCounter) sample() (int64, ByteCoverage) {
	if c == nil {
		return 0, BytesUnavailable
	}
	deferred := c.deferred.Load()
	value := c.Value()
	if value < 0 || c.overflow.Load() {
		return value, BytesOverflow
	}
	if deferred {
		return value, BytesDeferredRawCopy
	}
	return value, BytesExact
}

type connectionEntry struct {
	UserConnection
	uplink, downlink *flowByteCounter
}

// BeginRawCopy marks the bypass as deferred and counts only this observation's
// final n. Native connection counters are updated separately, without forwarding.
func (c *flowByteCounter) BeginRawCopy() func(int64) {
	c.setDeferred(true)
	return func(n int64) {
		c.addOwn(n)
		c.setDeferred(false)
	}
}

// ConnectionSnapshot covers explicit DispatchUserStream calls only. The native
// caller currently covered is SOCKS TCP CONNECT; empty is not proof of no other
// traffic. Dropped counts admissions omitted due to capacity or ID exhaustion.
type ConnectionSnapshot struct {
	Enabled     bool
	Closed      bool
	Limit       int
	Dropped     uint64
	Connections []UserConnection
	// Totals have the same USER TCP and byte boundaries as Connections, but
	// include retired requests and requests omitted from the live index.
	OutboundTotals []UserOutboundTotal
	// TotalsDropped counts selected requests omitted by distinct-tag capacity.
	// An absent bucket never proves zero traffic. Limit caps each map separately.
	TotalsDropped uint64
}

type connectionTracker struct {
	sync.Mutex
	enabled       bool
	closed        bool
	limit         int
	next          uint64
	dropped       uint64
	live          map[uint64]*connectionEntry
	totals        map[string]*outboundTotal
	totalsDropped uint64
}

// EnableConnectionTracking enables this dispatcher's bounded user TCP snapshot
// once. Limit separately caps live rows and historical outbound tags. It does
// not discover already running requests. Tracking is off by default.
func (d *DefaultDispatcher) EnableConnectionTracking(limit int) error {
	if limit <= 0 {
		return errors.New("connection tracking limit must be positive")
	}
	t := &d.connections
	t.Lock()
	defer t.Unlock()
	if t.closed || t.enabled {
		return errors.New("connection tracking already enabled or dispatcher closed")
	}
	t.enabled, t.limit = true, limit
	t.live = make(map[uint64]*connectionEntry)
	t.totals = make(map[string]*outboundTotal)
	return nil
}

// ConnectionSnapshot returns detached metadata sorted by admission ID.
func (d *DefaultDispatcher) ConnectionSnapshot() ConnectionSnapshot {
	return d.connectionSnapshot(time.Now)
}

func (d *DefaultDispatcher) connectionSnapshot(sampleTime func() time.Time) ConnectionSnapshot {
	t := &d.connections
	t.Lock()
	s := ConnectionSnapshot{Enabled: t.enabled, Closed: t.closed, Limit: t.limit, Dropped: t.dropped, TotalsDropped: t.totalsDropped}
	s.Connections = make([]UserConnection, 0, len(t.live))
	for _, row := range t.live {
		copy := row.UserConnection
		copy.UplinkReadBytes, copy.UplinkCoverage = row.uplink.sample()
		copy.DownlinkWrittenBytes, copy.DownlinkCoverage = row.downlink.sample()
		s.Connections = append(s.Connections, copy)
	}
	for tag, total := range t.totals {
		s.OutboundTotals = append(s.OutboundTotals, total.snapshot(tag, sampleTime))
	}
	t.Unlock()
	sort.Slice(s.Connections, func(i, j int) bool { return s.Connections[i].ID < s.Connections[j].ID })
	sort.Slice(s.OutboundTotals, func(i, j int) bool { return s.OutboundTotals[i].OutboundTag < s.OutboundTotals[j].OutboundTag })
	return s
}

func (t *connectionTracker) begin(ctx context.Context, dest net.Destination) *connectionEntry {
	t.Lock()
	defer t.Unlock()
	if !t.enabled || t.closed || ctx.Err() != nil {
		return nil
	}
	row := &connectionEntry{}
	if len(t.live) >= t.limit || t.next == math.MaxUint64 {
		if t.dropped != math.MaxUint64 {
			t.dropped++
		}
		return row // Request-owned counters still contribute to totals.
	}
	t.next++
	row.UserConnection = UserConnection{ID: t.next, Started: time.Now(), Destination: dest.String()}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if inbound.Source.IsValid() {
			row.Source = inbound.Source.String()
		}
		row.InboundTag = inbound.Tag
	}
	t.live[row.ID] = row
	return row
}

func (t *connectionTracker) selected(row *connectionEntry, tag, rule string, target net.Destination) {
	if row == nil {
		return
	}
	t.Lock()
	defer t.Unlock()
	if !t.closed && !row.OutboundSelected {
		row.OutboundTag, row.RuleTag, row.RouteTarget = tag, rule, target.String()
		row.OutboundSelected = true
		t.bindTotals(row, tag)
	}
}

func (t *connectionTracker) end(row *connectionEntry) {
	if row == nil {
		return
	}
	t.Lock()
	delete(t.live, row.ID)
	t.Unlock()
}

func (t *connectionTracker) close() {
	t.Lock()
	t.closed = true
	t.live = nil
	t.totals = nil
	t.Unlock()
}
