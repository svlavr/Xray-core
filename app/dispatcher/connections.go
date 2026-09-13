package dispatcher

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// UserConnection is one explicitly admitted TCP dispatch, not a carrier or
// remote session. IDs are unique only within this dispatcher. No byte counts
// or transport-completion claims are provided by this first observation slice.
type UserConnection struct {
	ID               uint64
	Started          time.Time
	Source           string
	InboundTag       string
	Destination      string
	RouteTarget      string
	OutboundTag      string
	OutboundSelected bool
	RuleTag          string
}

// ConnectionSnapshot covers explicit DispatchUserLink calls only. The native
// caller currently covered is SOCKS TCP CONNECT; empty is not proof of no other
// traffic. Dropped counts admissions omitted due to capacity or ID exhaustion.
type ConnectionSnapshot struct {
	Enabled     bool
	Closed      bool
	Limit       int
	Dropped     uint64
	Connections []UserConnection
}

type connectionTracker struct {
	sync.Mutex
	enabled bool
	closed  bool
	limit   int
	next    uint64
	dropped uint64
	live    map[uint64]UserConnection
}

// EnableConnectionTracking enables this dispatcher's bounded user TCP snapshot
// once. It does not discover already running requests. Tracking is off by default.
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
	t.live = make(map[uint64]UserConnection)
	return nil
}

// ConnectionSnapshot returns detached metadata sorted by admission ID.
func (d *DefaultDispatcher) ConnectionSnapshot() ConnectionSnapshot {
	t := &d.connections
	t.Lock()
	s := ConnectionSnapshot{Enabled: t.enabled, Closed: t.closed, Limit: t.limit, Dropped: t.dropped}
	s.Connections = make([]UserConnection, 0, len(t.live))
	for _, row := range t.live {
		s.Connections = append(s.Connections, row)
	}
	t.Unlock()
	sort.Slice(s.Connections, func(i, j int) bool { return s.Connections[i].ID < s.Connections[j].ID })
	return s
}

// DispatchUserLink observes an explicit USER TCP admission around synchronous
// DispatchLink. Metadata/markers in context never infer USER for ordinary calls.
// Observation neither wraps I/O nor alters cancellation or routing behavior.
func (d *DefaultDispatcher) DispatchUserLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if !dest.IsValid() || dest.Network != net.Network_TCP {
		return errors.New("user connection observation requires a valid TCP destination")
	}
	id := d.connections.begin(ctx, dest)
	if id != 0 {
		defer d.connections.end(id)
	}
	return d.dispatchLink(ctx, dest, link, id)
}

func (t *connectionTracker) begin(ctx context.Context, dest net.Destination) uint64 {
	t.Lock()
	defer t.Unlock()
	if !t.enabled || t.closed || ctx.Err() != nil {
		return 0
	}
	if len(t.live) >= t.limit || t.next == math.MaxUint64 {
		if t.dropped != math.MaxUint64 {
			t.dropped++
		}
		return 0
	}
	t.next++
	row := UserConnection{ID: t.next, Started: time.Now(), Destination: dest.String()}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if inbound.Source.IsValid() {
			row.Source = inbound.Source.String()
		}
		row.InboundTag = inbound.Tag
	}
	t.live[row.ID] = row
	return row.ID
}

func (t *connectionTracker) selected(id uint64, tag, rule string, target net.Destination) {
	if id == 0 {
		return
	}
	t.Lock()
	defer t.Unlock()
	if row, ok := t.live[id]; ok {
		row.OutboundTag, row.RuleTag, row.RouteTarget = tag, rule, target.String()
		row.OutboundSelected = true
		t.live[id] = row
	}
}

func (t *connectionTracker) end(id uint64) {
	t.Lock()
	delete(t.live, id)
	t.Unlock()
}

func (t *connectionTracker) close() {
	t.Lock()
	t.closed = true
	t.live = nil
	t.Unlock()
}
