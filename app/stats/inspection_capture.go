package stats

import (
	"errors"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

// A capture owns only a bounded transfer queue. Traffic never invokes consumer
// code; a full queue drops the incoming fact and increments an out-of-band count.
type observationCapture struct {
	mu      sync.Mutex
	store   *inspectionStore
	epoch   time.Time
	started time.Duration
	ended   time.Duration
	stopped bool
	dropped uint64
	rows    []fs.FlowObservation
}

func (s *inspectionStore) CaptureObservations(capacity uint32) (fs.ObservationCapture, error) {
	if capacity == 0 || uint64(capacity) > uint64(^uint(0)>>1) {
		return nil, errors.New("invalid observation capacity")
	}
	s.mu.Lock()
	if s.live == nil || s.capture.Load() != nil {
		s.mu.Unlock()
		return nil, errors.New("inspection closed or capture already active")
	}
	c := &observationCapture{store: s, epoch: s.epoch, started: s.elapsed(), rows: make([]fs.FlowObservation, 0, int(capacity))}
	s.capture.Store(c)
	existing := make([]*inspectionExchange, 0, len(s.live))
	for _, e := range s.live {
		existing = append(existing, e)
	}
	s.mu.Unlock()
	// Never hold the store lock while taking a flow lock. Concurrent facts may
	// precede this baseline; Existing is a sample, not a replay or open event.
	for _, e := range existing {
		e.mu.Lock()
		if !e.published {
			e.captureLocked(c, fs.ObservationExisting)
		}
		e.mu.Unlock()
	}
	return c, nil
}

func (c *observationCapture) ReadInto(storage []fs.FlowObservation) fs.ObservationBatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	rows := storage[:0]
	if rows == nil || cap(rows) < len(c.rows) {
		clear(storage)
		rows = make([]fs.FlowObservation, 0, len(c.rows))
	}
	rows = append(rows, c.rows...)
	if len(rows) < len(storage) {
		clear(storage[len(rows):])
	}
	clear(c.rows)
	c.rows = c.rows[:0]
	return fs.ObservationBatch{Started: c.started, Ended: c.ended, At: time.Since(c.epoch), Stopped: c.stopped, Dropped: c.dropped, ExistingPartial: true, Rows: rows}
}

func (c *observationCapture) Close() error {
	c.mu.Lock()
	s := c.store
	c.store = nil
	if !c.stopped {
		c.ended = time.Since(c.epoch)
	}
	c.stopped = true
	c.mu.Unlock()
	if s != nil {
		s.capture.CompareAndSwap(c, nil)
	}
	return nil
}

func (e *inspectionExchange) observeLocked(kind fs.ObservationKind) {
	if c := e.store.capture.Load(); c != nil {
		e.captureLocked(c, kind)
	}
}

func (e *inspectionExchange) captureLocked(c *observationCapture, kind fs.ObservationKind) {
	if e.excluded || e.provenanceConflict || (!e.admitted && e.rayID == 0) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	if e.observationID == 0 {
		e.observationID = e.store.nextObservation.Add(1)
	}
	if len(c.rows) == cap(c.rows) {
		c.dropped++
		return
	}
	flow := e.record
	// Shared live values are only a display. Capture pairs facts on their native
	// receipt owner, including late receipts from an older selected UDP ray.
	flow.Outbound = e.selectedOutbound
	if e.rayID != 0 {
		flow.Destination = e.rayDestination
	} else if flow.Kind == xnet.Network_UDP && e.nextRayID != 0 {
		flow.Outbound = fs.OutboundRef{}
	}
	selected := e.selected
	if e.rayID == 0 && flow.Kind == xnet.Network_UDP && e.nextRayID != 0 {
		selected = false // Root latest destination has no single selected ray.
	}
	c.rows = append(c.rows, fs.FlowObservation{Kind: kind, FlowID: e.observationID, RayID: e.rayID, At: e.store.elapsed(), Flow: flow, Selected: selected})
}
