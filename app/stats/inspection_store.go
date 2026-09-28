package stats

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

type aggregateKey struct {
	serial uint64
	origin featurestats.TrafficOrigin
}

type aggregateCell struct {
	outbound featurestats.OutboundRef
	origin   featurestats.TrafficOrigin
	uplink   atomic.Uint64
	downlink atomic.Uint64
}

func newAggregateCell(outbound featurestats.OutboundRef, origin featurestats.TrafficOrigin) *aggregateCell {
	return &aggregateCell{
		outbound: outbound,
		origin:   origin,
	}
}

type inspectionStore struct {
	runtime featurestats.RuntimeID
	limits  featurestats.ObservationOptions
	epoch   time.Time
	closed  atomic.Bool

	mu           sync.RWMutex
	live         map[uint64]*inspectionExchange
	buckets      map[aggregateKey]*aggregateCell
	unassigned   [4]*aggregateCell
	terminals    []featurestats.TerminalRecord
	terminalHead uint32
	nextID       uint64
}

func newInspectionStore(runtime featurestats.RuntimeID, limits featurestats.ObservationOptions) *inspectionStore {
	store := &inspectionStore{
		runtime: runtime,
		limits:  limits,
		epoch:   time.Now(),
		live:    make(map[uint64]*inspectionExchange),
		buckets: make(map[aggregateKey]*aggregateCell),
	}
	for i := range store.unassigned {
		origin := featurestats.TrafficOrigin(i)
		store.unassigned[i] = newAggregateCell(featurestats.OutboundRef{Runtime: runtime}, origin)
	}
	return store
}

func (s *inspectionStore) isClosed() bool {
	return s.closed.Load()
}

func (s *inspectionStore) elapsed() time.Duration {
	return time.Since(s.epoch)
}

func (s *inspectionStore) Runtime() featurestats.RuntimeID {
	return s.runtime
}

func (s *inspectionStore) Begin(kind xnet.Network, origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
	flow := s.prepare(kind, origin, source, destination, stop)
	if flow != nil {
		e := flow.(*inspectionExchange)
		e.mu.Lock()
		e.registerLocked()
		e.mu.Unlock()
	}
	return flow
}

func (s *inspectionStore) PrepareTCP(origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
	return s.prepare(xnet.Network_TCP, origin, source, destination, stop)
}

func (s *inspectionStore) prepare(kind xnet.Network, origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
	if s.closed.Load() {
		return nil
	}
	origin = normalizeOrigin(origin)
	exchange := &inspectionExchange{
		inspectionFlow: &inspectionFlow{
			store: s,
			stop:  stop,
			record: featurestats.FlowRecord{
				Kind:               kind,
				Origin:             origin,
				Source:             source,
				InitialDestination: destination,
				Opened:             s.elapsed(),
			},
		},
	}
	return exchange
}

// Native endpoint owners retain unregistered receipts themselves. There is no
// pending index; the existing live map only owns classified logical exchanges.
func (e *inspectionExchange) registerLocked() {
	if e.registered || e.excluded {
		return
	}
	e.registered = true
	s := e.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return
	}
	if uint32(len(s.live)) >= s.limits.MaxLive {
		return
	}
	s.nextID++
	e.record.Ref = featurestats.FlowRef{Runtime: s.runtime, ID: s.nextID}
	s.live[s.nextID] = e
}

func (s *inspectionStore) ReadLive() (featurestats.LiveSnapshot, error) {
	if s.closed.Load() {
		return featurestats.LiveSnapshot{}, errors.New("inspection closed")
	}
	s.mu.RLock()
	rows := make([]*inspectionExchange, 0, len(s.live))
	for _, exchange := range s.live {
		rows = append(rows, exchange)
	}
	s.mu.RUnlock()

	result := make([]featurestats.FlowRecord, 0, len(rows))
	for _, exchange := range rows {
		exchange.mu.Lock()
		if !exchange.published {
			result = append(result, exchange.record)
		}
		exchange.mu.Unlock()
	}
	return featurestats.LiveSnapshot{
		At:   s.elapsed(),
		Rows: result,
	}, nil
}

func (s *inspectionStore) ReadTotals() (featurestats.TotalsSnapshot, error) {
	if s.closed.Load() {
		return featurestats.TotalsSnapshot{}, errors.New("inspection closed")
	}
	s.mu.RLock()
	cells := make([]*aggregateCell, 0, len(s.buckets)+len(s.unassigned))
	for _, cell := range s.unassigned {
		cells = append(cells, cell)
	}
	for _, cell := range s.buckets {
		cells = append(cells, cell)
	}
	s.mu.RUnlock()

	rows := make([]featurestats.TotalRecord, 0, len(cells))
	for _, cell := range cells {
		rows = append(rows, featurestats.TotalRecord{
			Outbound: cell.outbound,
			Origin:   cell.origin,
			Uplink:   cell.uplink.Load(),
			Downlink: cell.downlink.Load(),
		})
	}
	return featurestats.TotalsSnapshot{
		At:   s.elapsed(),
		Rows: rows,
	}, nil
}

func (s *inspectionStore) ReadTerminals() (featurestats.TerminalSnapshot, error) {
	if s.closed.Load() {
		return featurestats.TerminalSnapshot{}, errors.New("inspection closed")
	}

	s.mu.RLock()
	rows := make([]featurestats.TerminalRecord, 0, len(s.terminals))
	for i := 0; i < len(s.terminals); i++ {
		rows = append(rows, s.terminals[(int(s.terminalHead)+i)%len(s.terminals)])
	}
	s.mu.RUnlock()
	return featurestats.TerminalSnapshot{
		At:   s.elapsed(),
		Rows: rows,
	}, nil
}

func (s *inspectionStore) CloseFlows(ctx context.Context, refs []featurestats.FlowRef) ([]featurestats.CloseOutcome, error) {
	if s.closed.Load() {
		return nil, errors.New("inspection closed")
	}
	outcomes := make([]featurestats.CloseOutcome, len(refs))
	for i, ref := range refs {
		outcomes[i].Ref = ref
		if err := ctx.Err(); err != nil {
			outcomes[i].Err = err
			continue
		}
		if ref.Runtime != s.runtime {
			continue
		}
		exchange := s.lookup(ref.ID)
		if exchange == nil {
			continue
		}
		stop, err := exchange.requestStop()
		if err != nil {
			outcomes[i].Err = err
			continue
		}
		if stop == nil {
			continue
		}
		err = stop()
		exchange.Finish()
		outcomes[i].Err = err
	}
	return outcomes, nil
}

func (s *inspectionStore) lookup(id uint64) *inspectionExchange {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if exchange := s.live[id]; exchange != nil {
		return exchange
	}
	return nil
}

func (s *inspectionStore) bucketFor(outbound featurestats.OutboundRef, origin featurestats.TrafficOrigin) *aggregateCell {
	if outbound.Serial == 0 {
		return s.unassigned[int(origin)]
	}
	key := aggregateKey{serial: outbound.Serial, origin: origin}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cell := s.buckets[key]; cell != nil {
		return cell
	}
	if s.closed.Load() {
		return s.unassigned[int(origin)]
	}
	if uint32(len(s.buckets)) >= s.limits.MaxBuckets {
		return s.unassigned[int(origin)]
	}
	cell := newAggregateCell(outbound, origin)
	s.buckets[key] = cell
	return cell
}

func (s *inspectionStore) publish(exchange *inspectionExchange, terminal featurestats.TerminalRecord) {
	if terminal.Flow.Ref.ID == 0 || s.closed.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live[terminal.Flow.Ref.ID] != exchange {
		return
	}
	delete(s.live, terminal.Flow.Ref.ID)
	if uint32(len(s.terminals)) < s.limits.MaxTerminals {
		if len(s.terminals) == cap(s.terminals) {
			capacity := min(int(s.limits.MaxTerminals), max(1, 2*cap(s.terminals)))
			grown := make([]featurestats.TerminalRecord, len(s.terminals), capacity)
			copy(grown, s.terminals)
			s.terminals = grown
		}
		s.terminals = append(s.terminals, terminal)
		return
	}
	s.terminals[s.terminalHead] = terminal
	s.terminalHead = (s.terminalHead + 1) % uint32(len(s.terminals))
}

func (s *inspectionStore) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	s.live = nil
	s.buckets = nil
	s.terminals = nil
	s.terminalHead = 0
	s.mu.Unlock()
}

// One association owns the visible values and lock. Native rays retain only
// their attribution and completion state; no historical ray list is kept.
type inspectionFlow struct {
	store              *inspectionStore
	registered         bool
	stop               func() error
	stopRequested      bool
	mu                 sync.Mutex
	record             featurestats.FlowRecord
	routeSerial        uint64
	provenanceConflict bool
}

type inspectionExchange struct {
	*inspectionFlow
	isLeg            bool
	hasLegs          bool
	route            featurestats.OutboundRef
	routeSeq         uint64
	pending          *pendingCredit
	bucket           *aggregateCell
	published        bool
	excluded         bool
	finishRequested  bool
	selectedReturned bool
}

// Only a ray with unbound receipts needs numeric pending credit. The ordinary
// single-leg endpoint continues to use its authoritative flow cells directly.
type pendingCredit struct {
	up, down uint64
}

func (e *inspectionExchange) NewLeg() featurestats.Exchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.isLeg || (e.record.Kind != xnet.Network_UDP && e.record.Kind != xnet.Network_TCP) || e.stopRequested || e.published {
		return nil
	}
	e.hasLegs = true
	pending := &pendingCredit{}
	return &inspectionExchange{inspectionFlow: e.inspectionFlow, isLeg: true, pending: pending}
}

func (e *inspectionExchange) Ref() featurestats.FlowRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.record.Ref
}

func (e *inspectionExchange) ExcludeCarrier() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isLeg || (e.registered && e.record.Ref != (featurestats.FlowRef{})) {
		return false
	}
	e.excluded = true
	return true
}

func (e *inspectionExchange) Route(outbound featurestats.OutboundRef) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published {
		return
	}
	e.commitPendingLocked()
	outbound.Runtime = e.store.runtime
	e.routeSerial++
	e.routeSeq = e.routeSerial
	e.record.Outbound = outbound
	e.record.EffectiveDestination = xnet.Destination{}
	if e.bucket == nil {
		e.route = outbound
	}
}

func (e *inspectionExchange) BindRoute() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.published {
		e.bindLocked(e.route)
	}
}

func (e *inspectionExchange) Unassign() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.published {
		e.bindLocked(featurestats.OutboundRef{})
	}
}

func (e *inspectionExchange) bindLocked(outbound featurestats.OutboundRef) {
	if e.excluded || e.bucket != nil {
		return
	}
	e.commitPendingLocked()
	if !e.isLeg {
		e.registerLocked()
	}
	outbound.Runtime = e.store.runtime
	e.route = outbound
	bucket := e.store.bucketFor(outbound, e.record.Origin)
	e.bucket = bucket
	up, down := e.record.Uplink, e.record.Downlink
	if e.pending != nil {
		up, down = e.pending.up, e.pending.down
	}
	bucket.uplink.Add(up)
	bucket.downlink.Add(down)
	e.pending = nil
}

func (e *inspectionExchange) Effective(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.routeSeq == 0 || e.routeSeq != e.routeSerial {
		return
	}
	e.record.EffectiveDestination = destination
}

func (e *inspectionExchange) SetSource(source xnet.Destination) {
	if !source.IsValid() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.isLeg || e.record.Source.IsValid() {
		return
	}
	e.record.Source = source
}

func (e *inspectionExchange) PacketDestination(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.provenanceConflict || !destination.IsValid() {
		return
	}
	e.record.LatestDestination = destination
}

func (e *inspectionExchange) AddUplink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if e.isLeg && e.pending != nil && e.routeSeq == 0 {
		e.pending.up += value
		return
	}
	e.record.Uplink += value
	if e.bucket != nil {
		e.bucket.uplink.Add(value)
	} else if e.pending != nil {
		e.pending.up += value
	}
}

func (e *inspectionExchange) AddDownlink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if e.isLeg && e.pending != nil && e.routeSeq == 0 {
		e.pending.down += value
		return
	}
	e.record.Downlink += value
	if e.bucket != nil {
		e.bucket.downlink.Add(value)
	} else if e.pending != nil {
		e.pending.down += value
	}
}

func (e *inspectionExchange) Rebind(runtime featurestats.RuntimeID, origin featurestats.TrafficOrigin) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.provenanceConflict {
		return
	}
	if runtime != e.store.runtime ||
		normalizeOrigin(origin) == featurestats.TrafficOriginUnknown || origin != e.record.Origin {
		e.provenanceConflict = true
	}
}

func (e *inspectionExchange) Finish() {
	var terminal *featurestats.TerminalRecord
	e.mu.Lock()
	if e.isLeg {
		e.finishRequested = true
	}
	terminal = e.completeLocked()
	e.mu.Unlock()
	if terminal != nil {
		e.store.publish(e, *terminal)
	}
}

// FinishSelectedLeg settles a UDP leg after the selected handler returns. It
// is intentionally absent from the public Exchange contract: only the native
// dispatcher selection point can distinguish this event from an early endpoint
// reader Finish racing asynchronous routing.
func (e *inspectionExchange) FinishSelectedLeg() {
	e.mu.Lock()
	if !e.isLeg {
		e.mu.Unlock()
		return
	}
	e.selectedReturned = true
	terminal := e.completeLocked()
	e.mu.Unlock()
	if terminal != nil {
		e.store.publish(e, *terminal)
	}
}

func (e *inspectionExchange) requestStop() (func() error, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.published || e.stopRequested {
		return nil, nil
	}
	if e.stop == nil {
		return nil, errors.ErrUnsupported
	}
	e.stopRequested = true
	return e.stop, nil
}

func (e *inspectionExchange) completeLocked() *featurestats.TerminalRecord {
	if e.published {
		return nil
	}
	if e.excluded {
		e.published = true
		e.stop = nil
		return nil
	}
	if e.isLeg && e.pending != nil {
		// DefaultDispatcher selects asynchronously after returning the link. A
		// native UDP reader may end before Route or BindRoute, so do not guess
		// that the still-pending selected role is unassigned. Only a marked
		// synchronous handler return may settle a selected no-claim leg.
		if !e.selectedReturned {
			return nil
		}
		e.bindLocked(featurestats.OutboundRef{})
	}
	if e.bucket == nil && !e.hasLegs {
		e.bindLocked(featurestats.OutboundRef{})
	}
	if e.isLeg && !e.finishRequested {
		return nil
	}
	e.published = true
	if e.isLeg {
		return nil
	}
	// Owner-end disables stop; late byte receipts only need the accounting state.
	e.stop = nil
	flow := e.record
	return &featurestats.TerminalRecord{Flow: flow, Ended: e.store.elapsed()}
}

func (e *inspectionExchange) commitPendingLocked() {
	if e.pending == nil || e.routeSeq != 0 {
		return
	}
	e.record.Uplink += e.pending.up
	e.record.Downlink += e.pending.down
}

func normalizeOrigin(origin featurestats.TrafficOrigin) featurestats.TrafficOrigin {
	switch origin {
	case featurestats.TrafficOriginUser, featurestats.TrafficOriginInternal, featurestats.TrafficOriginControlledMeasurement:
		return origin
	default:
		return featurestats.TrafficOriginUnknown
	}
}
