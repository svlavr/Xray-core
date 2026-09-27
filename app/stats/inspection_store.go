package stats

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

const maxMetadataString = 255

type byteCell struct {
	known saturatingUint64
}

func (c *byteCell) addKnown(value uint64) {
	if value == 0 {
		return
	}
	c.known.add(value)
}

func (c *byteCell) snapshot() featurestats.ByteFact {
	return featurestats.ByteFact{Known: c.known.load()}
}

type aggregateKey struct {
	serial uint64
	origin featurestats.TrafficOrigin
}

type aggregateCell struct {
	outbound featurestats.OutboundRef
	origin   featurestats.TrafficOrigin
	uplink   byteCell
	downlink byteCell
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

func (s *inspectionStore) Info() featurestats.InspectionInfo {
	return featurestats.InspectionInfo{Runtime: s.runtime}
}

func (s *inspectionStore) Begin(kind featurestats.FlowKind, origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
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
	return s.prepare(featurestats.FlowKindTCP, origin, source, destination, stop)
}

func (s *inspectionStore) prepare(kind featurestats.FlowKind, origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
	if s.closed.Load() {
		return nil
	}
	origin = normalizeOrigin(origin)
	source = cloneDestination(source)
	destination = cloneDestination(destination)

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
				State:              featurestats.FlowStateOpen,
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
	if uint32(len(s.live)) >= s.limits.MaxLive || s.nextID == math.MaxUint64 {
		return
	}
	s.nextID++
	e.record.Ref = featurestats.FlowRef{Runtime: s.runtime, ID: s.nextID}
	s.live[s.nextID] = e
}

func (s *inspectionStore) ReadLive() (featurestats.LiveSnapshot, error) {
	if s.closed.Load() {
		return featurestats.LiveSnapshot{}, featurestats.ErrInspectionClosed
	}
	s.mu.RLock()
	rows := make([]*inspectionExchange, 0, len(s.live))
	for _, exchange := range s.live {
		rows = append(rows, exchange)
	}
	s.mu.RUnlock()

	result := make([]featurestats.FlowRecord, 0, len(rows))
	for _, exchange := range rows {
		row := exchange.snapshot()
		if row.State != featurestats.FlowStateEnded {
			result = append(result, row)
		}
	}
	return featurestats.LiveSnapshot{
		Sample: featurestats.Sample{Runtime: s.runtime, At: s.elapsed()},
		Rows:   result,
	}, nil
}

func (s *inspectionStore) ReadTotals() (featurestats.TotalsSnapshot, error) {
	if s.closed.Load() {
		return featurestats.TotalsSnapshot{}, featurestats.ErrInspectionClosed
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
			Uplink:   cell.uplink.snapshot(),
			Downlink: cell.downlink.snapshot(),
		})
	}
	return featurestats.TotalsSnapshot{
		Sample: featurestats.Sample{Runtime: s.runtime, At: s.elapsed()},
		Rows:   rows,
	}, nil
}

func (s *inspectionStore) ReadTerminals() (featurestats.TerminalSnapshot, error) {
	if s.closed.Load() {
		return featurestats.TerminalSnapshot{}, featurestats.ErrInspectionClosed
	}

	s.mu.RLock()
	rows := make([]featurestats.TerminalRecord, 0, len(s.terminals))
	for i := 0; i < len(s.terminals); i++ {
		rows = append(rows, s.terminals[(int(s.terminalHead)+i)%len(s.terminals)])
	}
	s.mu.RUnlock()
	return featurestats.TerminalSnapshot{
		Sample: featurestats.Sample{Runtime: s.runtime, At: s.elapsed()},
		Rows:   rows,
	}, nil
}

func (s *inspectionStore) CloseFlows(ctx context.Context, refs []featurestats.FlowRef) ([]featurestats.CloseOutcome, error) {
	if s.closed.Load() {
		return nil, featurestats.ErrInspectionClosed
	}
	if len(refs) > int(s.limits.MaxClose) {
		return nil, fmt.Errorf("%w: close batch", featurestats.ErrInspectionLimit)
	}
	outcomes := make([]featurestats.CloseOutcome, len(refs))
	for i, ref := range refs {
		outcomes[i].Ref = ref
		if ctx.Err() != nil {
			outcomes[i].Code = featurestats.CloseCodeNotStartedCanceled
			continue
		}
		if ref.Runtime != s.runtime {
			outcomes[i].Code = featurestats.CloseCodeStaleRuntime
			continue
		}
		exchange := s.lookup(ref.ID)
		if exchange == nil {
			outcomes[i].Code = featurestats.CloseCodeNoAction
			continue
		}
		stop, code := exchange.requestStop()
		outcomes[i].Code = code
		if stop == nil {
			continue
		}
		err := stop()
		exchange.Finish()
		if err != nil {
			outcomes[i].Code = featurestats.CloseCodeFailed
			outcomes[i].Err = err
		}
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

func (s *inspectionStore) bucketFor(step featurestats.RouteStep, origin featurestats.TrafficOrigin) *aggregateCell {
	if step.Outbound.Serial == 0 || step.Outbound.Runtime != s.runtime {
		return s.unassigned[int(origin)]
	}
	key := aggregateKey{serial: step.Outbound.Serial, origin: origin}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cell := s.buckets[key]; cell != nil {
		return cell
	}
	if s.closed.Load() || s.buckets == nil {
		return s.unassigned[int(origin)]
	}
	if uint32(len(s.buckets)) >= s.limits.MaxBuckets {
		return s.unassigned[int(origin)]
	}
	cell := newAggregateCell(step.Outbound, origin)
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
	mu                 sync.Mutex
	record             featurestats.FlowRecord
	routeSerial        uint64
	selectedSerial     uint64
	provenanceConflict bool
}

type inspectionExchange struct {
	*inspectionFlow
	isLeg            bool
	hasLegs          bool
	route            featurestats.RouteStep
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

	classified bool
	settled    bool
}

func addKnown(value *uint64, n uint64) {
	if n > math.MaxUint64-*value {
		*value = math.MaxUint64
		return
	}
	*value += n
}

func (e *inspectionExchange) NewLeg() featurestats.Exchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.isLeg || (e.record.Kind != featurestats.FlowKindUDPAssociation && e.record.Kind != featurestats.FlowKindTCP) || e.record.State == featurestats.FlowStateStopRequested || e.published {
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

func (e *inspectionExchange) Route(step featurestats.RouteStep) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.store == nil {
		return
	}
	e.commitPendingLocked()
	step.Outbound.Runtime = e.store.runtime
	if e.routeSerial < math.MaxUint64 {
		e.routeSerial++
	}
	step = cloneRouteStep(step)
	e.record.SelectedRoute = step
	e.record.EffectiveDestination = xnet.Destination{}
	e.selectedSerial = e.routeSerial
	e.routeSeq = e.routeSerial
	if e.bucket == nil {
		e.route = step
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
		e.bindLocked(featurestats.RouteStep{Selection: featurestats.SelectionUnknown})
	}
}

func (e *inspectionExchange) bindLocked(step featurestats.RouteStep) {
	if e.excluded || e.bucket != nil {
		return
	}
	e.commitPendingLocked()
	if !e.isLeg {
		e.registerLocked()
	}
	step.Outbound.Runtime = e.store.runtime
	e.route = step
	bucket := e.store.bucketFor(step, e.record.Origin)
	e.bucket = bucket
	up, down := e.record.Uplink.Known, e.record.Downlink.Known
	if e.pending != nil {
		up, down = e.pending.up, e.pending.down
	}
	bucket.uplink.addKnown(up)
	bucket.downlink.addKnown(down)
	e.settlePendingLocked()
	e.pending = nil
}

func (e *inspectionExchange) Effective(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.routeSeq == 0 || e.routeSeq != e.selectedSerial {
		return
	}
	e.record.EffectiveDestination = cloneDestination(destination)
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
	e.record.Source = cloneDestination(source)
}

func (e *inspectionExchange) PacketDestination(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.provenanceConflict || !destination.IsValid() {
		return
	}
	e.record.LatestDestination = cloneDestination(destination)
}

func (e *inspectionExchange) AddUplink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		addKnown(&e.pending.up, value)
		return
	}
	addKnown(&e.record.Uplink.Known, value)
	if e.bucket != nil {
		e.bucket.uplink.addKnown(value)
	} else if e.pending != nil {
		addKnown(&e.pending.up, value)
	}
}

func (e *inspectionExchange) AddDownlink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		addKnown(&e.pending.down, value)
		return
	}
	addKnown(&e.record.Downlink.Known, value)
	if e.bucket != nil {
		e.bucket.downlink.addKnown(value)
	} else if e.pending != nil {
		addKnown(&e.pending.down, value)
	}
}

func (e *inspectionExchange) Rebind(runtime featurestats.RuntimeID, origin featurestats.TrafficOrigin) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.provenanceConflict {
		return
	}
	if runtime == (featurestats.RuntimeID{}) || runtime != e.store.runtime ||
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

func (e *inspectionExchange) requestStop() (func() error, featurestats.CloseCode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.published {
		return nil, featurestats.CloseCodeNoAction
	}
	if e.record.State == featurestats.FlowStateStopRequested {
		return nil, featurestats.CloseCodeNoAction
	}
	if e.stop == nil {
		return nil, featurestats.CloseCodeUnsupportedOwner
	}
	e.record.State = featurestats.FlowStateStopRequested
	return e.stop, featurestats.CloseCodeAccepted
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
	if e.isLeg && e.pending != nil && !e.pending.settled {
		// DefaultDispatcher selects asynchronously after returning the link. A
		// native UDP reader may end before Route or BindRoute, so do not guess
		// that the still-pending selected role is unassigned. Only a marked
		// synchronous handler return may settle a selected no-claim leg.
		if !e.selectedReturned {
			return nil
		}
		e.bindLocked(featurestats.RouteStep{Selection: featurestats.SelectionUnknown})
	}
	if e.bucket == nil && !e.hasLegs {
		e.bindLocked(featurestats.RouteStep{Selection: featurestats.SelectionUnknown})
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
	e.record.State = featurestats.FlowStateEnded
	flow := e.snapshotLocked()
	return &featurestats.TerminalRecord{Flow: flow, Ended: e.store.elapsed()}
}

func (e *inspectionExchange) settlePendingLocked() {
	if e.pending == nil || e.pending.settled {
		return
	}
	e.pending.settled = true
}

func (e *inspectionExchange) commitPendingLocked() {
	if e.pending == nil || e.pending.classified {
		return
	}
	e.pending.classified = true
	addKnown(&e.record.Uplink.Known, e.pending.up)
	addKnown(&e.record.Downlink.Known, e.pending.down)
}

func (e *inspectionExchange) snapshot() featurestats.FlowRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

func (e *inspectionExchange) snapshotLocked() featurestats.FlowRecord {
	return e.record
}

func normalizeOrigin(origin featurestats.TrafficOrigin) featurestats.TrafficOrigin {
	switch origin {
	case featurestats.TrafficOriginUser, featurestats.TrafficOriginInternal, featurestats.TrafficOriginControlledMeasurement:
		return origin
	default:
		return featurestats.TrafficOriginUnknown
	}
}

func cloneRouteStep(step featurestats.RouteStep) featurestats.RouteStep {
	step.Outbound.Tag = cloneMetadataString(step.Outbound.Tag)
	step.RuleTag = cloneMetadataString(step.RuleTag)
	step.SelectedTarget = cloneDestination(step.SelectedTarget)
	return step
}

func cloneDestination(destination xnet.Destination) xnet.Destination {
	if destination.Address == nil {
		return destination
	}
	if destination.Address.Family().IsDomain() {
		domain := cloneMetadataString(destination.Address.Domain())
		destination.Address = xnet.DomainAddress(domain)
		return destination
	}
	destination.Address = xnet.IPAddress(destination.Address.IP())
	return destination
}

func cloneMetadataString(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) > maxMetadataString {
		value = value[:maxMetadataString]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return strings.Clone(value)
}
