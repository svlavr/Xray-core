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

const (
	maxMetadataString = 255
	maxRecordMetadata = 4096
)

type byteCell struct {
	known      saturatingUint64
	incomplete atomic.Bool
}

func (c *byteCell) addKnown(value uint64) {
	if value == 0 {
		return
	}
	if c.known.add(value) {
		c.incomplete.Store(true)
	}
}

func (c *byteCell) markIncomplete() { c.incomplete.Store(true) }

func (c *byteCell) snapshot() featurestats.ByteFact {
	return featurestats.ByteFact{Known: c.known.load(), Incomplete: c.incomplete.Load()}
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

type inspectionLoss struct {
	untrackedAdmissions saturatingUint64
	bucketAdmissionLoss saturatingUint64
	terminalOverwrite   saturatingUint64
	metadataTruncated   atomic.Bool
}

func (l *inspectionLoss) snapshot() featurestats.LossFacts {
	return featurestats.LossFacts{
		UntrackedAdmissions: l.untrackedAdmissions.load(),
		BucketAdmissionLoss: l.bucketAdmissionLoss.load(),
		TerminalOverwrite:   l.terminalOverwrite.load(),
		Saturated:           l.untrackedAdmissions.saturated.Load() || l.bucketAdmissionLoss.saturated.Load() || l.terminalOverwrite.saturated.Load(),
		MetadataTruncated:   l.metadataTruncated.Load(),
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
	loss         inspectionLoss
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
	return featurestats.InspectionInfo{
		Runtime: s.runtime,
		Limits:  s.limits,
		Closed:  s.closed.Load(),
	}
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
	metadataBudget := maxRecordMetadata
	var truncated bool
	source = cloneDestination(source, &metadataBudget, &truncated)
	destination = cloneDestination(destination, &metadataBudget, &truncated)

	exchange := &inspectionExchange{
		inspectionFlow: &inspectionFlow{
			store:          s,
			stop:           stop,
			metadataBudget: metadataBudget,
			record: featurestats.FlowRecord{
				Kind:               kind,
				Origin:             origin,
				Source:             source,
				InitialDestination: destination,
				Opened:             s.elapsed(),
				State:              featurestats.FlowStateOpen,
				MetadataTruncated:  truncated,
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
	if e.record.MetadataTruncated {
		s.loss.metadataTruncated.Store(true)
	}
	if uint32(len(s.live)) >= s.limits.MaxLive || s.nextID == math.MaxUint64 {
		s.loss.untrackedAdmissions.add(1)
		return
	}
	s.nextID++
	e.record.Ref = featurestats.FlowRef{Runtime: s.runtime, ID: s.nextID}
	s.live[s.nextID] = e
}

func (s *inspectionStore) ReadLive(context.Context) (featurestats.LiveSnapshot, error) {
	if s.closed.Load() {
		return featurestats.LiveSnapshot{}, featurestats.ErrInspectionClosed
	}
	s.mu.RLock()
	rows := make([]*inspectionExchange, 0, len(s.live))
	for _, exchange := range s.live {
		rows = append(rows, exchange)
	}
	loss := s.loss.snapshot()
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
		Loss:   loss,
	}, nil
}

func (s *inspectionStore) ReadTotals(context.Context) (featurestats.TotalsSnapshot, error) {
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
	loss := s.loss.snapshot()
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
		Loss:   loss,
	}, nil
}

func (s *inspectionStore) ReadTerminals(context.Context) (featurestats.TerminalSnapshot, error) {
	if s.closed.Load() {
		return featurestats.TerminalSnapshot{}, featurestats.ErrInspectionClosed
	}

	s.mu.RLock()
	rows := make([]featurestats.TerminalRecord, 0, len(s.terminals))
	for i := 0; i < len(s.terminals); i++ {
		rows = append(rows, cloneTerminalRecord(s.terminals[(int(s.terminalHead)+i)%len(s.terminals)]))
	}
	loss := s.loss.snapshot()
	s.mu.RUnlock()
	return featurestats.TerminalSnapshot{
		Sample: featurestats.Sample{Runtime: s.runtime, At: s.elapsed()},
		Rows:   rows,
		Loss:   loss,
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
		exchange, ended := s.lookup(ref.ID)
		if exchange == nil {
			if ended {
				outcomes[i].Code = featurestats.CloseCodeAlreadyEnded
			} else {
				outcomes[i].Code = featurestats.CloseCodeNotFound
			}
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
		}
	}
	return outcomes, nil
}

func (s *inspectionStore) lookup(id uint64) (*inspectionExchange, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if exchange := s.live[id]; exchange != nil {
		return exchange, false
	}
	for i := 0; i < len(s.terminals); i++ {
		if s.terminals[(int(s.terminalHead)+i)%len(s.terminals)].Flow.Ref.ID == id {
			return nil, true
		}
	}
	return nil, false
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
		s.loss.bucketAdmissionLoss.add(1)
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
	s.loss.terminalOverwrite.add(1)
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
	metadataBudget     int
	endReason          featurestats.EndReason
	routeSerial        uint64
	pendingRoutes      uint64
	provenanceConflict bool
}

type inspectionExchange struct {
	*inspectionFlow
	isLeg            bool
	hasLegs          bool
	route            featurestats.RouteStep
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
	up, down                     uint64
	upIncomplete, downIncomplete bool
	destinations                 []xnet.Destination
	metadataBudget               int
	metadataTruncated            bool
	endReason                    featurestats.EndReason
	classified                   bool
	counted                      bool
	settled                      bool
}

func addKnown(value *uint64, n uint64) bool {
	if n > math.MaxUint64-*value {
		*value = math.MaxUint64
		return true
	}
	*value += n
	return false
}

func (e *inspectionExchange) NewLeg() featurestats.Exchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.isLeg || (e.record.Kind != featurestats.FlowKindUDPAssociation && e.record.Kind != featurestats.FlowKindTCP) || e.record.State == featurestats.FlowStateStopRequested || e.published {
		return nil
	}
	e.hasLegs = true
	pending := &pendingCredit{metadataBudget: maxRecordMetadata}
	if e.pendingRoutes < math.MaxUint64 {
		e.pendingRoutes++
		pending.counted = true
	} else {
		e.record.Uplink.Incomplete = true
		e.record.Downlink.Incomplete = true
		e.store.loss.untrackedAdmissions.add(1)
	}
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
		step.Leg = e.routeSerial
	} else {
		step.Leg = 0
		step.Truncated = true
		e.record.MetadataTruncated = true
	}
	step = cloneRouteStep(step, &e.metadataBudget, &e.record.MetadataTruncated)
	if e.registered && e.record.MetadataTruncated {
		e.store.loss.metadataTruncated.Store(true)
	}
	if uint32(len(e.record.Routes)) < e.store.limits.MaxRouteSteps {
		e.record.Routes = append(e.record.Routes, step)
	} else {
		step.Truncated = true
		e.record.MetadataTruncated = true
		if e.registered {
			e.store.loss.metadataTruncated.Store(true)
		}
	}
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
	if step.Leg >= e.record.AccountingRoute.Leg {
		e.record.AccountingRoute = step
	}
	bucket := e.store.bucketFor(step, e.record.Origin)
	e.bucket = bucket
	up, down := e.record.Uplink.Known, e.record.Downlink.Known
	upIncomplete, downIncomplete := e.record.Uplink.Incomplete, e.record.Downlink.Incomplete
	if e.pending != nil {
		up, down = e.pending.up, e.pending.down
		upIncomplete, downIncomplete = e.pending.upIncomplete, e.pending.downIncomplete
	}
	bucket.uplink.addKnown(up)
	bucket.downlink.addKnown(down)
	if upIncomplete {
		bucket.uplink.markIncomplete()
	}
	if downIncomplete {
		bucket.downlink.markIncomplete()
	}
	e.settlePendingLocked()
	e.pending = nil
}

func (e *inspectionExchange) Effective(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || len(e.record.Routes) == 0 {
		return
	}
	destination = cloneDestination(destination, &e.metadataBudget, &e.record.MetadataTruncated)
	for i := range e.record.Routes {
		if e.record.Routes[i].Leg == e.route.Leg {
			e.record.Routes[i].Effective = destination
		}
	}
	if e.record.AccountingRoute.Leg == e.route.Leg {
		e.record.AccountingRoute.Effective = destination
	}
	if e.registered && e.record.MetadataTruncated {
		e.store.loss.metadataTruncated.Store(true)
	}
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
	e.record.Source = cloneDestination(source, &e.metadataBudget, &e.record.MetadataTruncated)
	if e.registered && e.record.MetadataTruncated {
		e.store.loss.metadataTruncated.Store(true)
	}
}

func (e *inspectionExchange) PacketDestination(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.provenanceConflict || !destination.IsValid() {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		e.stagePacketDestinationLocked(destination)
		return
	}
	e.recordPacketDestinationLocked(destination)
}

func (e *inspectionExchange) stagePacketDestinationLocked(destination xnet.Destination) {
	for _, known := range e.pending.destinations {
		if known == destination {
			return
		}
	}
	if uint32(len(e.pending.destinations)) < e.store.limits.MaxDestinations {
		destination = cloneDestination(destination, &e.pending.metadataBudget, &e.pending.metadataTruncated)
		e.pending.destinations = append(e.pending.destinations, destination)
	} else {
		e.pending.metadataTruncated = true
	}
}

func (e *inspectionExchange) recordPacketDestinationLocked(destination xnet.Destination) {
	for _, known := range e.record.Destinations {
		if known == destination {
			return
		}
	}
	if uint32(len(e.record.Destinations)) < e.store.limits.MaxDestinations {
		destination = cloneDestination(destination, &e.metadataBudget, &e.record.MetadataTruncated)
		e.record.Destinations = append(e.record.Destinations, destination)
	} else {
		e.record.MetadataTruncated = true
	}
	if e.registered && e.record.MetadataTruncated {
		e.store.loss.metadataTruncated.Store(true)
	}
}

func (e *inspectionExchange) AddUplink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		if addKnown(&e.pending.up, value) {
			e.pending.upIncomplete = true
		}
		return
	}
	if addKnown(&e.record.Uplink.Known, value) {
		e.record.Uplink.Incomplete = true
	}
	if e.bucket != nil {
		e.bucket.uplink.addKnown(value)
	} else if e.pending != nil && addKnown(&e.pending.up, value) {
		e.pending.upIncomplete = true
	}
}

func (e *inspectionExchange) AddDownlink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		if addKnown(&e.pending.down, value) {
			e.pending.downIncomplete = true
		}
		return
	}
	if addKnown(&e.record.Downlink.Known, value) {
		e.record.Downlink.Incomplete = true
	}
	if e.bucket != nil {
		e.bucket.downlink.addKnown(value)
	} else if e.pending != nil && addKnown(&e.pending.down, value) {
		e.pending.downIncomplete = true
	}
}

func (e *inspectionExchange) MarkUplinkIncomplete() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.markUplinkIncompleteLocked()
}

func (e *inspectionExchange) markUplinkIncompleteLocked() {
	if e.excluded {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		e.pending.upIncomplete = true
		return
	}
	e.record.Uplink.Incomplete = true
	if e.bucket != nil {
		e.bucket.uplink.markIncomplete()
	} else if e.pending != nil {
		e.pending.upIncomplete = true
	}
}

func (e *inspectionExchange) MarkDownlinkIncomplete() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.markDownlinkIncompleteLocked()
}

func (e *inspectionExchange) markDownlinkIncompleteLocked() {
	if e.excluded {
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		e.pending.downIncomplete = true
		return
	}
	e.record.Downlink.Incomplete = true
	if e.bucket != nil {
		e.bucket.downlink.markIncomplete()
	} else if e.pending != nil {
		e.pending.downIncomplete = true
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
	if e.provenanceConflict {
		e.markUplinkIncompleteLocked()
		e.markDownlinkIncompleteLocked()
	}
}

func (e *inspectionExchange) SetEndReason(reason featurestats.EndReason) {
	e.mu.Lock()
	if e.excluded {
		e.mu.Unlock()
		return
	}
	if e.isLeg && e.pending != nil && !e.pending.classified {
		if endReasonRank(reason) > endReasonRank(e.pending.endReason) {
			e.pending.endReason = reason
		}
		e.mu.Unlock()
		return
	}
	if !e.published && endReasonRank(reason) > endReasonRank(e.endReason) {
		e.endReason = reason
	}
	e.mu.Unlock()
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
		return nil, featurestats.CloseCodeAlreadyEnded
	}
	if e.record.State == featurestats.FlowStateStopRequested {
		return nil, featurestats.CloseCodeAlreadyRequested
	}
	if e.stop == nil {
		return nil, featurestats.CloseCodeUnsupportedOwner
	}
	e.record.State = featurestats.FlowStateStopRequested
	if endReasonRank(featurestats.EndReasonLocalStop) > endReasonRank(e.endReason) {
		e.endReason = featurestats.EndReasonLocalStop
	}
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
		e.markUplinkIncompleteLocked()
		e.markDownlinkIncompleteLocked()
	}
	if e.bucket == nil && !e.hasLegs {
		e.bindLocked(featurestats.RouteStep{Selection: featurestats.SelectionUnknown})
		e.markUplinkIncompleteLocked()
		e.markDownlinkIncompleteLocked()
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
	if e.pendingRoutes != 0 {
		e.record.Uplink.Incomplete = true
		e.record.Downlink.Incomplete = true
	}
	e.record.State = featurestats.FlowStateEnded
	flow := e.snapshotLocked()
	return &featurestats.TerminalRecord{Flow: flow, Ended: e.store.elapsed(), Reason: e.endReason}
}

func (e *inspectionExchange) settlePendingLocked() {
	if e.pending == nil || e.pending.settled {
		return
	}
	e.pending.settled = true
	if !e.pending.counted {
		return
	}
	e.pending.counted = false
	if e.pendingRoutes == 0 {
		e.record.Uplink.Incomplete = true
		e.record.Downlink.Incomplete = true
		e.store.loss.untrackedAdmissions.add(1)
		return
	}
	e.pendingRoutes--
}

func (e *inspectionExchange) commitPendingLocked() {
	if e.pending == nil || e.pending.classified {
		return
	}
	e.pending.classified = true
	if addKnown(&e.record.Uplink.Known, e.pending.up) {
		e.record.Uplink.Incomplete = true
	}
	if addKnown(&e.record.Downlink.Known, e.pending.down) {
		e.record.Downlink.Incomplete = true
	}
	e.record.Uplink.Incomplete = e.record.Uplink.Incomplete || e.pending.upIncomplete
	e.record.Downlink.Incomplete = e.record.Downlink.Incomplete || e.pending.downIncomplete
	for _, destination := range e.pending.destinations {
		e.recordPacketDestinationLocked(destination)
	}
	if e.pending.metadataTruncated {
		e.record.MetadataTruncated = true
		if e.registered {
			e.store.loss.metadataTruncated.Store(true)
		}
	}
	if endReasonRank(e.pending.endReason) > endReasonRank(e.endReason) {
		e.endReason = e.pending.endReason
	}
}

func (e *inspectionExchange) snapshot() featurestats.FlowRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

func (e *inspectionExchange) snapshotLocked() featurestats.FlowRecord {
	record := e.record
	record.Routes = append([]featurestats.RouteStep(nil), e.record.Routes...)
	record.Destinations = append([]xnet.Destination(nil), e.record.Destinations...)
	return record
}

func normalizeOrigin(origin featurestats.TrafficOrigin) featurestats.TrafficOrigin {
	switch origin {
	case featurestats.TrafficOriginUser, featurestats.TrafficOriginInternal, featurestats.TrafficOriginControlledMeasurement:
		return origin
	default:
		return featurestats.TrafficOriginUnknown
	}
}

func endReasonRank(reason featurestats.EndReason) uint8 {
	switch reason {
	case featurestats.EndReasonLocalStop:
		return 4
	case featurestats.EndReasonRejected:
		return 3
	case featurestats.EndReasonTimeout, featurestats.EndReasonReadError, featurestats.EndReasonWriteError:
		return 2
	case featurestats.EndReasonEOF:
		return 1
	default:
		return 0
	}
}

func cloneRouteStep(step featurestats.RouteStep, budget *int, truncated *bool) featurestats.RouteStep {
	var local bool
	step.Outbound.Tag = cloneMetadataString(step.Outbound.Tag, budget, &local)
	step.Outbound.TagTruncated = step.Outbound.TagTruncated || local
	step.RuleTag = cloneMetadataString(step.RuleTag, budget, &local)
	step.Original = cloneDestination(step.Original, budget, &local)
	step.RouteTarget = cloneDestination(step.RouteTarget, budget, &local)
	step.SelectedTarget = cloneDestination(step.SelectedTarget, budget, &local)
	step.Effective = cloneDestination(step.Effective, budget, &local)
	step.Truncated = step.Truncated || local
	*truncated = *truncated || local
	return step
}

func cloneDestination(destination xnet.Destination, budget *int, truncated *bool) xnet.Destination {
	if destination.Address == nil {
		return destination
	}
	if destination.Address.Family().IsDomain() {
		domain := cloneMetadataString(destination.Address.Domain(), budget, truncated)
		destination.Address = xnet.DomainAddress(domain)
		return destination
	}
	destination.Address = xnet.IPAddress(destination.Address.IP())
	return destination
}

func cloneMetadataString(value string, budget *int, truncated *bool) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	limit := maxMetadataString
	if *budget < limit {
		limit = *budget
	}
	if len(value) > limit {
		value = value[:limit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		*truncated = true
	}
	*budget -= len(value)
	return strings.Clone(value)
}

func cloneTerminalRecord(record featurestats.TerminalRecord) featurestats.TerminalRecord {
	record.Flow.Routes = append([]featurestats.RouteStep(nil), record.Flow.Routes...)
	record.Flow.Destinations = append([]xnet.Destination(nil), record.Flow.Destinations...)
	return record
}
