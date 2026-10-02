package stats

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	featurestats "github.com/xtls/xray-core/features/stats"
)

type aggregateKey struct {
	tag    string
	origin featurestats.TrafficOrigin
}

type aggregateCell struct {
	uplink   atomic.Uint64
	downlink atomic.Uint64
}

type inspectionStore struct {
	runtime featurestats.RuntimeID
	limits  featurestats.ObservationOptions
	epoch   time.Time

	mu           sync.RWMutex
	live         map[uint64]*inspectionExchange
	buckets      map[aggregateKey]*aggregateCell
	unassigned   [4]aggregateCell
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
	return store
}

func (s *inspectionStore) elapsed() time.Duration {
	return time.Since(s.epoch)
}

func (s *inspectionStore) Runtime() featurestats.RuntimeID {
	return s.runtime
}

func (s *inspectionStore) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.live == nil
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
	if s.isClosed() {
		return nil
	}
	origin = normalizeOrigin(origin)
	exchange := &inspectionExchange{
		inspectionFlow: &inspectionFlow{
			store: s,
			stop:  stop,
			record: featurestats.FlowRecord{
				Kind:        kind,
				Origin:      origin,
				Source:      source,
				Destination: destination,
				Opened:      s.elapsed(),
			},
		},
	}
	return exchange
}

// Native endpoint owners retain unregistered receipts themselves. There is no
// pending index; the existing live map only owns classified logical exchanges.
func (e *inspectionExchange) registerLocked() {
	if e.record.Ref.ID != 0 || e.excluded {
		return
	}
	s := e.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
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
	s.mu.RLock()
	if s.live == nil {
		s.mu.RUnlock()
		return featurestats.LiveSnapshot{}, errors.New("inspection closed")
	}
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.live == nil {
		return featurestats.TotalsSnapshot{}, errors.New("inspection closed")
	}
	rows := make([]featurestats.TotalRecord, 0, len(s.buckets)+len(s.unassigned))
	appendCell := func(cell *aggregateCell, outbound featurestats.OutboundRef, origin featurestats.TrafficOrigin) {
		rows = append(rows, featurestats.TotalRecord{Outbound: outbound, Origin: origin, Uplink: cell.uplink.Load(), Downlink: cell.downlink.Load()})
	}
	for i := range s.unassigned {
		appendCell(&s.unassigned[i], featurestats.OutboundRef{}, featurestats.TrafficOrigin(i))
	}
	for key, cell := range s.buckets {
		appendCell(cell, featurestats.OutboundRef{Tag: key.tag}, key.origin)
	}
	return featurestats.TotalsSnapshot{
		At:   s.elapsed(),
		Rows: rows,
	}, nil
}

func (s *inspectionStore) ReadTerminals() (featurestats.TerminalSnapshot, error) {
	s.mu.RLock()
	if s.live == nil {
		s.mu.RUnlock()
		return featurestats.TerminalSnapshot{}, errors.New("inspection closed")
	}
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

func (s *inspectionStore) CloseFlows(ctx context.Context, refs []featurestats.FlowRef) ([]error, error) {
	if s.isClosed() {
		return nil, errors.New("inspection closed")
	}
	outcomes := make([]error, len(refs))
	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			outcomes[i] = err
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
			outcomes[i] = err
			continue
		}
		if stop == nil {
			continue
		}
		err = stop()
		exchange.Finish()
		outcomes[i] = err
	}
	return outcomes, nil
}

func (s *inspectionStore) lookup(id uint64) *inspectionExchange {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.live[id]
}

func (s *inspectionStore) bucketFor(outbound featurestats.OutboundRef, origin featurestats.TrafficOrigin) *aggregateCell {
	if outbound.Tag == "" {
		return &s.unassigned[int(origin)]
	}
	key := aggregateKey{tag: outbound.Tag, origin: origin}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cell := s.buckets[key]; cell != nil {
		return cell
	}
	if s.live == nil {
		return &s.unassigned[int(origin)]
	}
	if uint32(len(s.buckets)) >= s.limits.MaxBuckets {
		return &s.unassigned[int(origin)]
	}
	cell := &aggregateCell{}
	s.buckets[key] = cell
	return cell
}

func (s *inspectionStore) publish(exchange *inspectionExchange, terminal featurestats.TerminalRecord) {
	if terminal.Flow.Ref.ID == 0 {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		return
	}
	s.live = nil
	s.buckets = nil
	s.terminals = nil
	s.terminalHead = 0
}

// One association owns the visible values and lock. Native rays retain only
// their attribution and completion state; no historical ray list is kept.
type inspectionFlow struct {
	store              *inspectionStore
	stop               func() error
	stopRequested      bool
	mu                 sync.Mutex
	record             featurestats.FlowRecord
	provenanceConflict bool
}

type inspectionExchange struct {
	*inspectionFlow
	isLeg           bool
	hasLegs         bool
	pending         *pendingCredit
	bucket          *aggregateCell
	published       bool
	excluded        bool
	finishRequested bool
}

// Only a ray with unbound receipts needs numeric pending credit. The ordinary
// single-leg endpoint continues to use its authoritative flow cells directly.
type pendingCredit struct {
	up, down uint64
}

func (e *inspectionExchange) NewLeg() featurestats.Exchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.isLeg || e.record.Kind != xnet.Network_UDP || e.stopRequested || e.published {
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
	if e.isLeg || e.record.Ref.ID != 0 {
		return false
	}
	e.excluded = true
	return true
}

func (e *inspectionExchange) Route(outbound featurestats.OutboundRef) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.published || e.bucket != nil {
		return
	}
	e.record.Outbound = outbound
	e.bindLocked(outbound)
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
	if !e.isLeg {
		e.registerLocked()
	}
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
	e.record.Destination = destination
}

func (e *inspectionExchange) AddUplink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
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
		origin == featurestats.TrafficOriginUnknown || origin != e.record.Origin {
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
	if e.pending != nil {
		e.bindLocked(featurestats.OutboundRef{})
	}
	e.completeLocked()
	e.mu.Unlock()
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
	if e.pending != nil {
		return nil // Only the selected handler can settle an unclaimed leg.
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

func normalizeOrigin(origin featurestats.TrafficOrigin) featurestats.TrafficOrigin {
	switch origin {
	case featurestats.TrafficOriginUser, featurestats.TrafficOriginInternal, featurestats.TrafficOriginControlledMeasurement:
		return origin
	default:
		return featurestats.TrafficOriginUnknown
	}
}

var defaultObservationOptions = featurestats.ObservationOptions{
	MaxLive:      256,
	MaxTerminals: 1024,
	MaxBuckets:   1024,
}

func normalizeObservationOptions(options featurestats.ObservationOptions) featurestats.ObservationOptions {
	if options.MaxLive == 0 {
		options.MaxLive = defaultObservationOptions.MaxLive
	}
	if options.MaxTerminals == 0 {
		options.MaxTerminals = defaultObservationOptions.MaxTerminals
	}
	if options.MaxBuckets == 0 {
		options.MaxBuckets = defaultObservationOptions.MaxBuckets
	}
	return options
}

// EnableInspection enables the optional observation store before Manager.Start.
func (m *Manager) EnableInspection(options featurestats.ObservationOptions) (featurestats.FlowInspection, error) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.running {
		return nil, fmt.Errorf("inspection enablement is too late")
	}
	if m.inspection != nil {
		return nil, fmt.Errorf("inspection already enabled")
	}
	m.inspection = newInspectionStore(featurestats.RuntimeID(uuid.New()), normalizeObservationOptions(options))
	return m.inspection, nil
}

// Observation returns the admission store only while enabled and open.
func (m *Manager) Observation() featurestats.AdmissionStore {
	m.access.RLock()
	store := m.inspection
	m.access.RUnlock()
	if store == nil || store.isClosed() {
		return nil
	}
	return store
}
