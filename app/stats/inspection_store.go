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

type aggregateCell struct {
	uplink   atomic.Uint64
	downlink atomic.Uint64
}

type inspectionStore struct {
	runtime featurestats.RuntimeID
	limits  featurestats.ObservationOptions
	epoch   time.Time

	mu             sync.RWMutex
	live           map[uint64]*inspectionExchange
	buckets        map[string]*aggregateCell
	user           aggregateCell
	bucketsOmitted uint64
	nextID         uint64
}

func newInspectionStore(runtime featurestats.RuntimeID, limits featurestats.ObservationOptions) *inspectionStore {
	store := &inspectionStore{
		runtime: runtime,
		limits:  limits,
		epoch:   time.Now(),
		live:    make(map[uint64]*inspectionExchange),
		buckets: make(map[string]*aggregateCell),
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
		e.admitLocked()
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
	var exchange *inspectionExchange
	if kind == xnet.Network_TCP {
		root := &struct {
			flow     inspectionFlow
			exchange inspectionExchange
		}{}
		root.exchange.inspectionFlow = &root.flow
		exchange = &root.exchange
	} else {
		// A late UDP leg retains the flow alone, without retaining the root.
		exchange = &inspectionExchange{inspectionFlow: &inspectionFlow{}}
	}
	exchange.store = s
	exchange.stop = stop
	exchange.record = featurestats.FlowRecord{
		Kind: kind, Origin: origin, Source: source, Destination: destination,
		Opened: s.elapsed(),
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

func (s *inspectionStore) ReadLiveInto(storage []featurestats.FlowRecord) (featurestats.LiveSnapshot, error) {
	s.mu.RLock()
	if s.live == nil {
		s.mu.RUnlock()
		clear(storage)
		return featurestats.LiveSnapshot{}, errors.New("inspection closed")
	}
	rows := make([]*inspectionExchange, 0, len(s.live))
	for _, exchange := range s.live {
		rows = append(rows, exchange)
	}
	s.mu.RUnlock()

	result := storage[:0]
	if result == nil || cap(result) < len(rows) {
		clear(storage)
		result = make([]featurestats.FlowRecord, 0, len(rows))
	}
	for _, exchange := range rows {
		exchange.mu.Lock()
		if !exchange.published {
			result = append(result, exchange.record)
		}
		exchange.mu.Unlock()
	}
	if len(result) < len(storage) {
		clear(storage[len(result):])
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
	rows := make([]featurestats.TotalRecord, 0, len(s.buckets))
	for tag, cell := range s.buckets {
		rows = append(rows, featurestats.TotalRecord{Outbound: featurestats.OutboundRef{Tag: tag}, Origin: featurestats.TrafficOriginUser, Uplink: cell.uplink.Load(), Downlink: cell.downlink.Load()})
	}
	return featurestats.TotalsSnapshot{
		At:             s.elapsed(),
		User:           featurestats.ClientTotals{Uplink: s.user.uplink.Load(), Downlink: s.user.downlink.Load()},
		BucketsOmitted: s.bucketsOmitted,
		Rows:           rows,
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
	if outbound.Tag == "" || origin != featurestats.TrafficOriginUser {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cell := s.buckets[outbound.Tag]; cell != nil {
		return cell
	}
	if s.live == nil {
		return nil
	}
	if uint32(len(s.buckets)) >= s.limits.MaxBuckets {
		s.bucketsOmitted++
		return nil
	}
	cell := &aggregateCell{}
	s.buckets[outbound.Tag] = cell
	return cell
}

func (s *inspectionStore) remove(exchange *inspectionExchange, ref featurestats.FlowRef) {
	if ref.ID == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live[ref.ID] == exchange {
		delete(s.live, ref.ID)
	}
}

func (s *inspectionStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		return
	}
	s.live = nil
	s.buckets = nil
}

// One association owns the visible values, lifetime and lock. Native rays retain
// only route binding; no pending credit or ray lifecycle exists.
type inspectionFlow struct {
	store              *inspectionStore
	stop               func() error
	mu                 sync.Mutex
	record             featurestats.FlowRecord
	hasLeg             bool
	stopRequested      bool
	provenanceConflict bool
	published          bool
	excluded           bool
	admitted           bool // Prepared TCP carriers remain private.
}

type inspectionExchange struct {
	*inspectionFlow
	bucket *aggregateCell
	isLeg  bool
	bound  bool // Selection can bind without a public tag bucket.
}

func (e *inspectionExchange) NewLeg() featurestats.Exchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.isLeg || e.record.Kind != xnet.Network_UDP || e.stopRequested || e.published {
		return nil
	}
	e.hasLeg = true
	return &inspectionExchange{inspectionFlow: e.inspectionFlow, isLeg: true}
}

func (e *inspectionExchange) Ref() featurestats.FlowRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.record.Ref
}

func (e *inspectionExchange) ExcludeCarrier() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isLeg || e.admitted || e.record.Ref.ID != 0 {
		return false
	}
	e.excluded = true
	return true
}

func (e *inspectionExchange) Route(outbound featurestats.OutboundRef) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || (!e.isLeg && e.published) || e.bound {
		return
	}
	e.record.Outbound = outbound

	e.bindLocked(outbound)
}

func (e *inspectionExchange) Unassign() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isLeg || !e.published {
		e.bindLocked(featurestats.OutboundRef{})
	}
}

func (e *inspectionExchange) bindLocked(outbound featurestats.OutboundRef) {
	if e.excluded || e.bound {
		return
	}
	if !e.isLeg {
		e.registerLocked()
		e.admitLocked()
	}
	e.bucket = e.store.bucketFor(outbound, e.record.Origin)
	e.bound = true
}

// Prepared TCP may still prove to be a carrier. Classify once, then credit its
// retained pre-route prefix; UDP rays share this root admission and never replay
// input into the general metric a second time.
func (e *inspectionExchange) admitLocked() {
	if e.admitted {
		return
	}
	e.admitted = true
	if e.record.Origin == featurestats.TrafficOriginUser {
		e.store.user.uplink.Add(e.record.Uplink)
		e.store.user.downlink.Add(e.record.Downlink)
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
	e.record.Source = source
}

func (e *inspectionExchange) PacketDestination(destination xnet.Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// A selected leg may end before the dispatcher records its first packet.
	// Like late byte receipts, its address still belongs to the shared flow;
	// root Finish has already removed the live entry.
	if e.excluded || (!e.isLeg && e.published) || e.provenanceConflict || !destination.IsValid() {
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
	e.addUplinkLocked(value)
}

func (e *inspectionExchange) RecordPacketInput(destination xnet.Destination, value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if (e.isLeg || !e.published) && destination.IsValid() {
		e.record.Destination = destination
	}
	e.addUplinkLocked(value)
}

func (e *inspectionExchange) addUplinkLocked(value uint64) {
	e.record.Uplink += value
	if e.admitted && e.record.Origin == featurestats.TrafficOriginUser {
		e.store.user.uplink.Add(value)
	}
}

func (e *inspectionExchange) AddSelectedUplink(value uint64) {
	if value == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.excluded && !e.provenanceConflict && e.bucket != nil {
		e.bucket.uplink.Add(value)
	}
}

func (e *inspectionExchange) AddDownlink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	e.record.Downlink += value
	if e.admitted && e.record.Origin == featurestats.TrafficOriginUser {
		e.store.user.downlink.Add(value)
	}
	if e.bucket != nil {
		e.bucket.downlink.Add(value)
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
	if e.isLeg {
		return
	}
	e.mu.Lock()
	remove := e.completeLocked()
	ref := e.record.Ref
	e.mu.Unlock()
	if remove {
		e.store.remove(e, ref)
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

func (e *inspectionExchange) completeLocked() bool {
	if e.published {
		return false
	}
	if e.excluded {
		e.published = true
		e.stop = nil
		return false
	}
	if !e.bound && !e.hasLeg {
		e.bindLocked(featurestats.OutboundRef{})
	}
	e.published = true

	// Owner-end disables stop; late byte receipts only need the accounting state.
	e.stop = nil
	if e.record.Ref.ID == 0 {
		return false
	}
	return true
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
	MaxLive:    256,
	MaxBuckets: 1024,
}

func normalizeObservationOptions(options featurestats.ObservationOptions) featurestats.ObservationOptions {
	if options.MaxLive == 0 {
		options.MaxLive = defaultObservationOptions.MaxLive
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
