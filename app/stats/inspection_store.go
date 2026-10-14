package stats

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	featurestats "github.com/xtls/xray-core/features/stats"
)

// The instance lock protects records and receipts as well as the two indexes.
// Endpoint I/O, cancellation and owner callbacks never run under it.
type inspectionStore struct {
	mu             sync.Mutex
	runtime        featurestats.RuntimeID
	limits         featurestats.ObservationOptions
	epoch          time.Time
	live           map[uint64]*inspectionFlow
	buckets        map[string]*featurestats.ClientTotals
	user           featurestats.ClientTotals
	bucketsOmitted uint64
	nextID         uint64
}

// One record owns association facts. A receipt adds only its immutable role
// and first route binding; old UDP receipts never consult a newer binding.
type inspectionFlow struct {
	store              *inspectionStore
	record             featurestats.FlowRecord
	stop               func() error
	hasLeg             bool
	stopRequested      bool
	provenanceConflict bool
	published          bool
	excluded           bool
	admitted           bool
}

type inspectionExchange struct {
	*inspectionFlow
	bucket *featurestats.ClientTotals
	isLeg  bool
	bound  bool
}

func newInspectionStore(runtime featurestats.RuntimeID, limits featurestats.ObservationOptions) *inspectionStore {
	return &inspectionStore{
		runtime: runtime,
		limits:  limits,
		epoch:   time.Now(),
		live:    make(map[uint64]*inspectionFlow),
		buckets: make(map[string]*featurestats.ClientTotals),
	}
}

func (s *inspectionStore) Runtime() featurestats.RuntimeID { return s.runtime }

func (s *inspectionStore) elapsed() time.Duration { return time.Since(s.epoch) }

func (s *inspectionStore) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live == nil
}

func (s *inspectionStore) Begin(kind xnet.Network, origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
	return s.prepare(kind, origin, source, destination, stop, true)
}

func (s *inspectionStore) PrepareTCP(origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error) featurestats.Exchange {
	return s.prepare(xnet.Network_TCP, origin, source, destination, stop, false)
}

func (s *inspectionStore) prepare(kind xnet.Network, origin featurestats.TrafficOrigin, source, destination xnet.Destination, stop func() error, admitted bool) featurestats.Exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		return nil
	}
	e := &inspectionExchange{inspectionFlow: &inspectionFlow{
		store: s, stop: stop,
		record: featurestats.FlowRecord{
			Kind: kind, Origin: normalizeOrigin(origin), Source: source,
			Destination: destination, Opened: s.elapsed(),
		},
		admitted: admitted,
	}}
	if admitted {
		e.registerLocked()
	}
	return e
}

func (e *inspectionExchange) registerLocked() {
	s := e.store
	if e.record.Ref.ID == 0 && !e.excluded && s.live != nil && uint32(len(s.live)) < s.limits.MaxLive {
		s.nextID++
		e.record.Ref = featurestats.FlowRef{Runtime: s.runtime, ID: s.nextID}
		s.live[s.nextID] = e.inspectionFlow
	}
}

func (s *inspectionStore) ReadLiveInto(storage []featurestats.FlowRecord) (featurestats.LiveSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		clear(storage)
		return featurestats.LiveSnapshot{}, errors.New("inspection closed")
	}
	rows := storage[:0]
	if rows == nil || cap(rows) < len(s.live) {
		clear(storage)
		rows = make([]featurestats.FlowRecord, 0, len(s.live))
	}
	for _, flow := range s.live {
		rows = append(rows, flow.record)
	}
	if len(rows) < len(storage) {
		clear(storage[len(rows):])
	}
	return featurestats.LiveSnapshot{At: s.elapsed(), Rows: rows}, nil
}

func (s *inspectionStore) ReadTotals() (featurestats.TotalsSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		return featurestats.TotalsSnapshot{}, errors.New("inspection closed")
	}
	rows := make([]featurestats.TotalRecord, 0, len(s.buckets))
	for tag, cell := range s.buckets {
		rows = append(rows, featurestats.TotalRecord{
			Outbound: featurestats.OutboundRef{Tag: tag}, Origin: featurestats.TrafficOriginUser,
			Uplink: cell.Uplink, Downlink: cell.Downlink,
		})
	}
	return featurestats.TotalsSnapshot{At: s.elapsed(), User: s.user, BucketsOmitted: s.bucketsOmitted, Rows: rows}, nil
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
		s.mu.Lock()
		flow := s.live[ref.ID]
		var stop func() error
		if ref.Runtime == s.runtime && flow != nil && !flow.published && !flow.stopRequested {
			if flow.stop == nil {
				outcomes[i] = errors.ErrUnsupported
			} else {
				flow.stopRequested = true
				stop = flow.stop
			}
		}
		s.mu.Unlock()
		if stop != nil {
			outcomes[i] = stop()
			s.mu.Lock()
			flow.finishLocked()
			s.mu.Unlock()
		}
	}
	return outcomes, nil
}

func (s *inspectionStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live, s.buckets = nil, nil
}

func (e *inspectionExchange) NewLeg() featurestats.Exchange {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.excluded || e.isLeg || e.record.Kind != xnet.Network_UDP || e.stopRequested || e.published {
		return nil
	}
	e.hasLeg = true
	return &inspectionExchange{inspectionFlow: e.inspectionFlow, isLeg: true}
}

func (e *inspectionExchange) Ref() featurestats.FlowRef {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	return e.record.Ref
}

func (e *inspectionExchange) ExcludeCarrier() bool {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.isLeg || e.admitted || e.record.Ref.ID != 0 {
		return false
	}
	e.excluded = true
	return true
}

func (e *inspectionExchange) Route(outbound featurestats.OutboundRef) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.excluded || (!e.isLeg && e.published) || e.bound {
		return
	}
	e.record.Outbound = outbound
	e.bindLocked(outbound)
}

func (e *inspectionExchange) Unassign() {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.isLeg || !e.published {
		e.bindLocked(featurestats.OutboundRef{})
	}
}

func (e *inspectionExchange) bindLocked(outbound featurestats.OutboundRef) {
	if e.excluded || e.bound {
		return
	}
	s := e.store
	if !e.isLeg {
		e.registerLocked()
		if !e.admitted {
			e.admitted = true
			if e.record.Origin == featurestats.TrafficOriginUser {
				s.user.Uplink += e.record.Uplink
				s.user.Downlink += e.record.Downlink
			}
		}
	}
	if outbound.Tag != "" && e.record.Origin == featurestats.TrafficOriginUser {
		e.bucket = s.buckets[outbound.Tag]
		if e.bucket == nil && s.live != nil {
			if uint32(len(s.buckets)) >= s.limits.MaxBuckets {
				s.bucketsOmitted++
			} else {
				e.bucket = &featurestats.ClientTotals{}
				s.buckets[outbound.Tag] = e.bucket
			}
		}
	}
	e.bound = true
}

func (e *inspectionExchange) SetSource(source xnet.Destination) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if source.IsValid() && !e.excluded && !e.published && !e.isLeg && !e.record.Source.IsValid() {
		e.record.Source = source
	}
}

func (e *inspectionExchange) PacketDestination(destination xnet.Destination) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if !e.excluded && !e.provenanceConflict && (e.isLeg || !e.published) && destination.IsValid() {
		e.record.Destination = destination
	}
}

func (e *inspectionExchange) RecordPacketInput(destination xnet.Destination, value uint64) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	if (e.isLeg || !e.published) && destination.IsValid() {
		e.record.Destination = destination
	}
	e.addUplinkLocked(value)
}

func (e *inspectionExchange) AddUplink(value uint64) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if !e.excluded && !e.provenanceConflict {
		e.addUplinkLocked(value)
	}
}

func (e *inspectionExchange) addUplinkLocked(value uint64) {
	e.record.Uplink += value
	if e.admitted && e.record.Origin == featurestats.TrafficOriginUser {
		e.store.user.Uplink += value
	}
}

func (e *inspectionExchange) AddSelectedUplink(value uint64) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if !e.excluded && !e.provenanceConflict && e.bucket != nil {
		e.bucket.Uplink += value
	}
}

func (e *inspectionExchange) AddDownlink(value uint64) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.excluded || e.provenanceConflict {
		return
	}
	e.record.Downlink += value
	if e.admitted && e.record.Origin == featurestats.TrafficOriginUser {
		e.store.user.Downlink += value
	}
	if e.bucket != nil {
		e.bucket.Downlink += value
	}
}

func (e *inspectionExchange) Rebind(runtime featurestats.RuntimeID, origin featurestats.TrafficOrigin) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if !e.excluded && !e.published && !e.provenanceConflict &&
		(runtime != e.store.runtime || origin == featurestats.TrafficOriginUnknown || origin != e.record.Origin) {
		e.provenanceConflict = true
	}
}

func (e *inspectionExchange) Finish() {
	if e.isLeg {
		return
	}
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if !e.published && !e.excluded && !e.bound && !e.hasLeg {
		e.bindLocked(featurestats.OutboundRef{})
	}
	e.finishLocked()
}

func (f *inspectionFlow) finishLocked() {
	f.published = true
	f.stop = nil
	if f.store.live[f.record.Ref.ID] == f {
		delete(f.store.live, f.record.Ref.ID)
	}
}

func normalizeOrigin(origin featurestats.TrafficOrigin) featurestats.TrafficOrigin {
	switch origin {
	case featurestats.TrafficOriginUser, featurestats.TrafficOriginInternal, featurestats.TrafficOriginControlledMeasurement:
		return origin
	default:
		return featurestats.TrafficOriginUnknown
	}
}

var defaultObservationOptions = featurestats.ObservationOptions{MaxLive: 256, MaxBuckets: 1024}

func normalizeObservationOptions(options featurestats.ObservationOptions) featurestats.ObservationOptions {
	if options.MaxLive == 0 {
		options.MaxLive = defaultObservationOptions.MaxLive
	}
	if options.MaxBuckets == 0 {
		options.MaxBuckets = defaultObservationOptions.MaxBuckets
	}
	return options
}

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

func (m *Manager) Observation() featurestats.AdmissionStore {
	m.access.RLock()
	store := m.inspection
	m.access.RUnlock()
	if store == nil || store.isClosed() {
		return nil
	}
	return store
}
