package flow

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const maxCarrierAdmissionDrainBatch = 16

// serverMuxCarrier is registry-affine; every method is best-effort and inert
// after registry shutdown. It is intentionally separate from logical roots.
type carrierSidecar struct {
	r    *Registry
	ref  string
	kind CarrierKind

	mu                                                   sync.Mutex
	reader, monitor, owner, uplinkSealed, downlinkSealed bool
	reservations                                         uint64
	reservationFault                                     bool
	pendingRead, pendingWrite                            uint64
	pendingReadOverflow, pendingWriteOverflow            bool
	pendingBoundaryError                                 bool
	omitted                                              atomic.Bool
	state                                                uint8
	workerQuiesced                                       bool
}

type (
	serverMuxCarrier = carrierSidecar
	clientMuxCarrier struct{ sidecar *carrierSidecar }
)

const (
	carrierPrepared uint8 = iota
	carrierCommitted
	carrierAborted
)

func (r *Registry) admitServerMuxCarrier(ref string) *serverMuxCarrier {
	return r.admitMuxCarrier(ref, CarrierKindServerMuxFrameLink, true)
}

func (r *Registry) admitMuxCarrier(ref string, kind CarrierKind, committed bool) *carrierSidecar {
	if r == nil || ref == "" || carrierKindDirectionIndex(kind, DirectionUplink) < 0 || r.continuationsClosed.Load() {
		return nil
	}
	// The shared close barrier protects queue publication only; it neither uses
	// flow pending capacity nor changes flow admission accounting.
	if !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	c := &carrierSidecar{r: r, ref: ref, kind: kind}
	if committed {
		c.state = carrierCommitted
	}
	if r.mu.TryLock() {
		registered := r.registerMuxCarrierLocked(c)
		r.mu.Unlock()
		if registered {
			return c
		}
		return nil
	}
	select {
	case r.pendingCarriers <- c:
		r.signalDirty()
		return c
	default:
		if c.omitted.CompareAndSwap(false, true) {
			r.recordCarrierAdmissionLossKind(c.kind)
		}
		return c
	}
}

func (r *Registry) admitClientMuxCarrier(ref string) *clientMuxCarrier {
	if r == nil || ref == "" || r.continuationsClosed.Load() {
		return nil
	}
	return &clientMuxCarrier{sidecar: &carrierSidecar{r: r, ref: ref, kind: CarrierKindClientMuxFrameLink}}
}

func (c *clientMuxCarrier) Commit() {
	if c == nil || c.sidecar == nil {
		return
	}
	s := c.sidecar
	s.mu.Lock()
	if s.state != carrierPrepared {
		s.mu.Unlock()
		return
	}
	s.state = carrierCommitted
	s.mu.Unlock()
	if s.r == nil || s.r.continuationsClosed.Load() || !s.r.beginAdmission() {
		s.omitted.CompareAndSwap(false, true)
		return
	}
	defer s.r.endAdmission()
	if s.r.mu.TryLock() {
		s.r.registerMuxCarrierLocked(s)
		s.r.mu.Unlock()
	} else {
		select {
		case s.r.pendingCarriers <- s:
		default:
			if s.omitted.CompareAndSwap(false, true) {
				s.r.recordCarrierAdmissionLossKind(s.kind)
			}
		}
	}
	s.r.signalDirty()
}

func (c *clientMuxCarrier) Abort() {
	if c == nil || c.sidecar == nil {
		return
	}
	s := c.sidecar
	s.mu.Lock()
	if s.state == carrierPrepared {
		s.state = carrierAborted
	}
	s.mu.Unlock()
}

func (c *clientMuxCarrier) WorkerQuiesced() {
	if c == nil || c.sidecar == nil {
		return
	}
	s := c.sidecar
	s.mu.Lock()
	if s.state != carrierCommitted || s.omitted.Load() || s.r.continuationsClosed.Load() {
		s.mu.Unlock()
		return
	}
	s.workerQuiesced = true
	s.mu.Unlock()
	s.r.signalDirty()
}

func (c *clientMuxCarrier) Read(n uint64) {
	if c != nil && c.sidecar != nil {
		c.sidecar.add(DirectionDownlink, n, nil)
	}
}

func (c *clientMuxCarrier) Write(n uint64, e error) {
	if c != nil && c.sidecar != nil {
		c.sidecar.add(DirectionUplink, n, e)
	}
}

// registerServerMuxCarrierLocked owns only sidecar publication. A false
// result never changes the worker correlation capability or child admission.
func (r *Registry) registerMuxCarrierLocked(c *carrierSidecar) bool {
	if c == nil || carrierKindDirectionIndex(c.kind, DirectionUplink) < 0 {
		return false
	}
	if c.omitted.Load() {
		return false
	}
	if r.closed {
		return r.rejectCarrierAdmissionLocked(c)
	}
	if len(r.carriers) >= r.maxRecords && !r.evictOldestTerminalCarrierLocked() {
		return r.rejectCarrierAdmissionLocked(c)
	}
	neededSeries := uint64(0)
	for i := range r.carrierSeries {
		if carrierKindForIndex(i) == c.kind && r.carrierCoverage[i].State == AccountingCoverageComplete && r.carrierSeries[i] == nil {
			neededSeries++
		}
	}
	if math.MaxUint64-r.nextSeries < neededSeries {
		return r.rejectCarrierAdmissionLocked(c)
	}
	now := r.offsetLocked()
	obs := []ByteObservation{{Direction: DirectionUplink, ByteScope: ByteScopeCarrierConnectionIO, ObservedBytes: OptionalUint64{Known: true}, State: ByteObservationStateProven}, {Direction: DirectionDownlink, ByteScope: ByteScopeCarrierConnectionIO, ObservedBytes: OptionalUint64{Known: true}, State: ByteObservationStateProven}}
	state := &recordStateCarrier{carrier: c, record: CarrierRecord{RuntimeInstanceID: r.runtimeInstanceID, CarrierReference: c.ref, CarrierKind: c.kind, ByteObservations: obs, ActivityState: ActivityAdmitted, CompletionState: CompletionOpen, AdmittedAtOffset: now, UpdatedAtOffset: now}}
	r.carriers[c.ref] = state
	r.carrierOrder = append(r.carrierOrder, c.ref)
	for _, direction := range []Direction{DirectionUplink, DirectionDownlink} {
		r.attachCarrierSeriesLocked(c.kind, direction, now)
	}
	r.appendEventLocked(Event{Type: EventAdmitted, Carrier: cloneCarrierRecordPtr(state.record)})
	return true
}

func (r *Registry) rejectCarrierAdmissionLocked(c *carrierSidecar) bool {
	if c == nil || carrierKindDirectionIndex(c.kind, DirectionUplink) < 0 || !c.omitted.CompareAndSwap(false, true) {
		return false
	}
	r.addDroppedCarriersLocked(1)
	r.loseCarrierMembershipLockedKind(c.kind)
	return false
}

func (r *Registry) drainCarrierAdmissionsLocked() {
	for drained := 0; drained < maxCarrierAdmissionDrainBatch; drained++ {
		select {
		case c := <-r.pendingCarriers:
			r.registerMuxCarrierLocked(c)
		default:
			return
		}
	}
	if len(r.pendingCarriers) != 0 {
		r.signalDirty()
	}
}

func (r *Registry) rejectPendingCarrierAdmissionsLocked() {
	for {
		select {
		case carrier := <-r.pendingCarriers:
			r.rejectCarrierAdmissionLocked(carrier)
		default:
			return
		}
	}
}

func (r *Registry) recordCarrierAdmissionLoss() {
	r.recordCarrierAdmissionLossKind(CarrierKindServerMuxFrameLink)
}

func (r *Registry) recordCarrierAdmissionLossKind(kind CarrierKind) {
	i := carrierKindDirectionIndex(kind, DirectionUplink)
	if i < 0 {
		return
	}
	r.incrementPendingLoss(&r.pendingCarrierDrops[i/2])
	r.signalDirty()
}

func (r *Registry) addDroppedCarriersLocked(delta uint64) {
	if math.MaxUint64-r.droppedCarriers < delta {
		r.droppedCarriers = math.MaxUint64
		return
	}
	r.droppedCarriers += delta
}

func (r *Registry) attachCarrierSeriesLocked(kind CarrierKind, direction Direction, now time.Duration) {
	i := carrierKindDirectionIndex(kind, direction)
	if i < 0 {
		return
	}
	if r.carrierCoverage[i].State == AccountingCoverageIndeterminate && r.carrierSeries[i] == nil {
		return
	}
	if r.carrierSeries[i] == nil {
		r.nextSeries++
		series := CarrierCounterSeries{RuntimeInstanceID: r.runtimeInstanceID, SeriesID: r.runtimeInstanceID + "-series-" + encodeUint64(r.nextSeries), CoverageGeneration: r.carrierCoverage[i].Generation, Key: CarrierCounterSeriesKey{CarrierKind: kind, Direction: direction, ByteScope: ByteScopeCarrierConnectionIO}, CumulativeBytes: OptionalUint64{Known: true}, ActiveCarrierCount: OptionalUint64{Known: true, Value: 1}, StartedAtOffset: now, SampledAtOffset: now, State: SeriesStateContinuous, StartReason: SeriesStartFirstObserved}
		if r.carrierCoverage[i].Generation > 1 {
			series.StartReason = SeriesStartAfterCoverageLoss
		}
		r.carrierSeries[i] = &carrierSeriesState{series: series, active: 1}
		copy := series
		r.appendEventLocked(Event{Type: EventCounterSeriesStarted, CarrierSeries: &copy, Reason: DiscontinuitySeriesCreated})
		return
	}
	r.carrierSeries[i].active++
	if r.carrierCoverage[i].State == AccountingCoverageComplete {
		r.carrierSeries[i].series.ActiveCarrierCount = OptionalUint64{Known: true, Value: r.carrierSeries[i].active}
	}
}

func (r *Registry) evictOldestTerminalCarrierLocked() bool {
	for index, ref := range r.carrierOrder {
		state := r.carriers[ref]
		if state == nil || state.record.CompletionState != CompletionTerminal {
			continue
		}
		record := cloneCarrierRecord(state.record)
		delete(r.carriers, ref)
		r.carrierOrder = append(r.carrierOrder[:index], r.carrierOrder[index+1:]...)
		r.evictedCarriers++
		r.appendEventLocked(Event{Type: EventCarrierDetailEvicted, Carrier: &record})
		return true
	}
	return false
}

func (c *serverMuxCarrier) Reserve() {
	if !c.lockOpen() {
		return
	}
	if c.reservations == math.MaxUint64 {
		c.reservationFault = true
	} else {
		c.reservations++
	}
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) Release() {
	if !c.lockOpen() {
		return
	}
	if c.reservations > 0 {
		c.reservations--
	} else {
		c.reservationFault = true
	}
	c.mu.Unlock()
	c.r.signalDirty()
}
func (c *serverMuxCarrier) Read(n uint64)           { c.add(DirectionUplink, n, nil) }
func (c *serverMuxCarrier) Write(n uint64, e error) { c.add(DirectionDownlink, n, e) }
func (c *serverMuxCarrier) add(d Direction, n uint64, e error) {
	if !c.lockOpen() {
		return
	}
	if e != nil {
		// The writer API exposes no accepted prefix. The sidecar kind fixes
		// whether this is the client uplink or server downlink boundary.
		c.pendingBoundaryError = true
	} else if d == DirectionUplink {
		if math.MaxUint64-c.pendingRead < n {
			c.pendingReadOverflow = true
		} else {
			c.pendingRead += n
		}
	} else if math.MaxUint64-c.pendingWrite < n {
		c.pendingWriteOverflow = true
	} else {
		c.pendingWrite += n
	}
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) ReaderExited() {
	if !c.lockOpen() {
		return
	}
	c.reader = true
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) MonitorCompleted() {
	if !c.lockOpen() {
		return
	}
	c.monitor = true
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) UplinkSealed() {
	if !c.lockOpen() {
		return
	}
	c.uplinkSealed = true
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) DownlinkSealed() {
	if !c.lockOpen() {
		return
	}
	c.downlinkSealed = true
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) ownerClosed() {
	if !c.lockOpen() {
		return
	}
	c.owner = true
	c.mu.Unlock()
	c.r.signalDirty()
}

func (c *serverMuxCarrier) lockOpen() bool {
	if c == nil || c.omitted.Load() {
		return false
	}
	c.mu.Lock()
	if c.r.continuationsClosed.Load() || c.state != carrierCommitted {
		c.mu.Unlock()
		return false
	}
	return true
}

type carrierPendingState struct {
	read, write                     uint64
	readOverflow, writeOverflow     bool
	uplinkFault, downlinkFault      bool
	terminalReady, reservationFault bool
}

func (c *serverMuxCarrier) consumePending() carrierPendingState {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := carrierPendingState{
		read:             c.pendingRead,
		write:            c.pendingWrite,
		readOverflow:     c.pendingReadOverflow,
		writeOverflow:    c.pendingWriteOverflow,
		uplinkFault:      c.kind == CarrierKindClientMuxFrameLink && c.pendingBoundaryError,
		downlinkFault:    c.kind == CarrierKindServerMuxFrameLink && c.pendingBoundaryError,
		reservationFault: c.reservationFault,
		terminalReady:    (c.kind == CarrierKindClientMuxFrameLink && c.workerQuiesced) || (c.kind == CarrierKindServerMuxFrameLink && c.owner && c.reader && c.monitor && c.uplinkSealed && c.downlinkSealed && c.reservations == 0),
	}
	c.pendingRead = 0
	c.pendingWrite = 0
	c.pendingReadOverflow = false
	c.pendingWriteOverflow = false
	c.pendingBoundaryError = false
	return pending
}

func (r *Registry) syncCarriersLocked() {
	for _, ref := range r.carrierOrder {
		state := r.carriers[ref]
		if state == nil || state.carrier == nil || state.record.CompletionState == CompletionTerminal {
			continue
		}
		pending := state.carrier.consumePending()
		changed := false
		changed = r.applyCarrierDirectionLocked(state, DirectionUplink, pending.read, pending.readOverflow, pending.uplinkFault) || changed
		changed = r.applyCarrierDirectionLocked(state, DirectionDownlink, pending.write, pending.writeOverflow, pending.downlinkFault) || changed
		if pending.reservationFault && state.record.CompletionState == CompletionOpen {
			state.record.CompletionState = CompletionIndeterminate
			state.record.IndeterminateReason = IndeterminateAsyncSessionUnobserved
			changed = true
			r.loseCarrierDirectionLockedKind(state.record.CarrierKind, DirectionUplink, DiscontinuityAccountingCallbackLost, SeriesStateIndeterminate)
			r.loseCarrierDirectionLockedKind(state.record.CarrierKind, DirectionDownlink, DiscontinuityAccountingCallbackLost, SeriesStateIndeterminate)
		}
		if changed {
			state.record.UpdatedAtOffset = r.offsetLocked()
			r.appendEventLocked(Event{Type: EventUpdated, Carrier: cloneCarrierRecordPtr(state.record)})
		}
		if pending.terminalReady && !pending.reservationFault {
			r.finishCarrierLocked(state)
		}
	}
}

func (r *Registry) applyCarrierDirectionLocked(state *recordStateCarrier, direction Direction, delta uint64, overflow, unproven bool) bool {
	if state == nil {
		return false
	}
	for i := range state.record.ByteObservations {
		observation := &state.record.ByteObservations[i]
		if observation.Direction != direction {
			continue
		}
		if unproven {
			if observation.State == ByteObservationStateIndeterminate {
				return false
			}
			observation.State = ByteObservationStateIndeterminate
			observation.ObservedBytes = OptionalUint64{}
			observation.AccountingFault = AccountingFaultBoundaryUnproven
			r.loseCarrierDirectionLockedKind(state.record.CarrierKind, direction, DiscontinuityAccountingScopeUnproven, SeriesStateIndeterminate)
			return true
		}
		if overflow || observation.ObservedBytes.Known && math.MaxUint64-observation.ObservedBytes.Value < delta {
			if observation.State == ByteObservationStateOverflowed {
				return false
			}
			observation.State = ByteObservationStateOverflowed
			observation.ObservedBytes = OptionalUint64{}
			observation.AccountingFault = AccountingFaultCounterOverflow
			r.loseCarrierDirectionLockedKind(state.record.CarrierKind, direction, DiscontinuityCounterOverflow, SeriesStateOverflowed)
			return true
		}
		if delta == 0 || observation.State != ByteObservationStateProven || !observation.ObservedBytes.Known {
			return false
		}
		series := r.carrierSeries[carrierKindDirectionIndex(state.record.CarrierKind, direction)]
		if series != nil && series.series.CumulativeBytes.Known && math.MaxUint64-series.series.CumulativeBytes.Value < delta {
			observation.State = ByteObservationStateOverflowed
			observation.ObservedBytes = OptionalUint64{}
			observation.AccountingFault = AccountingFaultCounterOverflow
			r.loseCarrierDirectionLockedKind(state.record.CarrierKind, direction, DiscontinuityCounterOverflow, SeriesStateOverflowed)
			return true
		}
		observation.ObservedBytes.Value += delta
		if series != nil && series.series.State == SeriesStateContinuous && series.series.CumulativeBytes.Known {
			series.series.CumulativeBytes.Value += delta
			series.series.SampledAtOffset = r.offsetLocked()
		}
		if state.record.ActivityState == ActivityAdmitted {
			state.record.ActivityState = ActivityActive
			state.record.ActiveAtOffset = r.offsetLocked()
		}
		return true
	}
	return false
}

func (r *Registry) finishCarrierLocked(state *recordStateCarrier) {
	if state == nil || state.record.CompletionState != CompletionOpen {
		return
	}
	state.record.CompletionState = CompletionTerminal
	state.record.IndeterminateReason = ""
	state.record.TerminalClass = ""
	state.record.TerminalAtOffset = r.offsetLocked()
	state.record.UpdatedAtOffset = state.record.TerminalAtOffset
	r.appendEventLocked(Event{Type: EventTerminal, Carrier: cloneCarrierRecordPtr(state.record)})
	for _, direction := range []Direction{DirectionUplink, DirectionDownlink} {
		i := carrierKindDirectionIndex(state.record.CarrierKind, direction)
		series := r.carrierSeries[i]
		if series == nil {
			continue
		}
		if series.active > 0 {
			series.active--
		}
		if r.carrierCoverage[i].State == AccountingCoverageComplete {
			series.series.ActiveCarrierCount = OptionalUint64{Known: true, Value: series.active}
		}
		if series.active == 0 && r.carrierCoverage[i].State == AccountingCoverageIndeterminate && !r.carrierMembershipLost[i] {
			series.series.ActiveCarrierCount = OptionalUint64{Known: true}
			copy := series.series
			r.appendEventLocked(Event{Type: EventCounterSeriesEnded, CarrierSeries: &copy, Reason: series.series.DiscontinuityReason})
			r.carrierSeries[i] = nil
			r.carrierCoverage[i].State = AccountingCoverageComplete
			r.carrierCoverage[i].Reason = ""
			r.carrierCoverage[i].ChangedAtOffset = r.offsetLocked()
			coverage := r.carrierCoverage[i]
			r.appendEventLocked(Event{Type: EventCoverageDiscontinuity, CarrierCoverage: &coverage})
		}
	}
}

func (r *Registry) stopCarriersLocked() {
	for _, ref := range r.carrierOrder {
		state := r.carriers[ref]
		if state == nil || state.record.CompletionState == CompletionTerminal {
			continue
		}
		state.record.CompletionState = CompletionIndeterminate
		state.record.IndeterminateReason = IndeterminateRuntimeStopped
		state.record.TerminalClass = ""
		state.record.UpdatedAtOffset = r.offsetLocked()
		for i := range state.record.ByteObservations {
			observation := &state.record.ByteObservations[i]
			if observation.State == ByteObservationStateProven {
				observation.State = ByteObservationStateIndeterminate
				observation.ObservedBytes = OptionalUint64{}
				observation.AccountingFault = AccountingFaultCallbackLost
			}
		}
		r.appendEventLocked(Event{Type: EventUpdated, Carrier: cloneCarrierRecordPtr(state.record)})
	}
	for _, kind := range []CarrierKind{CarrierKindServerMuxFrameLink, CarrierKindClientMuxFrameLink} {
		r.loseCarrierDirectionLockedKind(kind, DirectionUplink, DiscontinuityAccountingCallbackLost, SeriesStateIndeterminate)
		r.loseCarrierDirectionLockedKind(kind, DirectionDownlink, DiscontinuityAccountingCallbackLost, SeriesStateIndeterminate)
	}
}
