package flow

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
)

type (
	xudpObservationContextKey struct{}
	XUDPScope                 struct {
		mu                        sync.Mutex
		registry                  *Registry
		carrier, source, dest     string
		handle                    *Handle
		epochLease                task.ParticipantLease
		closed                    bool
		terminalizing             bool
		next                      uint64
		quota, pendingN, receiptN int
		pending                   [16]xudpPending
		// Fixed lease slots are searched by full ordinal; no ordinal modulo alias.
		bindings                    [16]*xudpBinding
		tailLossFirst, tailLossLast XUDPTransitionKey
		hasTailLoss                 bool
		tailLossReason              XUDPTransitionLossReason
	}
)

type xudpBinding struct {
	epoch                                      *XUDPScope
	ordinal                                    uint64
	carrier                                    string
	installed, readerExited, aborted, detached atomic.Bool
	leaseReleased                              atomic.Bool
	lease                                      task.ParticipantLease
	transition                                 XUDPBindingTransition
	deactivated                                atomic.Bool
	deactivation                               session.XUDPDetachTransition
	authorityValid                             bool
}
type xudpPending struct {
	binding    *xudpBinding
	transition XUDPBindingTransition
	loss       *XUDPTransitionKey
	lossReason XUDPTransitionLossReason
}

func (r *Registry) NewXUDPObservation(d net.Destination, source string) session.XUDPEpochObservation {
	if r == nil || d.Network != net.Network_UDP {
		return nil
	}
	c := r.newCarrierReference()
	if c == "" {
		return nil
	}
	return r.newXUDPObservation(d, source, c)
}

func (r *Registry) newXUDPObservation(d net.Destination, source, c string) session.XUDPEpochObservation {
	if r == nil || d.Network != net.Network_UDP || r.continuationsClosed.Load() || c == "" {
		return nil
	}
	return &XUDPScope{registry: r, carrier: c, source: source, dest: d.String(), next: 1}
}

func (s *XUDPScope) Context(ctx context.Context) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, xudpObservationContextKey{}, s)
}

func XUDPObservationFromContext(ctx context.Context) *XUDPScope {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(xudpObservationContextKey{}).(*XUDPScope)
	return s
}

func (r *Registry) AdmitXUDP(s *XUDPScope, d net.Destination) *Handle {
	if r == nil || s == nil || d.Network != net.Network_UDP || !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	s.mu.Lock()
	if s.registry != r || s.closed || s.handle != nil || s.dest != d.String() {
		s.mu.Unlock()
		return nil
	}
	a := r.prepareXUDPAdmission(s.source, s.dest, s.carrier)
	if a == nil {
		s.mu.Unlock()
		return nil
	}
	s.handle = a.handle
	s.epochLease = a.handle.root.logical.AcquireParticipant()
	if s.epochLease == nil {
		s.retireLocked()
		s.mu.Unlock()
		return nil
	}
	s.quota = r.xudpTransitionQuota()
	a.root.xudp = s
	a.onRejected = s.rejectAdmission
	s.mu.Unlock()
	if r.publishAdmission(a) == nil {
		s.rejectAdmission()
		return nil
	}
	return a.handle
}

func (s *XUDPScope) rejectAdmission() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retireLocked()
}

func (r *Registry) xudpTransitionQuota() int {
	q := r.maxEvents / r.maxRecords
	if q < 1 {
		return 1
	}
	if q > 16 {
		return 16
	}
	return q
}

func (r *Registry) acquireXUDPTransitionCredit() bool {
	for {
		n := r.xudpTransitionCredits.Load()
		if n <= 0 {
			return false
		}
		if r.xudpTransitionCredits.CompareAndSwap(n, n-1) {
			return true
		}
	}
}
func (r *Registry) releaseXUDPTransitionCredit() { r.xudpTransitionCredits.Add(1) }
func (r *Registry) prepareXUDPAdmission(source, dest, c string) *pendingAdmission {
	a := r.prepareMuxSessionAdmission(source, dest, c)
	if a == nil {
		return nil
	}
	a.record.record.FlowKind = KindXUDPLogical
	a.record.record.XUDPNextBindingOrdinal = 1
	a.record.record.XUDPTransitionState = XUDPTransitionEvidenceComplete
	a.record.record.XUDPTransitionLossReason = XUDPTransitionLossNone
	return a
}

func (s *XUDPScope) PrepareBinding(capability session.XUDPCarrierObservation) session.XUDPBindingObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.terminalizing || s.handle == nil || s.registry.continuationsClosed.Load() {
		return nil
	}
	c, valid := s.carrier, true
	if capability != nil {
		carrier, ok := capability.(*MuxCarrier)
		if !ok || carrier.registry != s.registry || carrier.closed.Load() || carrier.reference == "" {
			valid = false
		} else {
			c = carrier.reference
		}
	} else if s.next != 1 {
		valid = false
	}
	if s.next == 0 { // ordinal exhaustion is observation-closed, never wrapped.
		s.closed = true
		return nil
	}
	b := &xudpBinding{epoch: s, ordinal: s.next, carrier: c, authorityValid: valid}
	s.next++
	return b
}

func (b *xudpBinding) Install() bool {
	if b == nil || !b.installed.CompareAndSwap(false, true) {
		return false
	}
	s := b.epoch
	if !s.registry.beginAdmission() {
		b.aborted.Store(true)
		return false
	}
	defer s.registry.endAdmission()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.terminalizing || s.handle == nil || s.handle.root.retired.Load() {
		b.aborted.Store(true)
		return false
	}
	if !b.authorityValid {
		s.noteLossReason(b, XUDPBindingActionAttach, XUDPTransitionLossAuthorityUnavailable)
		return true
	}
	if s.receiptN >= s.quota || s.pendingN >= len(s.pending) || !s.registry.acquireXUDPTransitionCredit() {
		s.noteLoss(b, XUDPBindingActionAttach)
		b.aborted.Store(true)
		return false
	}
	b.lease = s.handle.root.logical.AcquireParticipant()
	if b.lease == nil {
		s.registry.releaseXUDPTransitionCredit()
		b.aborted.Store(true)
		return false
	}
	b.transition = XUDPBindingTransition{Ordinal: b.ordinal, Action: XUDPBindingActionAttach, CarrierReference: b.carrier}
	if !s.addBindingLocked(b) {
		b.lease.Release(nil)
		b.lease = nil
		s.registry.releaseXUDPTransitionCredit()
		s.noteLoss(b, XUDPBindingActionAttach)
		b.aborted.Store(true)
		return false
	}
	s.pending[s.pendingN] = xudpPending{binding: b, transition: b.transition}
	s.pendingN++
	s.receiptN++
	s.handle.root.logical.markDirty()
	s.registry.signalDirty()
	return true
}

func (b *xudpBinding) Abort() {
	if b == nil {
		return
	}
	b.aborted.Store(true)
	b.releaseLeaseOnce()
}

func (b *xudpBinding) releaseLeaseOnce() {
	if b == nil || !b.leaseReleased.CompareAndSwap(false, true) {
		return
	}
	if b.lease != nil {
		b.lease.Release(nil)
		b.lease = nil
	}
}

func (b *xudpBinding) ReaderExited() {
	if b == nil || b.aborted.Load() || !b.authorityValid {
		return
	}
	s := b.epoch
	s.mu.Lock()
	defer s.mu.Unlock()
	b.readerExited.Store(true)
	b.tryDetachLocked()
}

func (b *xudpBinding) Deactivate(t session.XUDPDetachTransition) {
	if b == nil || b.aborted.Load() || !b.authorityValid {
		return
	}
	s := b.epoch
	s.mu.Lock()
	defer s.mu.Unlock()
	b.deactivation = t
	b.deactivated.Store(true)
	b.tryDetachLocked()
}

func (b *xudpBinding) RevokeUnproven() {
	if b == nil || !b.authorityValid {
		return
	}
	s := b.epoch
	if !s.registry.beginAdmission() {
		return
	}
	defer s.registry.endAdmission()
	if !b.aborted.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.lease == nil {
		return
	}
	b.detached.Store(true)
	s.noteLossReason(b, XUDPBindingActionDetach, XUDPTransitionLossReaderExitUnproven)
}

func (b *xudpBinding) tryDetachLocked() {
	s := b.epoch
	if b.aborted.Load() || !b.readerExited.Load() || !b.deactivated.Load() || !b.detached.CompareAndSwap(false, true) {
		return
	}
	if !s.registry.beginAdmission() {
		return
	}
	defer s.registry.endAdmission()
	if s.closed || s.receiptN >= s.quota || s.pendingN >= len(s.pending) || !s.registry.acquireXUDPTransitionCredit() {
		s.noteLoss(b, XUDPBindingActionDetach)
		return
	}
	b.transition = XUDPBindingTransition{Ordinal: b.ordinal, Action: XUDPBindingActionDetach, CarrierReference: b.carrier, DetachTransition: XUDPDetachTransition(b.deactivation)}
	s.pending[s.pendingN] = xudpPending{binding: b, transition: b.transition}
	s.pendingN++
	s.receiptN++
	s.handle.root.logical.markDirty()
	s.registry.signalDirty()
}

func (s *XUDPScope) noteLoss(binding *xudpBinding, a XUDPBindingAction) {
	s.noteLossReason(binding, a, XUDPTransitionLossCapacityExceeded)
}

func (s *XUDPScope) noteLossReason(binding *xudpBinding, a XUDPBindingAction, reason XUDPTransitionLossReason) {
	k := XUDPTransitionKey{Ordinal: binding.ordinal, Action: a}
	if s.pendingN < len(s.pending) {
		key := k
		s.pending[s.pendingN] = xudpPending{loss: &key, lossReason: reason}
		s.pendingN++
	} else if !s.hasTailLoss {
		s.tailLossFirst = k
		s.tailLossLast = k
		s.hasTailLoss = true
		s.tailLossReason = reason
	} else {
		s.tailLossLast = k
	}
	s.handle.root.logical.markDirty()
	s.registry.signalDirty()
}

func (s *XUDPScope) WriteReplaced() {
	if s == nil {
		return
	}
	s.mu.Lock()
	closed, handle := s.closed || s.terminalizing || s.registry.continuationsClosed.Load(), s.handle
	s.mu.Unlock()
	if handle != nil && !closed {
		handle.MarkAccountingBoundaryUnproven()
		handle.RecordOutcome(TerminalClassLocalError, "XUDP_RETAINED_WRITE_REPLACED")
	}
}

func (s *XUDPScope) InitialWriteUnproven() {
	if s == nil {
		return
	}
	s.mu.Lock()
	closed, handle := s.closed || s.terminalizing || s.registry.continuationsClosed.Load(), s.handle
	s.mu.Unlock()
	if handle != nil && !closed {
		handle.MarkDirectionAccountingBoundaryUnproven(DirectionUplink)
		handle.RecordOutcome(TerminalClassLocalError, "XUDP_INITIAL_WRITE_ACCEPTANCE_UNKNOWN")
	}
}

func (s *XUDPScope) Retire() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Retire is only for an unpublished/provisional scope. Published roots must
	// retain their receipts and leases until detach/loss materialization or the
	// explicit registry-close revocation path.
	if s.handle == nil {
		s.retireLocked()
	}
}

func (s *XUDPScope) Terminalize() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed || s.terminalizing || s.handle == nil || s.handle.root == nil || s.epochLease == nil {
		s.mu.Unlock()
		return
	}
	s.terminalizing = true
	handle, lease := s.handle, s.epochLease
	s.epochLease = nil
	s.mu.Unlock()
	// Called only by mux after exact map authority was removed and both local
	// retained-link close actions completed. The direction receipts are local
	// close proof, not a claim about the carrier or remote peer.
	handle.root.logical.SealXUDPRetainedLink()
	lease.Release(nil)
}

func (s *XUDPScope) retireLocked() {
	if s.closed {
		return
	}
	s.closed = true
	if s.epochLease != nil {
		s.epochLease.Release(nil)
		s.epochLease = nil
	}
	for i := 0; i < s.pendingN; i++ {
		b := s.pending[i].binding
		if b != nil {
			s.registry.releaseXUDPTransitionCredit()
			b.Abort()
		}
		s.pending[i] = xudpPending{}
	}
	s.pendingN = 0
	s.receiptN = 0
	for index, b := range s.bindings {
		if b != nil {
			b.Abort()
		}
		s.bindings[index] = nil
	}
	// A rejected provisional root was never published, so release its original
	// owner participant without fabricating a public terminal receipt.
	if s.handle != nil && s.handle.root != nil && s.handle.root.logical != nil {
		s.handle.root.logical.SealOwner(TerminalClassUnknown, "")
	}
}

func (s *XUDPScope) syncLocked(root *rootState, now time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingN == 0 && !s.hasTailLoss {
		return false
	}
	r := &root.record.record
	changed := false
	materializeLoss := func(first, last XUDPTransitionKey, reason XUDPTransitionLossReason) {
		r.XUDPTransitionIncomplete = true
		r.XUDPTransitionState = XUDPTransitionEvidenceIncomplete
		if r.XUDPTransitionLossReason == XUDPTransitionLossNone || r.XUDPTransitionLossReason == "" {
			r.XUDPTransitionLossReason = reason
		}
		if !r.XUDPLostTransitionFirst.Known {
			r.XUDPLostTransitionFirst = OptionalUint64{Known: true, Value: first.Ordinal}
			r.XUDPLostTransitionFirstAction = first.Action
		}
		r.XUDPLostTransitionLast = OptionalUint64{Known: true, Value: last.Ordinal}
		r.XUDPLostTransitionLastAction = last.Action
		// Resolve lost detaches by their full ordinal against fixed lease slots.
		// A slot is not reusable before this release, so no unbounded pointer
		// list or modulo alias is needed when loss spans multiple drains.
		for _, binding := range s.bindings {
			if binding == nil || !binding.detached.Load() || binding.lease == nil ||
				binding.ordinal < first.Ordinal || binding.ordinal > last.Ordinal {
				continue
			}
			binding.releaseLeaseOnce()
			s.removeBindingLocked(binding.ordinal)
		}
		// Loss is persistent root state, not an event-ring gap. Materialize its
		// record update before assigning a sequence to any later transition.
		r.UpdatedAtOffset = now
		s.registry.appendRecordEventLocked(EventUpdated, root.record)
		changed = true
	}
	for i := 0; i < s.pendingN; i++ {
		b := s.pending[i].binding
		if s.pending[i].loss != nil {
			materializeLoss(*s.pending[i].loss, *s.pending[i].loss, s.pending[i].lossReason)
			s.pending[i] = xudpPending{}
			continue
		}
		tr := s.pending[i].transition
		tr.RuntimeInstanceID = s.handle.runtimeInstanceID
		tr.FlowID = s.handle.flowID
		tr.ObservedAtOffset = now
		if tr.Action == XUDPBindingActionAttach {
			r.XUDPBindings = append(r.XUDPBindings, XUDPBinding{Ordinal: tr.Ordinal, CarrierReference: tr.CarrierReference, AttachedAtOffset: now})
			if len(r.XUDPBindings) > 8 {
				r.XUDPBindings = append([]XUDPBinding(nil), r.XUDPBindings[len(r.XUDPBindings)-8:]...)
				r.XUDPHistoryTruncated = true
			}
		} else {
			for j := range r.XUDPBindings {
				if r.XUDPBindings[j].Ordinal == tr.Ordinal {
					r.XUDPBindings[j].DetachedAtOffset = now
					r.XUDPBindings[j].DetachTransition = string(tr.DetachTransition)
				}
			}
			b.releaseLeaseOnce()
			s.removeBindingLocked(b.ordinal)
		}
		r.XUDPNextBindingOrdinal = s.next
		if len(r.XUDPBindings) > 0 {
			r.XUDPFirstRetainedOrdinal = OptionalUint64{Known: true, Value: r.XUDPBindings[0].Ordinal}
		}
		c := tr
		s.registry.appendEventLocked(Event{Type: EventXUDPBindingTransition, XUDPBinding: &c})
		s.registry.releaseXUDPTransitionCredit()
		s.pending[i] = xudpPending{}
		changed = true
	}
	s.pendingN = 0
	s.receiptN = 0
	if s.hasTailLoss {
		materializeLoss(s.tailLossFirst, s.tailLossLast, s.tailLossReason)
		s.hasTailLoss = false
	}
	return changed
}

func (s *XUDPScope) revokeForRegistryClose() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Registry shutdown has no reader-exit receipt. Revoke ownership and
	// release each lease once, but deliberately publish no detach or terminal.
	s.retireLocked()
}

func (s *XUDPScope) addBindingLocked(binding *xudpBinding) bool {
	for index, current := range s.bindings {
		if current == nil {
			s.bindings[index] = binding
			return true
		}
	}
	return false
}

func (s *XUDPScope) removeBindingLocked(ordinal uint64) {
	for index, binding := range s.bindings {
		if binding != nil && binding.ordinal == ordinal {
			s.bindings[index] = nil
			return
		}
	}
}

var (
	_ session.XUDPEpochObservation   = (*XUDPScope)(nil)
	_ session.XUDPBindingObservation = (*xudpBinding)(nil)
)
