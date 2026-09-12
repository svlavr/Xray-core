package flow

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/transport"
)

type ExternalOwnerClass string

const (
	ExternalOwnerListenerTCP  ExternalOwnerClass = "LISTENER_TCP"
	ExternalOwnerListenerUNIX ExternalOwnerClass = "LISTENER_UNIX"
	ExternalOwnerTUNTCP       ExternalOwnerClass = "TUN_TCP"
	ExternalOwnerWireGuardTCP ExternalOwnerClass = "WIREGUARD_TCP"
	ExternalOwnerTUNUDP       ExternalOwnerClass = "TUN_UDP_ASSOCIATION"
	ExternalOwnerWireGuardUDP ExternalOwnerClass = "WIREGUARD_UDP_ASSOCIATION"
	ExternalOwnerListenerUDP  ExternalOwnerClass = "LISTENER_UDP_ASSOCIATION"
)

type externalOwnerContextKey struct{}

type externalOwnerCloseReceipt struct {
	class    TerminalClass
	category string
}

// ExternalOwnerScope is a rootless one-shot token created by the stock owner
// before DispatchLink. It observes the owner's existing close after that close
// succeeds or fails; it never closes traffic itself.
type ExternalOwnerScope struct {
	mu          sync.Mutex
	class       ExternalOwnerClass
	claimed     atomic.Bool
	replayed    atomic.Bool
	link        atomic.Pointer[transport.Link]
	handle      atomic.Pointer[Handle]
	outcome     atomic.Pointer[outcomeReceipt]
	closed      atomic.Pointer[externalOwnerCloseReceipt]
	finalized   atomic.Bool
	accounted   atomic.Bool
	vlessUDP    atomic.Bool
	dokodemoUDP atomic.Bool
	hysteriaUDP atomic.Bool
}

func NewExternalOwnerScope(class ExternalOwnerClass) *ExternalOwnerScope {
	switch class {
	case ExternalOwnerListenerTCP, ExternalOwnerListenerUNIX, ExternalOwnerTUNTCP, ExternalOwnerWireGuardTCP, ExternalOwnerTUNUDP, ExternalOwnerWireGuardUDP, ExternalOwnerListenerUDP:
		return &ExternalOwnerScope{class: class}
	default:
		return nil
	}
}

// AuthorizeDokodemoUDP permits the one DispatchLink call made by an exact UDP
// listener association. Other listener and inbound protocols remain unobserved.
func (s *ExternalOwnerScope) AuthorizeDokodemoUDP() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.class != ExternalOwnerListenerUDP || s.claimed.Load() || s.closed.Load() != nil || s.dokodemoUDP.Load() {
		return false
	}
	s.dokodemoUDP.Store(true)
	return true
}

func ContextWithExternalOwnerScope(ctx context.Context, scope *ExternalOwnerScope) context.Context {
	if ctx == nil || scope == nil {
		return ctx
	}
	return context.WithValue(ctx, externalOwnerContextKey{}, scope)
}

func ExternalOwnerScopeFromContext(ctx context.Context) *ExternalOwnerScope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(externalOwnerContextKey{}).(*ExternalOwnerScope)
	return scope
}

func contextWithoutExternalOwnerScope(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, externalOwnerContextKey{}, maskedFlowObservation{})
}

func (s *ExternalOwnerScope) claim(link *transport.Link) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if link == nil || !s.claimed.CompareAndSwap(false, true) {
		s.replayed.Store(true)
		s.markBoundFault(LifecycleFaultExternalOwnerReplay)
		return false
	}
	s.link.Store(link)
	return true
}

func (s *ExternalOwnerScope) bind(handle *Handle) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if handle == nil || handle.root == nil || handle.root.logical == nil || handle.root.retired.Load() || !s.claimed.Load() {
		return false
	}
	if !s.handle.CompareAndSwap(nil, handle) {
		s.replayed.Store(true)
		s.markBoundFault(LifecycleFaultExternalOwnerReplay)
		return false
	}
	if s.replayed.Load() {
		handle.root.logical.markLifecycleFault(LifecycleFaultExternalOwnerReplay)
	}
	if outcome := s.outcome.Load(); outcome != nil {
		handle.root.logical.RecordOutcome(outcome.class, outcome.category)
	}
	s.finalizeLocked()
	return true
}

func (s *ExternalOwnerScope) Handle() *Handle {
	if s == nil {
		return nil
	}
	return s.handle.Load()
}

func (s *ExternalOwnerScope) Link() *transport.Link {
	if s == nil {
		return nil
	}
	return s.link.Load()
}

// AccountingBound reports whether the exact external link has its single
// post-I/O accounting boundary installed.
func (s *ExternalOwnerScope) AccountingBound() bool {
	return s != nil && s.accounted.Load()
}

// AuthorizeVLESSUDP permits one decoded ordinary VLESS UDP request to use this
// exact listener scope. It is intentionally narrower than the listener class:
// other DispatchLink UDP callers remain unobserved.
func (s *ExternalOwnerScope) AuthorizeVLESSUDP() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimed.Load() || s.closed.Load() != nil || s.vlessUDP.Load() || s.hysteriaUDP.Load() {
		return false
	}
	switch s.class {
	case ExternalOwnerListenerTCP, ExternalOwnerListenerUNIX:
		s.vlessUDP.Store(true)
		return true
	default:
		return false
	}
}

// AuthorizeHysteriaUDP permits the one DispatchLink call made by one validated
// Hysteria server InterConn epoch. The listener scope alone remains
// insufficient: TCP Hysteria and other listener protocols are unobserved.
func (s *ExternalOwnerScope) AuthorizeHysteriaUDP() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.class != ExternalOwnerListenerTCP || s.claimed.Load() || s.closed.Load() != nil || s.hysteriaUDP.Load() || s.vlessUDP.Load() {
		return false
	}
	s.hysteriaUDP.Store(true)
	return true
}

// MarkVLESSUDPDownlinkUnproven records the VLESS packet-writer silent-drop
// boundary on the exact admitted root without changing that writer's traffic
// behavior.
func (s *ExternalOwnerScope) MarkVLESSUDPDownlinkUnproven() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.vlessUDP.Load() || (s.class != ExternalOwnerListenerTCP && s.class != ExternalOwnerListenerUNIX) {
		s.mu.Unlock()
		return
	}
	handle := s.handle.Load()
	s.mu.Unlock()
	if handle != nil {
		handle.MarkDirectionAccountingBoundaryUnproven(DirectionDownlink)
	}
}

func (s *ExternalOwnerScope) bindAccounting(link *transport.Link) *Handle {
	if s == nil || link == nil || s.Link() != link {
		return nil
	}
	handle := s.Handle()
	if handle == nil || handle.root == nil || handle.root.logical == nil || handle.root.retired.Load() {
		return nil
	}
	if !s.accounted.CompareAndSwap(false, true) {
		return nil
	}
	return handle
}

func (s *ExternalOwnerScope) publishOutcomeLocked(class TerminalClass, category string) {
	candidate := &outcomeReceipt{class: class, category: boundedCategory(category), rank: outcomeRank(class)}
	for {
		current := s.outcome.Load()
		if current != nil && current.rank >= candidate.rank {
			break
		}
		if s.outcome.CompareAndSwap(current, candidate) {
			break
		}
	}
	if handle := s.handle.Load(); handle != nil && handle.root != nil && handle.root.logical != nil {
		handle.root.logical.RecordOutcome(class, category)
	}
}

// AfterOwnerClose is called only after the stock owner has already performed
// its close. It atomically publishes the owner and close results before
// sealing observation, so neither DispatchLink return nor a racing bind can
// fabricate terminal proof.
func (s *ExternalOwnerScope) AfterOwnerClose(ownerErr, closeErr error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() != nil {
		return
	}
	ownerClass, ownerCategory := outcomeFromError(ownerErr)
	s.publishOutcomeLocked(ownerClass, ownerCategory)
	closeClass, closeCategory := outcomeFromError(closeErr)
	s.closed.Store(&externalOwnerCloseReceipt{class: closeClass, category: boundedCategory(closeCategory)})
	s.finalizeLocked()
}

func (s *ExternalOwnerScope) finalizeLocked() {
	if s == nil || s.closed.Load() == nil {
		return
	}
	handle := s.handle.Load()
	if handle == nil || handle.root == nil || handle.root.logical == nil || handle.root.retired.Load() || !s.finalized.CompareAndSwap(false, true) {
		return
	}
	root := handle.root.logical
	if outcome := s.outcome.Load(); outcome != nil {
		root.RecordOutcome(outcome.class, outcome.category)
	}
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	closeReceipt := s.closed.Load()
	root.SealOwner(closeReceipt.class, closeReceipt.category)
}

func (s *ExternalOwnerScope) markBoundFault(fault LifecycleFault) {
	if handle := s.Handle(); handle != nil && handle.root != nil && handle.root.logical != nil {
		handle.root.logical.markLifecycleFault(fault)
	}
}

func (r *Registry) AdmitExternalTCP(ctx context.Context, source, originalDestination, protocol string, scope *ExternalOwnerScope, link *transport.Link) *Handle {
	if r == nil || scope == nil || !scope.isTCPOwner() || !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	return scope.admitAndBindLocked(link, func() *Handle {
		admission := r.prepareTCPAdmission(ctx, source, originalDestination, protocol, ByteScopeDispatcherExternalLinkIO)
		if admission == nil {
			return nil
		}
		return r.publishAdmission(admission)
	})
}

func (s *ExternalOwnerScope) isTCPOwner() bool {
	return s != nil && (s.class == ExternalOwnerListenerTCP || s.class == ExternalOwnerListenerUNIX || s.class == ExternalOwnerTUNTCP || s.class == ExternalOwnerWireGuardTCP)
}

// AdmitExternalUDP creates one root for a source-keyed synthetic netstack UDP
// association. Only the two proven netstack owner classes and an explicitly
// authorized VLESS listener may use this seam; all other DispatchLink UDP
// callers retain stock traffic without observation.
func (r *Registry) AdmitExternalUDP(ctx context.Context, source, originalDestination, protocol string, scope *ExternalOwnerScope, link *transport.Link) *Handle {
	if r == nil || scope == nil || !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	return scope.admitUDPAndBindLocked(link, func() *Handle {
		admission := r.prepareNativeLinkAdmission(ctx, KindUDPAssociation, source, originalDestination, protocol, ByteScopeDispatcherExternalLinkIO)
		if admission == nil {
			return nil
		}
		if scope.dokodemoUDP.Load() || scope.hysteriaUDP.Load() {
			admission.handle.MarkDirectionAccountingBoundaryUnproven(DirectionDownlink)
			admission.record.record.ByteObservations = admission.root.logical.View().ByteObservations
		}
		return r.publishAdmission(admission)
	})
}

func (s *ExternalOwnerScope) isUDPAssociationOwner() bool {
	return s != nil && (s.class == ExternalOwnerTUNUDP || s.class == ExternalOwnerWireGuardUDP ||
		((s.class == ExternalOwnerListenerTCP || s.class == ExternalOwnerListenerUNIX) && s.vlessUDP.Load()) ||
		(s.class == ExternalOwnerListenerUDP && s.dokodemoUDP.Load()) ||
		(s.class == ExternalOwnerListenerTCP && s.hysteriaUDP.Load()))
}

func (s *ExternalOwnerScope) admitUDPAndBindLocked(link *transport.Link, admit func() *Handle) *Handle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isUDPAssociationOwner() {
		return nil
	}
	if (s.vlessUDP.Load() || s.dokodemoUDP.Load() || s.hysteriaUDP.Load()) && s.closed.Load() != nil {
		return nil
	}
	return s.admitAndBindHeld(link, admit)
}

// admitAndBindLocked serializes the one-shot external token while registry
// admission is published synchronously or handed to its bounded pending queue.
// The token is claimed only after that non-blocking publication succeeds.
func (s *ExternalOwnerScope) admitAndBindLocked(link *transport.Link, admit func() *Handle) *Handle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admitAndBindHeld(link, admit)
}

func (s *ExternalOwnerScope) admitAndBindHeld(link *transport.Link, admit func() *Handle) *Handle {
	if link == nil || s.claimed.Load() {
		s.replayed.Store(true)
		s.markBoundFault(LifecycleFaultExternalOwnerReplay)
		return nil
	}
	handle := admit()
	if handle == nil {
		return nil
	}
	s.claimed.Store(true)
	s.link.Store(link)
	s.handle.Store(handle)
	if s.replayed.Load() {
		handle.root.logical.markLifecycleFault(LifecycleFaultExternalOwnerReplay)
	}
	if outcome := s.outcome.Load(); outcome != nil {
		handle.root.logical.RecordOutcome(outcome.class, outcome.category)
	}
	s.finalizeLocked()
	return handle
}
