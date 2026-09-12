package flow

import (
	"context"
	"math"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
)

type muxSessionContextKey struct{}

// MuxCarrier is one runtime-local correlation capability for a single stock
// mux.ServerWorker. Its reference is never a logical-flow identity.
type MuxCarrier struct {
	registry  *Registry
	reference string
	closed    atomic.Bool
	frame     *serverMuxCarrier
}

// MuxClientCarrier is one selected-outbound ClientWorker correlation. It is
// neither a logical-flow identity nor carrier lifecycle/accounting evidence.
type MuxClientCarrier struct {
	registry  *Registry
	reference string
	frame     *clientMuxCarrier
}

// MuxClientSessionScope binds the exact selected top-level outbound to an
// already admitted root. It has no authority to create or close a flow.
type MuxClientSessionScope struct {
	handle              *Handle
	selectedOutboundTag string
}

// NewMuxCarrierObservation mints one non-reused reference from the registry's
// runtime namespace. Exhaustion loses observation coverage, never traffic.
func (r *Registry) NewMuxCarrierObservation() *MuxCarrier {
	reference := r.newCarrierReferenceForKind(CarrierKindServerMuxFrameLink)
	if reference == "" {
		return nil
	}
	return &MuxCarrier{registry: r, reference: reference, frame: r.admitServerMuxCarrier(reference)}
}

func (r *Registry) newCarrierReference() string {
	return r.newCarrierReferenceForKind("")
}

func (r *Registry) newCarrierReferenceForKind(kind CarrierKind) string {
	if r == nil || r.continuationsClosed.Load() {
		return ""
	}
	for {
		current := r.nextCarrier.Load()
		if current == math.MaxUint64 {
			if kind == "" {
				r.recordAdmissionCapacityLoss()
			} else {
				r.recordCarrierAdmissionLossKind(kind)
			}
			return ""
		}
		if r.nextCarrier.CompareAndSwap(current, current+1) {
			return r.runtimeInstanceID + "-carrier-" + encodeUint64(current+1)
		}
	}
}

// NewMuxClientCarrierObservation creates the one early, registry-affine
// client-worker capability. It remains correlation-only in this stage.
func (r *Registry) NewMuxClientCarrierObservation() session.MuxClientCarrierObservation {
	reference := r.newCarrierReferenceForKind(CarrierKindClientMuxFrameLink)
	if reference == "" {
		return nil
	}
	return &MuxClientCarrier{registry: r, reference: reference, frame: r.admitClientMuxCarrier(reference)}
}

func (c *MuxClientCarrier) ClientFrameObservation() session.MuxClientCarrierFrameObservation {
	if c == nil {
		return nil
	}
	return c.frame
}

// ContextWithMuxClientSessionObservation exposes a scope only to the handler
// already recorded as this root's selected top-level outbound. A nested or
// unrelated handler receives a masked context instead of inherited authority.
func ContextWithMuxClientSessionObservation(ctx context.Context, selectedOutboundTag string) context.Context {
	handle := HandleFromContext(ctx)
	if !handle.hasSelectedTopLevelOutbound(selectedOutboundTag) {
		return session.ContextWithoutMuxClientSessionObservation(ctx)
	}
	return session.ContextWithMuxClientSessionObservation(ctx, &MuxClientSessionScope{
		handle:              handle,
		selectedOutboundTag: selectedOutboundTag,
	})
}

func (h *Handle) hasSelectedTopLevelOutbound(tag string) bool {
	if h == nil || h.registry == nil || h.registry.continuationsClosed.Load() || h.root == nil || h.root.logical == nil || h.root.retired.Load() || tag == "" || len(tag) > maxTagBytes {
		return false
	}
	selection := h.root.selection.Load()
	return selection != nil && selection.outboundTag == tag
}

// NewCarrier is called only after a stock ClientWorker accepted a logical
// session. The returned capability is registry-affine and worker-scoped.
func (s *MuxClientSessionScope) NewCarrier() session.MuxClientCarrierObservation {
	if s == nil || !s.handle.hasSelectedTopLevelOutbound(s.selectedOutboundTag) {
		return nil
	}
	reference := s.handle.registry.newCarrierReferenceForKind(CarrierKindClientMuxFrameLink)
	if reference == "" {
		return nil
	}
	return &MuxClientCarrier{registry: s.handle.registry, reference: reference}
}

// AttachTo publishes only the observed selected-outbound carrier correlation.
// Foreign, stale, replayed or conflicting capabilities fail observation closed.
func (c *MuxClientCarrier) AttachTo(observation session.MuxClientSessionObservation) {
	scope, ok := observation.(*MuxClientSessionScope)
	if !ok || scope == nil || c == nil || c.registry == nil || c.reference == "" {
		return
	}
	if !c.registry.beginAdmission() {
		return
	}
	defer c.registry.endAdmission()
	handle := scope.handle
	if !handle.hasSelectedTopLevelOutbound(scope.selectedOutboundTag) || handle.registry != c.registry {
		return
	}
	receipt := &carrierReferenceReceipt{reference: c.reference}
	if handle.root.selectedOutboundCarrier.CompareAndSwap(nil, receipt) {
		handle.root.logical.markDirty()
	}
}

// Close prevents observation admission for frames decoded after the owning
// worker has stopped. Existing child scopes retain their exact correlation.
func (c *MuxCarrier) Close() {
	if c != nil {
		c.closed.Store(true)
		if c.frame != nil {
			c.frame.ownerClosed()
		}
	}
}

func (c *MuxCarrier) FrameObservation() session.MuxCarrierFrameObservation {
	if c == nil {
		return nil
	}
	return c.frame
}

// NewTCPSession creates the one-shot capability only for an ordinary
// server-side zero-GlobalID MUX TCP child.
func (c *MuxCarrier) NewTCPSession(globalID [8]byte, destination net.Destination, source string) session.MuxSessionObservation {
	return c.newSession(globalID, destination, source, net.Network_TCP)
}

// NewUDPSession creates the one-shot capability only for an ordinary
// server-side zero-GlobalID MUX UDP child. Nonzero-GlobalID XUDP stays out of
// this fixed-session scope.
func (c *MuxCarrier) NewUDPSession(globalID [8]byte, destination net.Destination, source string) session.MuxSessionObservation {
	return c.newSession(globalID, destination, source, net.Network_UDP)
}

func (c *MuxCarrier) NewXUDPSession(destination net.Destination, source string) session.XUDPEpochObservation {
	if c == nil || c.registry == nil || c.reference == "" || c.closed.Load() {
		return nil
	}
	return c.registry.newXUDPObservation(destination, source, c.reference)
}
func (c *MuxCarrier) XUDPCarrierObservationMarker() {}
func (c *MuxCarrier) XUDPCarrierObservation() session.XUDPCarrierObservation {
	if c == nil || c.closed.Load() {
		return nil
	}
	return c
}

func (c *MuxCarrier) newSession(globalID [8]byte, destination net.Destination, source string, network net.Network) session.MuxSessionObservation {
	if c == nil || c.registry == nil || c.reference == "" || c.closed.Load() ||
		globalID != ([8]byte{}) || destination.Network != network {
		return nil
	}
	return &MuxSessionScope{carrier: c, requestedDestination: destination.String(), source: source}
}

// MuxSessionScope authorizes exactly one registry admission and owns the MUX
// root until Session.Close has completed its stock actions.
type MuxSessionScope struct {
	mu                   sync.Mutex
	carrier              *MuxCarrier
	requestedDestination string
	source               string
	handle               atomic.Pointer[Handle]
	bound                bool
	closeCompleted       bool
	finalized            bool
}

func ContextWithMuxSessionScope(ctx context.Context, scope *MuxSessionScope) context.Context {
	if ctx == nil || scope == nil {
		return ctx
	}
	return context.WithValue(ctx, muxSessionContextKey{}, scope)
}

func (s *MuxSessionScope) Context(ctx context.Context) context.Context {
	return ContextWithMuxSessionScope(ctx, s)
}

func MuxSessionScopeFromContext(ctx context.Context) *MuxSessionScope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(muxSessionContextKey{}).(*MuxSessionScope)
	return scope
}

func (s *MuxSessionScope) Handle() *Handle {
	if s == nil {
		return nil
	}
	return s.handle.Load()
}

// AcquireParticipant is called before publishing work owned by the decoded
// session. Nil preserves stock work when observation is unavailable.
func (s *MuxSessionScope) AcquireParticipant() task.ParticipantLease {
	handle := s.Handle()
	if handle == nil || handle.root == nil || handle.root.logical == nil || handle.root.retired.Load() {
		return nil
	}
	return handle.root.logical.AcquireParticipant()
}

// AfterClose publishes only that the stock Session.Close actions completed.
// Any exact cause must already have been reported by an owning call path.
func (s *MuxSessionScope) AfterClose() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeCompleted {
		return
	}
	s.closeCompleted = true
	s.finalizeLocked()
}

func (s *MuxSessionScope) finalizeLocked() {
	if s.finalized || !s.closeCompleted {
		return
	}
	handle := s.handle.Load()
	if handle == nil || handle.root == nil || handle.root.logical == nil || handle.root.retired.Load() {
		return
	}
	s.finalized = true
	handle.root.logical.sealOwnerWithoutOutcome()
}

// AdmitMuxTCP binds the one-shot scope to this exact registry. Invalid or
// replayed capabilities lose observation coverage but never suppress dispatch.
func (r *Registry) AdmitMuxTCP(scope *MuxSessionScope, destination net.Destination) *Handle {
	return r.admitMuxSession(scope, destination, net.Network_TCP)
}

// AdmitMuxUDP binds a zero-GlobalID decoded MUX UDP child to the existing
// logical MUX registry. Invalid or replayed capabilities lose observation
// coverage but never suppress stock dispatch.
func (r *Registry) AdmitMuxUDP(scope *MuxSessionScope, destination net.Destination) *Handle {
	return r.admitMuxSession(scope, destination, net.Network_UDP)
}

func (r *Registry) admitMuxSession(scope *MuxSessionScope, destination net.Destination, network net.Network) *Handle {
	if r == nil || scope == nil || destination.Network != network || !r.beginAdmission() {
		return nil
	}
	defer r.endAdmission()
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.bound || scope.closeCompleted || scope.carrier == nil || scope.carrier.registry != r ||
		scope.carrier.closed.Load() || scope.requestedDestination != destination.String() {
		if scope.carrier != nil && scope.carrier.registry != nil {
			scope.carrier.registry.recordAdmissionContention()
		}
		return nil
	}
	admission := r.prepareMuxSessionAdmission(scope.source, scope.requestedDestination, scope.carrier.reference)
	if admission == nil {
		return nil
	}
	handle := r.publishAdmission(admission)
	if handle == nil {
		return nil
	}
	scope.bound = true
	scope.handle.Store(handle)
	scope.finalizeLocked()
	return handle
}
