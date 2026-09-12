package session

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
)

// MuxCarrierObservation is the optional observation-only capability owned by
// one server-side MUX worker. It never controls carrier traffic or lifecycle.
type MuxCarrierObservation interface {
	NewTCPSession(globalID [8]byte, destination net.Destination, source string) MuxSessionObservation
	Close()
}

// MuxCarrierFrameObservation is the optional server-owner seam for exact
// encoded frame-link I/O. It never changes link results or controls traffic.
type MuxCarrierFrameObservation interface {
	Read(uint64)
	Write(uint64, error)
	Reserve()
	Release()
	ReaderExited()
	MonitorCompleted()
	UplinkSealed()
	DownlinkSealed()
}
type MuxCarrierFrameObservationProvider interface {
	FrameObservation() MuxCarrierFrameObservation
}

func MuxCarrierFrameObservationFromCarrier(c MuxCarrierObservation) MuxCarrierFrameObservation {
	p, _ := c.(MuxCarrierFrameObservationProvider)
	if p == nil {
		return nil
	}
	return p.FrameObservation()
}

// XUDPCarrierObservation is an opaque registry-affine capability. It exposes
// no caller-supplied reference; the receiving registry validates ownership.
type (
	XUDPCarrierObservation interface{ XUDPCarrierObservationMarker() }
	MuxXUDPCarrierProvider interface{ XUDPCarrierObservation() XUDPCarrierObservation }
)

func MuxXUDPCarrierObservation(carrier MuxCarrierObservation) XUDPCarrierObservation {
	provider, _ := carrier.(MuxXUDPCarrierProvider)
	if provider == nil {
		return nil
	}
	return provider.XUDPCarrierObservation()
}

// MuxUDPSessionObservationProvider is an additive optional capability for a
// decoded zero-GlobalID MUX UDP child. TCP-only providers retain their stock
// UDP behavior and simply produce no UDP observation.
type MuxUDPSessionObservationProvider interface {
	NewUDPSession(globalID [8]byte, destination net.Destination, source string) MuxSessionObservation
}

// MuxXUDPSessionObservationProvider preserves the worker-scoped carrier
// reference for a nonzero-ID retained-link epoch.
type MuxXUDPSessionObservationProvider interface {
	NewXUDPSession(destination net.Destination, source string) XUDPEpochObservation
}

func MuxXUDPObservationFromCarrier(carrier MuxCarrierObservation, destination net.Destination, source string) XUDPEpochObservation {
	provider, _ := carrier.(MuxXUDPSessionObservationProvider)
	if provider == nil {
		return nil
	}
	return provider.NewXUDPSession(destination, source)
}

func MuxUDPSessionObservationFromCarrier(carrier MuxCarrierObservation, globalID [8]byte, destination net.Destination, source string) MuxSessionObservation {
	provider, _ := carrier.(MuxUDPSessionObservationProvider)
	if provider == nil {
		return nil
	}
	return provider.NewUDPSession(globalID, destination, source)
}

// MuxSessionObservation follows one decoded TCP or UDP session through
// dispatcher admission, asynchronous work, and completion of stock
// Session.Close.
type MuxSessionObservation interface {
	Context(context.Context) context.Context
	AcquireParticipant() task.ParticipantLease
	AfterClose()
}

// XUDPObservation is an optional, retained-link-local observation capability.
// It is deliberately opaque to mux: GlobalID, SessionID and pointers never
// cross this boundary as flow identity.
type XUDPEpochObservation interface {
	Context(context.Context) context.Context
	PrepareBinding(XUDPCarrierObservation) XUDPBindingObservation
	WriteReplaced()
	InitialWriteUnproven()
	Retire()
	Terminalize()
}

type XUDPBindingObservation interface {
	Install() bool
	Abort()
	ReaderExited()
	Deactivate(XUDPDetachTransition)
	RevokeUnproven()
}

type XUDPDetachTransition string

const (
	XUDPDetachToExpiring XUDPDetachTransition = "TO_EXPIRING"
	XUDPDetachForRebind  XUDPDetachTransition = "FOR_REBIND"
	XUDPDetachRootClose  XUDPDetachTransition = "ROOT_CLOSE"
)

// MuxXUDPObservationProvider is additive. A dispatcher which does not expose
// it preserves stock XUDP execution without producing observation state.
type MuxXUDPObservationProvider interface {
	NewXUDPObservation(destination net.Destination, source string) XUDPEpochObservation
}

func MuxXUDPObservationFromDispatcher(dispatcher any, destination net.Destination, source string) XUDPEpochObservation {
	provider, _ := dispatcher.(MuxXUDPObservationProvider)
	if provider == nil {
		return nil
	}
	return provider.NewXUDPObservation(destination, source)
}

// MuxClientCarrierObservation is one worker-scoped client MUX capability.
// Its optional frame facet is provisional until Commit; it never controls traffic.
type MuxClientCarrierObservation interface {
	AttachTo(MuxClientSessionObservation)
}

// MuxClientCarrierFrameObservation observes the encoded client frame link.
// Commit and Abort are construction-only, mutually exclusive operations.
type MuxClientCarrierFrameObservation interface {
	Read(uint64)
	Write(uint64, error)
	Commit()
	Abort()
	WorkerQuiesced()
}

type MuxClientCarrierFrameObservationProvider interface {
	ClientFrameObservation() MuxClientCarrierFrameObservation
}

func MuxClientCarrierFrameObservationFromCarrier(c MuxClientCarrierObservation) MuxClientCarrierFrameObservation {
	p, _ := c.(MuxClientCarrierFrameObservationProvider)
	if p == nil {
		return nil
	}
	return p.ClientFrameObservation()
}

// MuxClientCarrierAuthorityProvider mints the single worker-scoped client MUX
// correlation capability before worker goroutines are published.
type MuxClientCarrierAuthorityProvider interface {
	NewMuxClientCarrierObservation() MuxClientCarrierObservation
}

// MuxClientCarrierAuthorityBinder is deliberately optional so the public
// outbound.Manager feature remains unchanged.
type MuxClientCarrierAuthorityBinder interface {
	BindMuxClientCarrierAuthority(MuxClientCarrierAuthorityProvider) bool
}

// MuxClientSessionObservation identifies one already-admitted logical flow at
// the exact selected-outbound MUX boundary. It never creates another flow.
type MuxClientSessionObservation interface {
	NewCarrier() MuxClientCarrierObservation
}

type muxClientSessionObservationKey struct{}

func ContextWithMuxClientSessionObservation(ctx context.Context, observation MuxClientSessionObservation) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, muxClientSessionObservationKey{}, observation)
}

func ContextWithoutMuxClientSessionObservation(ctx context.Context) context.Context {
	return ContextWithMuxClientSessionObservation(ctx, nil)
}

func MuxClientSessionObservationFromContext(ctx context.Context) MuxClientSessionObservation {
	if ctx == nil {
		return nil
	}
	observation, _ := ctx.Value(muxClientSessionObservationKey{}).(MuxClientSessionObservation)
	return observation
}

// MuxCarrierObservationProvider is an additive optional seam; a dispatcher
// without it retains exact stock MUX behavior and produces no MUX flow record.
type MuxCarrierObservationProvider interface {
	NewMuxCarrierObservation() MuxCarrierObservation
}

func MuxCarrierObservationFromDispatcher(dispatcher any) MuxCarrierObservation {
	provider, _ := dispatcher.(MuxCarrierObservationProvider)
	if provider == nil {
		return nil
	}
	return provider.NewMuxCarrierObservation()
}
