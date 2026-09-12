package internet

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/xtls/xray-core/common/task"
)

// InboundLifecycle is the narrow, optional receipt carrier for direct inbound
// listeners. It deliberately does not alter the Listener or ListenFunc API.
type InboundLifecycle struct{ Tasks *task.Lifecycle }

func (l *InboundLifecycle) Acquire() bool {
	return l == nil || l.Tasks == nil || l.Tasks.Acquire()
}

func (l *InboundLifecycle) Release() {
	if l != nil && l.Tasks != nil {
		l.Tasks.Release()
	}
}

type inboundLifecycleKey struct{}

func ContextWithInboundLifecycle(ctx context.Context, lifecycle *InboundLifecycle) context.Context {
	return context.WithValue(ctx, inboundLifecycleKey{}, lifecycle)
}

func InboundLifecycleFromContext(ctx context.Context) *InboundLifecycle {
	lifecycle, _ := ctx.Value(inboundLifecycleKey{}).(*InboundLifecycle)
	return lifecycle
}

// InboundHandoff serializes the first owner callback against listener stop.
// Admission and long-lived completion remain owned by InboundLifecycle.
type InboundHandoff struct{ state atomic.Uint32 }

const (
	inboundHandoffAccepted = 1
	inboundHandoffRejected = 2
)

func (h *InboundHandoff) Accept() bool {
	if h == nil {
		return true
	}
	if h.state.CompareAndSwap(0, inboundHandoffAccepted) {
		return true
	}
	return h.state.Load() == inboundHandoffAccepted
}

func (h *InboundHandoff) Reject() {
	if h != nil {
		h.state.CompareAndSwap(0, inboundHandoffRejected)
	}
}

type inboundHandoffCarrier interface {
	AcceptInboundHandoff() bool
	RejectInboundHandoff()
}

func AcceptInboundHandoff(conn net.Conn) bool {
	if handoff, ok := conn.(inboundHandoffCarrier); ok {
		return handoff.AcceptInboundHandoff()
	}
	return true
}

func RejectInboundHandoff(conn net.Conn) {
	if handoff, ok := conn.(inboundHandoffCarrier); ok {
		handoff.RejectInboundHandoff()
	}
}
