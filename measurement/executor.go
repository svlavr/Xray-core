// Package measurement executes caller-requested bounded raw operations.
// Executors own no background loop and do not register an Xray feature.
package measurement

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

var ErrUnsupported = errors.New("unsupported measurement execution shape")

// Executor enforces the caller's concurrent-operation limit. The caller must
// cancel its operations before closing a supplied instance. Slots count live method
// invocations; native Xray/Go own their ordinary connection lifecycle.
type Executor struct {
	instance *core.Instance
	slots    chan struct{}
}

// New creates an idle executor with a positive, caller-selected concurrency limit.
// The limit is fixed for this executor's lifetime; scheduling policy stays outside.
// A nil instance permits DIRECT operations; exact outbound operations return
// ErrUnsupported before dispatch when no instance is supplied.
func New(instance *core.Instance, maxConcurrent int) (*Executor, error) {
	if maxConcurrent <= 0 {
		return nil, errors.New("measurement concurrency limit must be positive")
	}
	return &Executor{instance: instance, slots: make(chan struct{}, maxConcurrent)}, nil
}

// acquire admits one live invocation and rechecks cancellation before native
// work. A free slot and a canceled context can both satisfy the select.
func (e *Executor) acquire(ctx context.Context) error {
	select {
	case e.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-e.slots
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type operation struct {
	mu          sync.Mutex
	nativeError error
	tlsTime     *time.Duration
}

func (o *operation) SubmitError(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.nativeError == nil {
		o.nativeError = err
	}
}

var _ session.TrackedRequestErrorFeedback = (*operation)(nil)

// measurementContext replaces mutable caller session objects, preserving cancellation.
func measurementContext(ctx context.Context, o *operation) context.Context {
	// Never mutate caller-owned session pointers or inherit USER admission.
	ctx = session.ContextWithInbound(ctx, &session.Inbound{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, &session.Content{SkipDNSResolve: true})
	ctx = session.ContextWithTimeoutOnly(ctx, false)
	// A measurement cannot continue the caller's logical USER exchange.
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginControlledMeasurement)
	ctx = session.TrackedConnectionError(ctx, o)
	return ctx
}
