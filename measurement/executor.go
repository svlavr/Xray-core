package measurement

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

var ErrUnsupported = errors.New("unsupported measurement execution shape")

type Executor struct {
	instance *core.Instance
	slots    chan struct{}
}

func New(instance *core.Instance, maxConcurrent int) (*Executor, error) {
	if maxConcurrent <= 0 {
		return nil, errors.New("measurement concurrency limit must be positive")
	}
	return &Executor{instance: instance, slots: make(chan struct{}, maxConcurrent)}, nil
}

// operation owns one admission and its cancellation/native feedback boundaries.
// Method-specific facts are finalized before end cancels cleanup and frees the slot.
type operation struct {
	context.Context
	cancel        context.CancelCauseFunc
	timeoutCancel context.CancelFunc
	owner         *Executor
	started       time.Time
	mu            sync.Mutex
	nativeError   error
	tlsTime       *time.Duration
	firstByte     *time.Duration
	tlsStarted    time.Time
}

func (e *Executor) begin(ctx context.Context, timeout time.Duration) (*operation, error) {
	if ctx == nil {
		return nil, errors.New("nil request context")
	}
	ctx, timeoutCancel := context.WithTimeout(ctx, timeout)
	select {
	case e.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-e.slots
			timeoutCancel()
			return nil, err
		}
	case <-ctx.Done():
		timeoutCancel()
		return nil, ctx.Err()
	}
	started := time.Now()
	ctx, cancel := context.WithCancelCause(ctx)
	o := &operation{Context: ctx, cancel: cancel, timeoutCancel: timeoutCancel, started: started, owner: e}
	o.Context = measurementContext(ctx, o)
	return o, nil
}

func (o *operation) end() {
	o.cancel(nil)
	o.timeoutCancel()
	<-o.owner.slots
}

func (o *operation) SubmitError(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.nativeError == nil {
		o.nativeError = err
	}
}

func (o *operation) outboundError() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.nativeError
}

// Pipe deadlines are no-ops; close the actual connection on cancellation.
func closeOnCancel(ctx context.Context, conn net.Conn) func() {
	closeConn := sync.OnceFunc(func() { _ = conn.Close() })
	stop := context.AfterFunc(ctx, closeConn)
	return func() {
		stop()
		closeConn()
	}
}

func measurementContext(ctx context.Context, o *operation) context.Context {
	ctx = session.ContextWithInbound(ctx, &session.Inbound{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, &session.Content{SkipDNSResolve: true})
	ctx = session.ContextWithTimeoutOnly(ctx, false)
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginControlledMeasurement)
	return session.TrackedConnectionError(ctx, o)
}
