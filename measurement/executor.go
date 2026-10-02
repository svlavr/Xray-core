// Package measurement executes caller-requested bounded raw operations.
// Executors own no background loop and do not register an Xray feature.
package measurement

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

var ErrUnsupported = errors.New("unsupported measurement execution shape")

// Executor enforces the caller's concurrent-operation limit. The caller must
// cancel its operations before closing the instance. Slots count live method
// invocations; native Xray/Go own their ordinary connection lifecycle.
type Executor struct {
	instance *core.Instance
	slots    chan struct{}
}

// New creates an idle executor with a positive, caller-selected concurrency limit.
// The limit is fixed for this executor's lifetime; scheduling policy stays outside.
func New(instance *core.Instance, maxConcurrent int) (*Executor, error) {
	if instance == nil {
		return nil, errors.New("nil Xray instance")
	}
	if maxConcurrent <= 0 {
		return nil, errors.New("measurement concurrency limit must be positive")
	}
	return &Executor{instance: instance, slots: make(chan struct{}, maxConcurrent)}, nil
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

// handshakeTLS records the observed phase even on failure. Keeping it in the
// operation also preserves this fact when subsequent I/O has not returned.
func (o *operation) handshakeTLS(ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error) {
	tlsConn := tls.Client(conn, config)
	started := time.Now()
	err := tlsConn.HandshakeContext(ctx)
	elapsed := time.Since(started)
	o.mu.Lock()
	o.tlsTime = &elapsed
	o.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return tlsConn, nil
}

var _ session.TrackedRequestErrorFeedback = (*operation)(nil)

// measurementContext replaces mutable caller session objects, preserving cancellation.
func measurementContext(ctx context.Context, o *operation) context.Context {
	// Never mutate caller-owned session pointers or inherit USER admission.
	ctx = session.ContextWithInbound(ctx, &session.Inbound{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, &session.Content{SkipDNSResolve: true})
	ctx = session.ContextWithTimeoutOnly(ctx, false)
	ctx = session.ContextWithTrafficOrigin(ctx, session.OriginMeasurement)
	ctx = session.TrackedConnectionError(ctx, o)
	return ctx
}
