package dns

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// dohRouteReceipt is carried by one pooled HTTP/2 connection. A loopback or
// other continuation may replace the offered route until the actual endpoint
// owner commits it; after Commit, Snapshot is immutable.
type dohRouteReceipt struct {
	mu        sync.Mutex
	step      stats.RouteStep
	offered   bool
	committed bool
	offeredCh chan struct{}
	offerOnce sync.Once
}

func newDoHRouteReceipt() *dohRouteReceipt {
	return &dohRouteReceipt{offeredCh: make(chan struct{})}
}

func (r *dohRouteReceipt) Offer(step stats.RouteStep) {
	r.mu.Lock()
	if !r.committed {
		r.step = step
		r.offered = true
	}
	r.mu.Unlock()
	r.offerOnce.Do(func() { close(r.offeredCh) })
}

func (r *dohRouteReceipt) WaitOffer(ctx context.Context) (stats.RouteStep, error) {
	select {
	case <-r.offeredCh:
		r.mu.Lock()
		step := r.step
		r.mu.Unlock()
		return step, nil
	case <-ctx.Done():
		return stats.RouteStep{}, ctx.Err()
	}
}

type dohRouteError struct{ step stats.RouteStep }

func (e *dohRouteError) Error() string { return "routed DoH carrier selection rejected" }

func classifyDoHTLSHandshakeError(ctx context.Context, conn stdnet.Conn, routeReceipt *dohRouteReceipt, handshakeErr error) error {
	_ = conn.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if routeReceipt != nil {
		if step, rejected := routeReceipt.Snapshot(); rejected && step.Selection == stats.SelectionRejected {
			return &dohRouteError{step: step}
		}
	}
	return handshakeErr
}

func (r *dohRouteReceipt) Commit() {
	r.mu.Lock()
	if r.offered {
		r.committed = true
	}
	r.mu.Unlock()
}

func (r *dohRouteReceipt) Snapshot() (stats.RouteStep, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.step, r.committed
}

type dohCarrierConn struct {
	stdnet.Conn
	route *dohRouteReceipt
}

type dohAttempt struct {
	leg      stats.Exchange
	route    *dohRouteReceipt
	bodySize uint64
	bodyRead atomic.Uint64
	finished atomic.Bool
	routeSet bool
}

func (a *dohAttempt) bindRoute(step stats.RouteStep) {
	a.leg.Route(step)
	a.leg.BindRoute()
	if step.Selection == stats.SelectionRejected {
		a.leg.SetEndReason(stats.EndReasonRejected)
	}
	a.routeSet = true
}

func (a *dohAttempt) recordBodyRead(n int) {
	if a != nil && n > 0 {
		a.bodyRead.Add(uint64(n))
		a.leg.AddUplink(uint64(n))
	}
}

func (a *dohAttempt) finish(responseComplete bool) {
	if a == nil || !a.finished.CompareAndSwap(false, true) {
		return
	}
	if a.bodyRead.Load() != a.bodySize {
		a.leg.MarkUplinkIncomplete()
	}
	if !responseComplete {
		a.leg.MarkDownlinkIncomplete()
	}
	if !a.routeSet {
		if step, ok := a.route.Snapshot(); ok {
			a.bindRoute(step)
		}
	}
	if !a.routeSet {
		a.leg.Unassign()
		a.leg.MarkUplinkIncomplete()
		a.leg.MarkDownlinkIncomplete()
	}
	a.leg.Finish()
}

// dohRequestObservation owns one packed DNS request. Its stop callback only
// cancels the HTTP request context, which resets that HTTP/2 stream without
// closing the pooled carrier used by siblings.
type dohRequestObservation struct {
	root       stats.Exchange
	cancel     context.CancelFunc
	bodySize   uint64
	current    atomic.Pointer[dohAttempt]
	finishOnce sync.Once
	stopped    atomic.Bool
}

func (o *dohRequestObservation) Close() error {
	if o != nil && o.stopped.CompareAndSwap(false, true) {
		if o.cancel != nil {
			o.cancel()
		}
		if o.root != nil {
			o.root.Finish()
		}
	}
	return nil
}

func (o *dohRequestObservation) gotConn(info httptrace.GotConnInfo) {
	if o == nil || o.root == nil || o.stopped.Load() {
		return
	}
	leg := o.root.NewLeg()
	if leg == nil {
		return
	}
	carrier, _ := info.Conn.(*dohCarrierConn)
	attempt := &dohAttempt{leg: leg, bodySize: o.bodySize}
	if carrier != nil {
		attempt.route = carrier.route
	} else {
		attempt.route = newDoHRouteReceipt()
	}
	if step, ok := attempt.route.Snapshot(); ok {
		attempt.bindRoute(step)
	}
	if previous := o.current.Swap(attempt); previous != nil {
		previous.finish(false)
	}
}

func (o *dohRequestObservation) recordBodyRead(n int) {
	if o != nil {
		o.current.Load().recordBodyRead(n)
	}
}

func (o *dohRequestObservation) recordResponseRead(n int, err error) {
	if o == nil {
		return
	}
	attempt := o.current.Load()
	if attempt == nil {
		return
	}
	if n > 0 {
		attempt.leg.AddDownlink(uint64(n))
	}
	if err != nil {
		attempt.leg.MarkDownlinkIncomplete()
		attempt.leg.SetEndReason(stats.EndReasonReadError)
	}
}

func (o *dohRequestObservation) markDecodeError() {
	if o == nil {
		return
	}
	if attempt := o.current.Load(); attempt != nil {
		attempt.leg.MarkDownlinkIncomplete()
		attempt.leg.SetEndReason(stats.EndReasonReadError)
	}
}

func (o *dohRequestObservation) reject(step stats.RouteStep) {
	if o == nil || o.root == nil || o.stopped.Load() {
		return
	}
	leg := o.root.NewLeg()
	if leg == nil {
		return
	}
	if previous := o.current.Swap(nil); previous != nil {
		previous.finish(false)
	}
	leg.Route(step)
	leg.BindRoute()
	leg.MarkUplinkIncomplete()
	leg.MarkDownlinkIncomplete()
	leg.SetEndReason(stats.EndReasonRejected)
	leg.Finish()
}

func (o *dohRequestObservation) finish(responseComplete bool) {
	if o == nil {
		return
	}
	o.finishOnce.Do(func() {
		if attempt := o.current.Load(); attempt != nil {
			attempt.finish(responseComplete)
		}
		o.root.Finish()
		o.cancel()
	})
}

func parseObservedDoHResponse(payload []byte, observation *dohRequestObservation) (*IPRecord, error) {
	record, err := parseResponse(payload)
	if observation != nil {
		if err != nil {
			observation.markDecodeError()
		}
		observation.finish(true)
	}
	return record, err
}

type dohRequestBody struct {
	*bytes.Reader
	observation *dohRequestObservation
}

func (b *dohRequestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.observation.recordBodyRead(n)
	return n, err
}

func (*dohRequestBody) Close() error { return nil }

func beginRoutedDoHObservation(ctx context.Context, store stats.AdmissionStore, destination xnet.Destination, bodySize int) (context.Context, *dohRequestObservation) {
	if store == nil {
		return ctx, nil
	}
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	requestCtx, cancel := context.WithCancel(ctx)
	owner := &dohRequestObservation{cancel: cancel, bodySize: uint64(bodySize)}
	owner.root = store.Begin(stats.FlowKindTCP, stats.TrafficOriginInternal, xnet.Destination{}, destination, owner.Close)
	if owner.root == nil {
		cancel()
		return ctx, nil
	}
	if owner.root.Ref() == (stats.FlowRef{}) {
		owner.root.ExcludeCarrier()
		owner.Close()
		return ctx, nil
	}
	if owner.stopped.Load() {
		owner.root.Finish()
		return requestCtx, nil
	}
	return requestCtx, owner
}

func dohObservationStore(ctx context.Context) stats.AdmissionStore {
	instance := core.FromContext(ctx)
	if instance == nil {
		return nil
	}
	provider, ok := instance.GetFeature(stats.ManagerType()).(stats.ObservationProvider)
	if !ok {
		return nil
	}
	return provider.Observation()
}

func dohObservationAvailable(ctx context.Context) bool {
	instance := core.FromContext(ctx)
	if instance == nil {
		return false
	}
	provider, ok := instance.GetFeature(stats.ManagerType()).(stats.ObservationProvider)
	return ok && provider.Observation() != nil
}

func dohRejectedRoute(err error) (stats.RouteStep, bool) {
	var rejected *dohRouteError
	if !stderrors.As(err, &rejected) {
		return stats.RouteStep{}, false
	}
	return rejected.step, true
}

func dohDestination(hostname, port string) xnet.Destination {
	if port == "" {
		port = "443"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return xnet.Destination{}
	}
	return xnet.TCPDestination(xnet.ParseAddress(hostname), xnet.Port(n))
}

func newObservedDoHRequest(ctx context.Context, method, endpoint string, payload []byte, observation *dohRequestObservation) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	newBody := func() io.ReadCloser {
		return &dohRequestBody{Reader: bytes.NewReader(payload), observation: observation}
	}
	request.Body = newBody()
	request.ContentLength = int64(len(payload))
	request.GetBody = func() (io.ReadCloser, error) { return newBody(), nil }
	trace := &httptrace.ClientTrace{GotConn: observation.gotConn}
	return request.WithContext(httptrace.WithClientTrace(request.Context(), trace)), nil
}
