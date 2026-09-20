// Package measurement executes bounded raw operations through one Xray instance.
package measurement

import (
	"context"
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

const (
	maxURLBytes          = 2048
	maxOutboundTagBytes  = 256
	maxResponseBodyBytes = 1 << 20
	maxResponseHeader    = 64 << 10
	maxOperationTimeout  = 30 * time.Second
)

// Outcome is the terminal technical outcome of one raw operation.
type Outcome string

const (
	OutcomeSucceeded        Outcome = "SUCCEEDED"
	OutcomeFailed           Outcome = "FAILED"
	OutcomeCancelled        Outcome = "CANCELLED"
	OutcomeDeadlineExceeded Outcome = "DEADLINE_EXCEEDED"
)

// FailureStage identifies the technical boundary that failed. It is not a node
// health or product-policy conclusion.
type FailureStage string

const (
	FailureNone            FailureStage = ""
	FailureExactSelect     FailureStage = "EXACT_SELECT"
	FailureEndpointTLS     FailureStage = "ENDPOINT_TLS"
	FailureResponseHeaders FailureStage = "RESPONSE_HEADERS"
	FailureResponseBody    FailureStage = "RESPONSE_BODY"
	FailureCleanup         FailureStage = "CLEANUP"
	FailureUnsupported     FailureStage = "UNSUPPORTED"
)

// CleanupOutcome reports only operation-owned logical-connection cleanup. It
// does not claim that a remote peer or every downstream worker has retired.
type CleanupOutcome string

const (
	CleanupNotOpened        CleanupOutcome = "NOT_OPENED"
	CleanupConnectionClosed CleanupOutcome = "CONNECTION_CLOSED"
	CleanupFailed           CleanupOutcome = "FAILED"
)

// HTTPSRequest is the first minimal raw measurement request. This slice is
// GET-only, HTTPS-only and exact-outbound-only by design.
type HTTPSRequest struct {
	URL                  string
	OutboundTag          string
	Timeout              time.Duration
	MaxResponseBodyBytes int64
}

// HTTPTiming contains only boundaries observed by the endpoint HTTP client.
type HTTPTiming struct {
	Total                time.Duration
	TLSHandshake         time.Duration
	TLSHandshakeObserved bool
	TimeToFirstByte      time.Duration
	TTFBObserved         bool
}

// HTTPSResponse contains bounded raw response facts. Non-2xx status is still a
// successful raw transaction and is not interpreted as health.
type HTTPSResponse struct {
	StatusCode                int
	Protocol                  string
	Body                      []byte
	BodyTruncated             bool
	ResponseBodyBytesObserved int64
	DeclaredContentLength     int64
}

// HTTPSReceipt is one terminal raw receipt. Failure details are deliberately
// typed and do not expose an unredacted internal error string.
type HTTPSReceipt struct {
	Outcome          Outcome
	FailureStage     FailureStage
	SelectedOutbound string
	StartedAt        time.Time
	FinishedAt       time.Time
	Timing           HTTPTiming
	Response         *HTTPSResponse
	Cleanup          CleanupOutcome
}

type exactRouteError struct {
	stage   FailureStage
	cleanup CleanupOutcome
}

func (e *exactRouteError) Error() string { return string(e.stage) }

type httpsOperation struct {
	access   sync.Mutex
	dialed   bool
	conn     net.Conn
	selected string
}

func (o *httpsOperation) beginDial() bool {
	o.access.Lock()
	defer o.access.Unlock()
	if o.dialed {
		return false
	}
	o.dialed = true
	return true
}

func (o *httpsOperation) attach(conn net.Conn, selected string) {
	o.access.Lock()
	o.conn = conn
	o.selected = selected
	o.access.Unlock()
}

func (o *httpsOperation) selectedTag() string {
	o.access.Lock()
	defer o.access.Unlock()
	return o.selected
}

func (o *httpsOperation) close() CleanupOutcome {
	o.access.Lock()
	conn := o.conn
	o.conn = nil
	o.access.Unlock()
	if conn == nil {
		return CleanupNotOpened
	}
	if err := conn.Close(); err != nil && !stderrors.Is(err, net.ErrClosed) && !stderrors.Is(err, io.ErrClosedPipe) {
		return CleanupFailed
	}
	return CleanupConnectionClosed
}

type traceState struct {
	access      sync.Mutex
	started     time.Time
	tlsStarted  time.Time
	tlsDuration time.Duration
	tlsObserved bool
	tlsErr      error
	ttfb        time.Duration
	ttfbSeen    bool
}

func (t *traceState) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			t.access.Lock()
			t.tlsStarted = time.Now()
			t.access.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			t.access.Lock()
			t.tlsObserved = true
			t.tlsErr = err
			if !t.tlsStarted.IsZero() {
				t.tlsDuration = time.Since(t.tlsStarted)
			}
			t.access.Unlock()
		},
		GotFirstResponseByte: func() {
			t.access.Lock()
			t.ttfbSeen = true
			t.ttfb = time.Since(t.started)
			t.access.Unlock()
		},
	}
}

func (t *traceState) snapshot(total time.Duration) (HTTPTiming, error) {
	t.access.Lock()
	defer t.access.Unlock()
	return HTTPTiming{
		Total:                total,
		TLSHandshake:         t.tlsDuration,
		TLSHandshakeObserved: t.tlsObserved,
		TimeToFirstByte:      t.ttfb,
		TTFBObserved:         t.ttfbSeen,
	}, t.tlsErr
}

// ExecuteHTTPS executes one bounded raw GET through an exact configured
// outbound. Operational failures are returned as a receipt; a non-nil error
// means the request itself was invalid and no network work was admitted.
func ExecuteHTTPS(ctx context.Context, instance *core.Instance, request HTTPSRequest) (*HTTPSReceipt, error) {
	return executeHTTPS(ctx, instance, request, nil)
}

func executeHTTPS(ctx context.Context, instance *core.Instance, request HTTPSRequest, tlsConfig *tls.Config) (*HTTPSReceipt, error) {
	if err := validateHTTPSRequest(ctx, instance, request); err != nil {
		return nil, err
	}

	operationCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()

	started := time.Now()
	receipt := &HTTPSReceipt{StartedAt: started.UTC(), Cleanup: CleanupNotOpened}
	operation := new(httpsOperation)
	trace := &traceState{started: started}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            exactDialer(instance, request.OutboundTag, operation),
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: maxResponseHeader,
		TLSClientConfig:        tlsConfig,
		Protocols:              protocols,
	}
	defer transport.CloseIdleConnections()

	httpRequest, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(operationCtx, trace.trace()),
		http.MethodGet,
		request.URL,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("measurement HTTPS request: %w", err)
	}
	httpRequest.Header["User-Agent"] = nil

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, doErr := client.Do(httpRequest)
	if doErr != nil {
		finishHTTPSReceipt(receipt, operation, trace, started, operationCtx.Err(), doErr)
		return receipt, nil
	}

	data, readErr := io.ReadAll(io.LimitReader(response.Body, request.MaxResponseBodyBytes+1))
	closeErr := response.Body.Close()
	receipt.Response = &HTTPSResponse{
		StatusCode:                response.StatusCode,
		Protocol:                  response.Proto,
		DeclaredContentLength:     response.ContentLength,
		ResponseBodyBytesObserved: int64(len(data)),
	}
	if int64(len(data)) > request.MaxResponseBodyBytes {
		receipt.Response.BodyTruncated = true
		data = data[:request.MaxResponseBodyBytes]
	}
	receipt.Response.Body = data

	finished := time.Now()
	receipt.FinishedAt = finished.UTC()
	receipt.Timing, _ = trace.snapshot(finished.Sub(started))
	receipt.SelectedOutbound = operation.selectedTag()
	receipt.Cleanup = operation.close()

	switch {
	case stderrors.Is(operationCtx.Err(), context.DeadlineExceeded):
		receipt.Outcome = OutcomeDeadlineExceeded
		receipt.FailureStage = FailureResponseBody
	case stderrors.Is(operationCtx.Err(), context.Canceled):
		receipt.Outcome = OutcomeCancelled
		receipt.FailureStage = FailureResponseBody
	case readErr != nil:
		receipt.Outcome = OutcomeFailed
		receipt.FailureStage = FailureResponseBody
	case closeErr != nil || receipt.Cleanup == CleanupFailed:
		receipt.Outcome = OutcomeFailed
		receipt.FailureStage = FailureCleanup
	default:
		receipt.Outcome = OutcomeSucceeded
	}
	return receipt, nil
}

func validateHTTPSRequest(ctx context.Context, instance *core.Instance, request HTTPSRequest) error {
	if ctx == nil {
		return fmt.Errorf("measurement HTTPS: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("measurement HTTPS: context already done: %w", err)
	}
	if instance == nil {
		return fmt.Errorf("measurement HTTPS: nil core instance")
	}
	if len(request.URL) == 0 || len(request.URL) > maxURLBytes {
		return fmt.Errorf("measurement HTTPS: URL must contain 1..%d bytes", maxURLBytes)
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("measurement HTTPS: URL must be absolute HTTPS without userinfo or fragment")
	}
	if len(request.OutboundTag) == 0 || len(request.OutboundTag) > maxOutboundTagBytes {
		return fmt.Errorf("measurement HTTPS: outbound tag must contain 1..%d bytes", maxOutboundTagBytes)
	}
	if request.Timeout <= 0 || request.Timeout > maxOperationTimeout {
		return fmt.Errorf("measurement HTTPS: timeout must be within (0,%s]", maxOperationTimeout)
	}
	if request.MaxResponseBodyBytes <= 0 || request.MaxResponseBodyBytes > maxResponseBodyBytes {
		return fmt.Errorf("measurement HTTPS: response body bound must be within 1..%d bytes", maxResponseBodyBytes)
	}
	return nil
}

func exactDialer(instance *core.Instance, outboundTag string, operation *httpsOperation) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || !operation.beginDial() {
			return nil, &exactRouteError{stage: FailureUnsupported, cleanup: CleanupNotOpened}
		}
		destination, err := xnet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, &exactRouteError{stage: FailureUnsupported, cleanup: CleanupNotOpened}
		}

		selection := session.NewForcedOutboundSelectionMailbox()
		routeCtx := session.ContextWithForcedOutboundSelection(ctx, selection)
		routeCtx = session.ContextWithTrafficOrigin(routeCtx, session.TrafficOriginControlledMeasurement)
		routeCtx = session.SetForcedOutboundTagToContext(routeCtx, outboundTag)
		conn, err := core.Dial(routeCtx, instance, destination)
		if err != nil {
			return nil, &exactRouteError{stage: FailureExactSelect, cleanup: CleanupNotOpened}
		}

		if selected, ok := selection.Wait(ctx); ok {
			if !selected.Found {
				cleanup := closeDetached(conn)
				return nil, &exactRouteError{stage: FailureExactSelect, cleanup: cleanup}
			}
			if selected.RequestedTag != outboundTag || selected.SelectedTag != outboundTag || selected.Origin != session.TrafficOriginControlledMeasurement {
				cleanup := closeDetached(conn)
				return nil, &exactRouteError{stage: FailureExactSelect, cleanup: cleanup}
			}
			operation.attach(conn, selected.SelectedTag)
			return conn, nil
		}
		cleanup := closeDetached(conn)
		return nil, &exactRouteError{stage: FailureExactSelect, cleanup: cleanup}
	}
}

func closeDetached(conn net.Conn) CleanupOutcome {
	if err := conn.Close(); err != nil && !stderrors.Is(err, net.ErrClosed) && !stderrors.Is(err, io.ErrClosedPipe) {
		return CleanupFailed
	}
	return CleanupConnectionClosed
}

func finishHTTPSReceipt(receipt *HTTPSReceipt, operation *httpsOperation, trace *traceState, started time.Time, contextErr, operationErr error) {
	finished := time.Now()
	receipt.FinishedAt = finished.UTC()
	receipt.Timing, _ = trace.snapshot(finished.Sub(started))
	receipt.SelectedOutbound = operation.selectedTag()
	receipt.Cleanup = operation.close()

	if stderrors.Is(contextErr, context.DeadlineExceeded) {
		receipt.Outcome = OutcomeDeadlineExceeded
		receipt.FailureStage = FailureResponseHeaders
		return
	}
	if stderrors.Is(contextErr, context.Canceled) {
		receipt.Outcome = OutcomeCancelled
		receipt.FailureStage = FailureResponseHeaders
		return
	}
	var routeErr *exactRouteError
	if stderrors.As(operationErr, &routeErr) {
		receipt.Outcome = OutcomeFailed
		receipt.FailureStage = routeErr.stage
		if receipt.Cleanup == CleanupNotOpened {
			receipt.Cleanup = routeErr.cleanup
		}
		return
	}
	_, tlsErr := trace.snapshot(0)
	if tlsErr != nil {
		receipt.Outcome = OutcomeFailed
		receipt.FailureStage = FailureEndpointTLS
		return
	}
	receipt.Outcome = OutcomeFailed
	receipt.FailureStage = FailureResponseHeaders
}
