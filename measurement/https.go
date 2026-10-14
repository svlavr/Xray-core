package measurement

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

var ErrBodyLimit = errors.New("response body exceeds request limit")

// HTTPSRequest describes one GET without redirect, retry, decompression or reuse.
// RootCAs supplies endpoint trust; nil uses the system trust store.
type HTTPSRequest struct {
	Route        Route
	URL          string
	Timeout      time.Duration
	MaxBodyBytes int64
	// MaxHeaderBytes bounds native informational and final response headers.
	// HTTP trailers are not returned and have the native parser's separate
	// 4 KiB ceiling. This is not a combined wire/header/trailer byte budget.
	MaxHeaderBytes int64
	RootCAs        *x509.CertPool
}

// HTTPSReceipt retains endpoint facts. BodyBytes is transfer-decoded payload,
// retaining content coding (for example gzip), not TLS/wire byte counts.
// Timing pointers are absent unless independently observed. FirstByteElapsed
// starts at operation admission, including open, TLS and request transmission.
// Elapsed ends after HTTP consumption or failure, excluding cleanup and slot wait.
type HTTPSReceipt struct {
	StatusCode       int
	Header           http.Header
	ContentLength    *int64   // Native response length; -1 unknown, nil before response.
	TransferEncoding []string // Native framing metadata, removed from Header by net/http.
	Body             []byte
	BodyBytes        int64
	BodyComplete     bool // Native body-reader completion; not content or authenticated-closure proof.
	Elapsed          time.Duration
	EndpointTLS      *time.Duration
	FirstByteElapsed *time.Duration
	OutboundError    error
}

// HTTPRequest uses the existing transaction budgets for HTTP or HTTPS probes.
// HEAD permits MaxBodyBytes=0; GET requires a positive retained-payload budget.
type HTTPRequest HTTPSRequest

// HTTPReceipt has the same raw facts; EndpointTLS is absent for plain HTTP.
type HTTPReceipt = HTTPSReceipt

// A plan shares construction and consumption; it cannot acquire a nested slot.
type httpPlan struct {
	method      string
	secure      bool
	destination *xnet.Destination
	body        io.Reader
	headers     http.Header
	consume     func(*operation, *http.Response, *HTTPSReceipt) error
	finish      func() error // Snapshot asynchronous writer facts before cleanup cancellation.
}

// HTTP performs one HEAD or GET through the requested native route. Status
// qualification and scheduling remain with the caller, including for HEAD.
func (e *Executor) HTTP(ctx context.Context, method string, request HTTPRequest) (HTTPReceipt, error) {
	if method != http.MethodHead && method != http.MethodGet {
		return HTTPReceipt{}, errors.New("HTTP probe method must be HEAD or GET")
	}
	return e.http(ctx, HTTPSRequest(request), httpPlan{method: method})
}

func (e *Executor) HTTPS(ctx context.Context, request HTTPSRequest) (HTTPSReceipt, error) {
	return e.http(ctx, request, httpPlan{method: http.MethodGet, secure: true})
}

// Do not compose inherited net/http hooks, including its aggregate-header override.
type withoutHTTPTrace struct{ context.Context }

func (c withoutHTTPTrace) Value(key any) any {
	value := c.Context.Value(key)
	if _, ok := value.(*httptrace.ClientTrace); ok {
		return nil
	}
	return value
}

func (e *Executor) http(ctx context.Context, request HTTPSRequest, plan httpPlan) (receipt HTTPSReceipt, resultErr error) {
	u, err := url.Parse(request.URL)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" || plan.secure && u.Scheme != "https" || u.Hostname() == "" {
		return receipt, errors.New("invalid bounded HTTP URL")
	}
	if request.Timeout <= 0 || request.MaxBodyBytes < 0 || request.MaxBodyBytes == 0 && plan.method != http.MethodHead || request.MaxBodyBytes == math.MaxInt64 || request.MaxHeaderBytes < 1 || !request.Route.valid() {
		return receipt, errors.New("invalid HTTP route/byte/time budget")
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	dest, err := xnet.ParseDestination("tcp:" + net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return receipt, err
	}
	if plan.destination != nil {
		dest = *plan.destination
	}
	o, err := e.begin(ctx, request.Timeout)
	if err != nil {
		return receipt, err
	}
	defer o.end()
	transport := &http.Transport{
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: request.MaxHeaderBytes,
		TLSNextProto:           make(map[string]func(string, *tls.Conn) http.RoundTripper),
		TLSClientConfig:        &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: request.RootCAs},
	}
	var responseBody io.ReadCloser
	defer func() {
		receipt.Elapsed = time.Since(o.started)
		if plan.finish != nil {
			resultErr = errors.Join(resultErr, plan.finish())
		}
		resultErr = errors.Join(resultErr, o.Err(), context.Cause(o))
		o.cancel(nil)
		transport.CloseIdleConnections()
		if responseBody != nil {
			_ = responseBody.Close()
		}
		o.mu.Lock()
		receipt.OutboundError, receipt.EndpointTLS, receipt.FirstByteElapsed = o.nativeError, o.tlsTime, o.firstByte
		o.mu.Unlock()
	}()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		conn, err := e.open(o, request.Route, dest)
		if err == nil && conn != nil {
			context.AfterFunc(o, func() { _ = conn.Close() })
		}
		return conn, err
	}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			o.mu.Lock()
			o.tlsStarted = time.Now()
			o.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			o.mu.Lock()
			elapsed := time.Since(o.tlsStarted)
			o.tlsTime = &elapsed
			o.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			o.mu.Lock()
			if o.firstByte == nil {
				elapsed := time.Since(o.started)
				o.firstByte = &elapsed
			}
			o.mu.Unlock()
		},
	}
	if upload, ok := plan.body.(*uploadBody); ok {
		upload.ctx, upload.cancel = o, o.cancel
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(withoutHTTPTrace{o}, trace), plan.method, request.URL, plan.body)
	if err != nil {
		return receipt, err
	}
	req.Header = plan.headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.GetBody = nil
	if _, ok := plan.body.(*uploadBody); ok {
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := transport.RoundTrip(req)
	if err != nil {
		return receipt, err
	}
	responseBody = response.Body
	receipt.StatusCode, receipt.Header = response.StatusCode, response.Header
	length := response.ContentLength
	receipt.ContentLength, receipt.TransferEncoding = &length, response.TransferEncoding
	if plan.consume != nil {
		return receipt, plan.consume(o, response, &receipt)
	}
	return receipt, readHTTPSBody(o, response, &receipt, request.MaxBodyBytes)
}

// Retained bodies inspect one extra byte; streams stop at their caller ceiling.
// Both retain positive bytes before handling an accompanying reader error.
func consumeHTTPBody(ctx context.Context, response *http.Response, receipt *HTTPSReceipt, limit int64, retain bool) (count int64, capHit bool, resultErr error) {
	ceiling := limit
	if retain {
		ceiling++
		receipt.Body = make([]byte, 0) // Preserve native io.ReadAll empty-body representation.
	}
	buffer := make([]byte, min(int64(transferChunk), ceiling))
	for count < ceiling {
		// Retained mode preserves the former io.ReadAll native read boundary.
		// Streaming mode retains its explicit between-read cancellation check.
		if !retain {
			if err := ctx.Err(); err != nil {
				return count, count >= limit, err
			}
		}
		n, err := response.Body.Read(buffer[:min(int64(len(buffer)), ceiling-count)])
		count += int64(n)
		if retain {
			kept := min(int64(n), limit-receipt.BodyBytes)
			receipt.Body = append(receipt.Body, buffer[:kept]...)
			receipt.BodyBytes += kept
		}
		if err == io.EOF {
			receipt.BodyComplete = true
			break
		}
		if err != nil {
			resultErr = err
			break
		}
	}
	capHit = count >= limit
	if retain && count > limit {
		receipt.BodyComplete = false
		resultErr = errors.Join(resultErr, ErrBodyLimit)
	}
	return count, capHit, resultErr
}

func readHTTPSBody(ctx context.Context, response *http.Response, receipt *HTTPSReceipt, limit int64) error {
	_, _, err := consumeHTTPBody(ctx, response, receipt, limit, true)
	return err
}
