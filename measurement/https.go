package measurement

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
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

// HTTPSReceipt contains raw endpoint facts. BodyBytes counts decoded HTTP payload retained in Body, not TLS/wire bytes.
// Timing pointers are absent unless independently observed. FirstByteElapsed
// starts at operation admission, including open, TLS and request transmission.
// Elapsed ends after HTTP consumption or failure, excluding cleanup and slot wait.
type HTTPSReceipt struct {
	StatusCode       int
	Header           http.Header
	Body             []byte
	BodyBytes        int64
	BodyComplete     bool
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

// HTTP performs one HEAD or GET through the requested native route. Status
// qualification and scheduling remain with the caller, including for HEAD.
func (e *Executor) HTTP(ctx context.Context, method string, request HTTPRequest) (HTTPReceipt, error) {
	if method != http.MethodHead && method != http.MethodGet {
		return HTTPReceipt{}, errors.New("HTTP probe method must be HEAD or GET")
	}
	return e.exchange(ctx, HTTPSRequest(request), method, nil, nil, nil)
}

// The standard library's trace context key is private. Mask its typed value
// before installing our trace, preserving cancellation and other caller values.
// Inherited Got1xxResponse hooks would reset net/http's aggregate header limit.
type withoutHTTPTrace struct{ context.Context }

func (c withoutHTTPTrace) Value(key any) any {
	value := c.Context.Value(key)
	if _, ok := value.(*httptrace.ClientTrace); ok {
		return nil
	}
	return value
}

func (e *Executor) HTTPS(ctx context.Context, request HTTPSRequest) (receipt HTTPSReceipt, resultErr error) {
	return e.exchangeHTTP(ctx, request, http.MethodGet, nil, nil, nil)
}

type httpExchangeOptions struct {
	destination xnet.Destination
	body        io.Reader
	headers     http.Header
}

// exchangeHTTP preserves the HTTPS-only contract of existing operation APIs.
func (e *Executor) exchangeHTTP(ctx context.Context, request HTTPSRequest, method string, upload *uploadBody, options *httpExchangeOptions, consume func(context.Context, *http.Response, *HTTPSReceipt) error) (receipt HTTPSReceipt, resultErr error) {
	scheme, _, found := strings.Cut(request.URL, ":")
	if !found || !strings.EqualFold(scheme, "https") {
		return receipt, errors.New("invalid bounded HTTPS URL")
	}
	return e.exchange(ctx, request, method, upload, options, consume)
}

// exchange owns the one native HTTP transport, route, TLS and cleanup path.
func (e *Executor) exchange(ctx context.Context, request HTTPSRequest, method string, upload *uploadBody, options *httpExchangeOptions, consume func(context.Context, *http.Response, *HTTPSReceipt) error) (receipt HTTPSReceipt, resultErr error) {
	if ctx == nil {
		return receipt, errors.New("nil request context")
	}
	u, err := url.Parse(request.URL)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" {
		return receipt, errors.New("invalid bounded HTTP URL")
	}
	if request.Timeout <= 0 || request.MaxBodyBytes < 0 || request.MaxBodyBytes == 0 && method != http.MethodHead || request.MaxBodyBytes == math.MaxInt64 || request.MaxHeaderBytes < 1 {
		return receipt, errors.New("invalid HTTPS byte/time budget")
	}
	if !request.Route.valid() {
		return receipt, errors.New("invalid measurement route")
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
	if options != nil {
		dest = options.destination
	}
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	if err := e.acquire(ctx); err != nil {
		return receipt, err
	}
	started := time.Now()
	o := new(operation)
	// net/http owns concurrent dialing and callbacks; these observations belong
	// only to this exchange and share the existing operation mutex.
	var firstByte *time.Duration
	var tlsStarted time.Time
	transport := &http.Transport{
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: request.MaxHeaderBytes,
		TLSNextProto:           make(map[string]func(string, *tls.Conn) http.RoundTripper),
		TLSClientConfig:        &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
	}
	if request.RootCAs != nil {
		transport.TLSClientConfig.RootCAs = request.RootCAs
	}
	var responseBody io.ReadCloser
	defer func() {
		receipt.Elapsed = time.Since(started)
		cancel()
		transport.CloseIdleConnections()
		if responseBody != nil {
			_ = responseBody.Close()
		}
		o.mu.Lock()
		receipt.OutboundError = o.nativeError
		receipt.EndpointTLS, receipt.FirstByteElapsed = o.tlsTime, firstByte
		o.mu.Unlock()
		<-e.slots
	}()
	ctx = measurementContext(ctx, o)
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		conn, err := e.open(ctx, request.Route, dest)
		if err == nil && conn != nil {
			// Pipe connections lack deadlines; ordinary cancellation closes
			// this concrete connection, including a late native dial result.
			context.AfterFunc(ctx, func() { _ = conn.Close() })
		}
		return conn, err
	}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			o.mu.Lock()
			tlsStarted = time.Now()
			o.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			o.mu.Lock()
			duration := time.Since(tlsStarted)
			o.tlsTime = &duration
			o.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			duration := time.Since(started)
			o.mu.Lock()
			if firstByte == nil {
				firstByte = &duration
			}
			o.mu.Unlock()
		},
	}
	var requestBody io.Reader
	if upload != nil {
		upload.ctx = ctx
		requestBody = upload
	} else if options != nil {
		requestBody = options.body
	}
	httpRequest, err := http.NewRequestWithContext(httptrace.WithClientTrace(withoutHTTPTrace{ctx}, trace), method, request.URL, requestBody)
	if err != nil {
		return receipt, err
	}
	if options != nil {
		httpRequest.Header = options.headers.Clone()
		httpRequest.GetBody = nil
	}
	if upload != nil {
		// A known length introduces io.LimitReader, bypassing WriterTo. Chunked
		// serialization preserves the explicitly counted HTTP writer boundary.
		httpRequest.ContentLength = -1
		httpRequest.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := transport.RoundTrip(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			err = errors.Join(ctx.Err(), err)
		}
		return receipt, err
	}
	responseBody = response.Body
	receipt.StatusCode, receipt.Header = response.StatusCode, response.Header.Clone()
	if consume == nil {
		err = readHTTPSBody(response, &receipt, request.MaxBodyBytes)
	} else {
		err = consume(ctx, response, &receipt)
	}
	if ctx.Err() != nil {
		err = errors.Join(ctx.Err(), err)
	}
	return receipt, err
}

func readHTTPSBody(response *http.Response, receipt *HTTPSReceipt, limit int64) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if int64(len(body)) > limit {
		body = body[:limit]
		err = errors.Join(err, ErrBodyLimit)
	}
	receipt.Body, receipt.BodyBytes = body, int64(len(body))
	receipt.BodyComplete = err == nil
	return err
}

func withNonce(rawURL, operation string) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", errors.New("invalid " + operation + " URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || query.Has("nonce") {
		return "", "", errors.New("invalid or conflicting " + operation + " nonce query")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", "", err
	}
	nonce := hex.EncodeToString(random[:])
	query.Set("nonce", nonce)
	u.RawQuery = query.Encode()
	return u.String(), nonce, nil
}
