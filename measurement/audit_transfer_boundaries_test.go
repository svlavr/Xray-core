package measurement

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func auditTransferExecutor(t *testing.T) *Executor {
	t.Helper()
	e, err := New(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func auditTransferRequest(s *httptest.Server) HTTPSRequest {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return HTTPSRequest{
		Route:          Route{Kind: Direct},
		URL:            s.URL,
		Timeout:        5 * time.Second,
		MaxBodyBytes:   64,
		MaxHeaderBytes: 4096,
		RootCAs:        pool,
	}
}

func TestAuditTransferTLSUploadReceiverBoundary(t *testing.T) {
	const payloadBytes int64 = 65543
	for _, mode := range []string{"drain_before_response", "early_200_without_handler_read"} {
		t.Run(mode, func(t *testing.T) {
			type receiverResult struct {
				consumed int64
				err      error
			}
			receiver := make(chan receiverResult, 1)
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var observed receiverResult
				if mode == "drain_before_response" {
					observed.consumed, observed.err = io.Copy(io.Discard, r.Body)
				} else {
					// This counts handler reads only. Native TLS, socket buffers and
					// HTTP parsing may already have consumed request bytes.
					w.Header().Set("Connection", "close")
				}
				receiver <- observed
				w.Header().Set("Content-Length", "2")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "ok")
				w.(http.Flusher).Flush()
			}))
			defer s.Close()
			e := auditTransferExecutor(t)
			r, err := e.Upload(context.Background(), UploadRequest{
				HTTPS:           auditTransferRequest(s),
				PayloadBytes:    payloadBytes,
				TransferTimeout: 3 * time.Second,
			})
			var observed receiverResult
			select {
			case observed = <-receiver:
			case <-time.After(5 * time.Second):
				t.Fatalf("receiver not reached: generated=%d writer_accepted=%d status=%d error=%v", r.GeneratedBytes, r.WriterAcceptedBytes, r.HTTPS.StatusCode, err)
			}
			t.Logf("payload=%d generated=%d writer_accepted=%d handler_consumed=%d status=%d error=%v handler_error=%v", payloadBytes, r.GeneratedBytes, r.WriterAcceptedBytes, observed.consumed, r.HTTPS.StatusCode, err, observed.err)
			if r.HTTPS.StatusCode != http.StatusOK {
				t.Fatalf("response not observed: %+v %v", r, err)
			}
			if mode == "drain_before_response" {
				if err != nil || observed.err != nil || observed.consumed != payloadBytes || r.GeneratedBytes != payloadBytes || r.WriterAcceptedBytes != payloadBytes {
					t.Fatalf("drained upload counts: receipt=%+v error=%v receiver=%+v", r, err, observed)
				}
				return
			}
			if observed.consumed != 0 || observed.err != nil {
				t.Fatalf("early-response handler read the body: %+v", observed)
			}
			// Small uploads may be accepted in full before the early response.
			// No exact partial count is portable across HTTP/TLS buffering.
			if r.WriterAcceptedBytes < 0 || r.WriterAcceptedBytes > r.GeneratedBytes || r.GeneratedBytes > payloadBytes {
				t.Fatalf("invalid local upload counts: %+v %v", r, err)
			}
			if (r.GeneratedBytes != payloadBytes || r.WriterAcceptedBytes != payloadBytes) && !errors.Is(err, ErrUploadIncomplete) {
				t.Fatalf("incomplete local upload lost its error: %+v %v", r, err)
			}
		})
	}
}

func TestAuditTransferBufferedWriterAcceptanceBeforeDrain(t *testing.T) {
	const payloadBytes int64 = 65543
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	body := &uploadBody{ctx: ctx, cancel: cancel, bytes: payloadBytes, timeout: 3 * time.Second}
	var downstream bytes.Buffer
	writer := bufio.NewWriterSize(&downstream, int(payloadBytes)+1)
	n, err := body.WriteTo(writer)
	t.Logf("before_drain payload=%d generated=%d writer_accepted=%d write_to=%d buffered=%d downstream_consumed=%d error=%v", payloadBytes, body.produced, body.written, n, writer.Buffered(), downstream.Len(), err)
	if err != nil || n != payloadBytes || body.produced != payloadBytes || body.written != payloadBytes || int64(writer.Buffered()) != payloadBytes || downstream.Len() != 0 {
		t.Fatalf("buffered acceptance boundary: generated=%d accepted=%d n=%d buffered=%d consumed=%d error=%v", body.produced, body.written, n, writer.Buffered(), downstream.Len(), err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Logf("after_explicit_drain buffered=%d downstream_consumed=%d", writer.Buffered(), downstream.Len())
	if writer.Buffered() != 0 || int64(downstream.Len()) != payloadBytes {
		t.Fatalf("explicit drain: buffered=%d consumed=%d", writer.Buffered(), downstream.Len())
	}
	// This is local buffering evidence, with no delivery or throughput claim.
}

func TestAuditTransferDownloadHeaderGateElapsedBoundary(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	held := make(chan time.Duration, 1)
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		close(entered)
		<-release // No response headers or payload exist before this gate opens.
		held <- time.Since(started)
		w.Header().Set("Content-Length", "7")
		_, _ = io.WriteString(w, "payload")
	}))
	defer s.Close()
	defer releaseHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type downloadResult struct {
		receipt DownloadReceipt
		err     error
		wall    time.Duration
	}
	done := make(chan downloadResult, 1)
	e := auditTransferExecutor(t)
	go func() {
		started := time.Now()
		r, err := e.Download(ctx, DownloadRequest{HTTPS: auditTransferRequest(s), TransferTimeout: 3 * time.Second})
		done <- downloadResult{receipt: r, err: err, wall: time.Since(started)}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not reach the pre-header gate")
	}
	// Hold the gate long enough to make the timing boundary visible on coarse
	// host clocks. Only the actual measured hold enters the assertions below.
	gateTimer := time.NewTimer(30 * time.Millisecond)
	defer gateTimer.Stop()
	select {
	case result := <-done:
		t.Fatalf("download returned while headers were gated: %+v", result)
	case <-gateTimer.C:
	}
	releaseHandler()
	var result downloadResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not finish after releasing headers")
	}
	measuredHold := <-held
	r := result.receipt
	if result.err != nil || r.HTTPS.StatusCode != http.StatusOK || r.PayloadBytes != 7 || !r.HTTPS.BodyComplete || r.ActiveElapsed == nil || r.DeclaredLength == nil || *r.DeclaredLength != 7 {
		t.Fatalf("fixed payload after header gate: %+v %v", r, result.err)
	}
	t.Logf("payload=%d total_elapsed=%s active_elapsed=%s measured_header_hold=%s caller_wall_elapsed=%s complete=%t error=%v", r.PayloadBytes, r.HTTPS.Elapsed, *r.ActiveElapsed, measuredHold, result.wall, r.HTTPS.BodyComplete, result.err)
	if measuredHold < 0 || *r.ActiveElapsed < 0 || r.HTTPS.Elapsed < *r.ActiveElapsed+measuredHold || result.wall < r.HTTPS.Elapsed {
		t.Fatalf("elapsed boundaries: total=%s active=%s hold=%s wall=%s", r.HTTPS.Elapsed, *r.ActiveElapsed, measuredHold, result.wall)
	}
	// The measured hold precedes the read phase. The timer is not a precision
	// or speed assertion, and this makes no claim about HTTP/TLS body prefetch.
}
