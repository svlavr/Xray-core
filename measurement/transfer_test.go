package measurement_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func downloadRequest(s *httptest.Server, kind measurement.RouteKind) measurement.DownloadRequest {
	r := request(s, kind)
	r.MaxBodyBytes = 4 << 20
	return measurement.DownloadRequest{HTTPS: r, TransferTimeout: time.Second}
}

func uploadRequest(s *httptest.Server, kind measurement.RouteKind) measurement.UploadRequest {
	return measurement.UploadRequest{HTTPS: request(s, kind), PayloadBytes: 128<<10 + 7, TransferTimeout: time.Second}
}

func TestDownloadDirectExactStreamAndLimits(t *testing.T) {
	payload := bytes.Repeat([]byte("fixed-payload"), 100000)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected request semantics")
		}
		if r.URL.Path != "/chunked" {
			w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		}
		w.WriteHeader(200)
		if r.URL.Path == "/chunked" {
			w.(http.Flusher).Flush()
		}
		w.Write(payload)
	}))
	defer s.Close()
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		for _, path := range []string{"/fixed", "/chunked"} {
			req := downloadRequest(s, kind)
			req.HTTPS.URL += path
			r, err := e.Download(context.Background(), req)
			if err != nil || r.PayloadBytes != int64(len(payload)) || !r.HTTPS.BodyComplete || r.ActiveElapsed == nil || r.DeclaredLength == nil || len(r.HTTPS.Body) != 0 || r.HTTPS.BodyBytes != 0 {
				t.Fatalf("complete stream: %+v %v", r, err)
			}
		}
		limited := downloadRequest(s, kind)
		limited.HTTPS.MaxBodyBytes = 65539
		r, err := e.Download(context.Background(), limited)
		if err != nil || r.PayloadBytes != limited.HTTPS.MaxBodyBytes || !r.ByteLimitReached || r.HTTPS.BodyComplete {
			t.Fatalf("bounded prefix: %+v %v", r, err)
		}
		exact := downloadRequest(s, kind)
		exact.HTTPS.MaxBodyBytes = int64(len(payload))
		if r, err := e.Download(context.Background(), exact); err != nil || !r.HTTPS.BodyComplete || !r.ByteLimitReached {
			t.Fatalf("exact fixed-length cap: %+v %v", r, err)
		}
	}
}

func TestDownloadPartialFramingAndPhaseTimeout(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("prefix"))
		w.(http.Flusher).Flush()
		if r.URL.Path == "/stall" {
			<-r.Context().Done()
		}
	}))
	defer s.Close()
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		req := downloadRequest(s, kind)
		r, err := e.Download(context.Background(), req)
		if !errors.Is(err, io.ErrUnexpectedEOF) || r.PayloadBytes != 6 || r.HTTPS.BodyComplete {
			t.Fatalf("early EOF: %+v %v", r, err)
		}
		req.HTTPS.URL += "/stall"
		req.TransferTimeout = 40 * time.Millisecond
		r, err = e.Download(context.Background(), req)
		if !errors.Is(err, measurement.ErrTransferTimeout) || r.PayloadBytes != 6 || r.HTTPS.BodyComplete {
			t.Fatalf("active deadline: %+v %v", r, err)
		}
	}
}

func TestUploadDirectExactCounts(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.ContentLength != -1 || len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" || r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Error("upload counting framing changed")
		}
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "raw-response")
	}))
	defer s.Close()
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		req := uploadRequest(s, kind)
		r, err := e.Upload(context.Background(), req)
		if err != nil || r.GeneratedBytes != req.PayloadBytes || r.WriterAcceptedBytes != req.PayloadBytes || r.ActiveElapsed == nil || !r.HTTPS.BodyComplete {
			t.Fatalf("upload facts: %+v %v", r, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("extra endpoint exchange")
	}
}

func TestUploadRawResponse(t *testing.T) {
	e := executor(t, instance(t))
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "raw-200")
	}))
	defer s.Close()
	req := uploadRequest(s, measurement.ExactOutbound)
	r, err := e.Upload(context.Background(), req)
	if err != nil || string(r.HTTPS.Body) != "raw-200" || r.WriterAcceptedBytes != req.PayloadBytes {
		t.Fatalf("raw response: %+v %v", r, err)
	}
}

func TestTransferValidationAndMissingExactNoFallback(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "raw-response")
	}))
	defer s.Close()
	e := executor(t, instance(t))
	d := downloadRequest(s, measurement.ExactOutbound)
	d.HTTPS.Route.Tag = "missing"
	if r, err := e.Download(context.Background(), d); err == nil || r.PayloadBytes != 0 {
		t.Fatalf("missing download: %+v %v", r, err)
	}
	u := uploadRequest(s, measurement.ExactOutbound)
	u.HTTPS.Route.Tag = "missing"
	if r, err := e.Upload(context.Background(), u); err == nil || r.GeneratedBytes != 0 {
		t.Fatalf("missing upload: %+v %v", r, err)
	}
	for _, size := range []int64{0, -1} {
		d = downloadRequest(s, measurement.Direct)
		d.HTTPS.MaxBodyBytes = size
		if _, err := e.Download(context.Background(), d); err == nil {
			t.Fatal("invalid download budget opened")
		}
		u = uploadRequest(s, measurement.Direct)
		u.PayloadBytes = size
		if _, err := e.Upload(context.Background(), u); err == nil {
			t.Fatal("invalid upload budget opened")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Download(ctx, downloadRequest(s, measurement.Direct)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := e.Upload(ctx, uploadRequest(s, measurement.Direct)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("validation/route failure reached endpoint")
	}
}

func TestUploadEarlyResponsePreservesPartialCounts(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid the server's automatic small-body drain and reply without reading.
		w.Header().Set("Connection", "close")
		w.WriteHeader(200)
		io.WriteString(w, "early")
		w.(http.Flusher).Flush()
	}))
	defer s.Close()
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		u := uploadRequest(s, kind)
		u.PayloadBytes = 64 << 20
		r, err := e.Upload(context.Background(), u)
		if err == nil || r.WriterAcceptedBytes >= u.PayloadBytes || r.GeneratedBytes < r.WriterAcceptedBytes || r.GeneratedBytes > r.WriterAcceptedBytes+(32<<10) {
			t.Fatalf("early response partial counts changed: %+v %v", r, err)
		}
	}
}

func TestTransferConcurrentCancellationAndSibling(t *testing.T) {
	entered := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("part"))
			w.(http.Flusher).Flush()
			close(entered)
			<-r.Context().Done()
			return
		}
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, "raw-response")
		} else {
			io.WriteString(w, "sibling")
		}
	}))
	defer s.Close()
	e := executor(t, instance(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := downloadRequest(s, measurement.ExactOutbound)
	d.HTTPS.URL += "/stall"
	done := make(chan error, 1)
	go func() { _, err := e.Download(ctx, d); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("download not active")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := uploadRequest(s, measurement.ExactOutbound)
			r, err := e.Upload(context.Background(), u)
			if err != nil || r.WriterAcceptedBytes != u.PayloadBytes || !r.HTTPS.BodyComplete {
				t.Errorf("upload sibling: %+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, measurement.ErrTransferTimeout) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled download not joined")
	}
	if r, err := e.HTTPS(context.Background(), request(s, measurement.ExactOutbound)); err != nil || string(r.Body) != "sibling" {
		t.Fatalf("ordinary HTTPS after transfer: %+v %v", r, err)
	}
}

// This peer exercises both transfer executors through native VLESS RAW/TCP;
// the B1 counting-relay fixture separately proves its physical selection seam.
func TestTransferExactVLESS(t *testing.T) {
	port := tcp.PickPort()
	peerID := uuid.New()
	id := peerID.String()
	peer, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}}), ProxySettings: serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: id})}}})}},
		Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	v := instance(t)
	manager := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := manager.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	if err := core.AddOutboundHandler(v, &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"})}}})}); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("vless-transfer"), 20000)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, "raw-response")
		} else {
			w.Write(payload)
		}
	}))
	defer s.Close()
	e := executor(t, v)
	d := downloadRequest(s, measurement.ExactOutbound)
	if r, err := e.Download(context.Background(), d); err != nil || r.PayloadBytes != int64(len(payload)) || !r.HTTPS.BodyComplete {
		t.Fatalf("VLESS download: %+v %v", r, err)
	}
	u := uploadRequest(s, measurement.ExactOutbound)
	if r, err := e.Upload(context.Background(), u); err != nil || r.WriterAcceptedBytes != u.PayloadBytes || !r.HTTPS.BodyComplete {
		t.Fatalf("VLESS upload: %+v %v", r, err)
	}
}

// Native TLS peer intentionally stops reading after HTTP headers to exercise
// real socket backpressure. Client close must unblock the write phase.
func TestUploadBackpressureActiveDeadline(t *testing.T) {
	gate := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-gate }))
	defer s.Close()
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		u := uploadRequest(s, kind)
		u.PayloadBytes = 64 << 20
		u.TransferTimeout = 50 * time.Millisecond
		r, err := e.Upload(context.Background(), u)
		if !errors.Is(err, measurement.ErrTransferTimeout) || r.WriterAcceptedBytes >= u.PayloadBytes {
			close(gate)
			t.Fatalf("backpressure: %+v %v", r, err)
		}
	}
	close(gate)
}

func TestUploadCancellationAndResponseDeadline(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			e := executor(t, instance(t))
			entered := make(chan struct{})
			release := make(chan struct{})
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release // Leave body unread, creating native socket backpressure.
			}))
			defer s.Close()
			defer close(release)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u := uploadRequest(s, kind)
			u.PayloadBytes = 64 << 20
			done := make(chan struct {
				receipt measurement.UploadReceipt
				err     error
			}, 1)
			go func() {
				r, err := e.Upload(ctx, u)
				done <- struct {
					receipt measurement.UploadReceipt
					err     error
				}{r, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("upload not entered")
			}
			cancel()
			select {
			case result := <-done:
				if !errors.Is(result.err, context.Canceled) {
					t.Fatalf("cancel: %+v %v", result.receipt, result.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("upload cancel did not join")
			}
		})
	}
	// Full-operation expiry after WriterTo returned is not an active-write expiry.
	e := executor(t, instance(t))
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); <-release }))
	defer s.Close()
	defer close(release)
	u := uploadRequest(s, measurement.ExactOutbound)
	u.HTTPS.Timeout = 120 * time.Millisecond
	u.TransferTimeout = 100 * time.Millisecond
	r, err := e.Upload(context.Background(), u)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, measurement.ErrTransferTimeout) || r.WriterAcceptedBytes != u.PayloadBytes || r.HTTPS.StatusCode != 0 {
		t.Fatalf("response expiry: %+v %v", r, err)
	}
}

func TestTransferUnknownLengthCapAndPartialUploadResponse(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			io.WriteString(w, "abcdef")
			return
		}
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, "partial")
	}))
	defer s.Close()
	e := executor(t, instance(t))
	d := downloadRequest(s, measurement.Direct)
	d.HTTPS.MaxBodyBytes = 4
	download, err := e.Download(context.Background(), d)
	if err != nil || !download.ByteLimitReached || download.HTTPS.BodyComplete || download.PayloadBytes != 4 || *download.DeclaredLength != -1 {
		t.Fatalf("unknown framing cap: %+v %v", download, err)
	}
	u := uploadRequest(s, measurement.ExactOutbound)
	upload, err := e.Upload(context.Background(), u)
	if !errors.Is(err, io.ErrUnexpectedEOF) || upload.WriterAcceptedBytes != u.PayloadBytes || upload.HTTPS.BodyComplete || string(upload.HTTPS.Body) != "partial" {
		t.Fatalf("partial response: %+v %v", upload, err)
	}
}

func TestDownloadRawPartialExit(t *testing.T) {
	prefix := []byte("prefix")
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		routeName := "direct"
		if kind == measurement.ExactOutbound {
			routeName = "exact"
		}
		for _, mode := range []string{"truncated", "timeout", "capped", "cancel", "pre-cancel", "complete", "raw-status"} {
			t.Run(routeName+"/"+mode, func(t *testing.T) {
				entered := make(chan struct{})
				s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/sibling" {
						io.WriteString(w, "sibling")
						return
					}
					if mode == "complete" || mode == "raw-status" {
						w.Header().Set("Content-Length", "6")
					} else {
						w.Header().Set("Content-Length", "100")
					}
					if mode == "raw-status" {
						w.WriteHeader(503)
					}
					w.Write(prefix)
					w.(http.Flusher).Flush()
					close(entered)
					if mode == "timeout" || mode == "cancel" {
						<-r.Context().Done()
					}
				}))
				defer s.Close()
				e := executor(t, instance(t))
				req := downloadRequest(s, kind)
				if mode == "timeout" {
					req.TransferTimeout = 80 * time.Millisecond
				}
				if mode == "cancel" {
					req.TransferTimeout = 5 * time.Second
				}
				if mode == "capped" {
					req.HTTPS.MaxBodyBytes = 3
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "pre-cancel" {
					cancel()
				}
				var got measurement.DownloadReceipt
				var err error
				if mode == "cancel" {
					done := make(chan struct{})
					go func() { got, err = e.Download(ctx, req); close(done) }()
					select {
					case <-entered:
					case <-time.After(2 * time.Second):
						t.Fatal("peer not entered")
					}
					sibling := request(s, kind)
					sibling.URL += "/sibling"
					if _, siblingErr := e.HTTPS(context.Background(), sibling); siblingErr != nil {
						t.Fatal(siblingErr)
					}
					cancel()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Fatal("cancel did not join")
					}
				} else {
					got, err = e.Download(ctx, req)
				}
				switch mode {
				case "truncated":
					if !errors.Is(err, io.ErrUnexpectedEOF) || got.PayloadBytes != 6 {
						t.Fatalf("truncated %+v %v", got, err)
					}
				case "timeout":
					if !errors.Is(err, measurement.ErrTransferTimeout) || got.PayloadBytes != 6 {
						t.Fatalf("timeout %+v %v", got, err)
					}
				case "capped":
					if err != nil || got.PayloadBytes != 3 || !got.ByteLimitReached {
						t.Fatalf("cap %+v %v", got, err)
					}
				case "cancel":
					if !errors.Is(err, context.Canceled) || errors.Is(err, measurement.ErrTransferTimeout) {
						t.Fatalf("cancel %+v %v", got, err)
					}
					t.Logf("cancellation bytes=%d response=%t", got.PayloadBytes, got.DeclaredLength != nil)
				case "pre-cancel":
					if !errors.Is(err, context.Canceled) || got.DeclaredLength != nil {
						t.Fatalf("pre-cancel %+v %v", got, err)
					}
				case "complete":
					if err != nil || !got.HTTPS.BodyComplete {
						t.Fatalf("unrequested %+v %v", got, err)
					}
					return
				case "raw-status":
					if err != nil || got.HTTPS.StatusCode != 503 || !got.HTTPS.BodyComplete {
						t.Fatalf("raw status %+v %v", got, err)
					}
				}
				// Cancellation may win before response admission; preserve that honest boundary.
				if got.DeclaredLength == nil {
					if mode != "cancel" && mode != "pre-cancel" || got.ActiveElapsed != nil || got.PayloadBytes != 0 || got.HTTPS.BodyComplete {
						t.Fatalf("before response %+v", got)
					}
					return
				}
				if got.PayloadBytes < 0 || got.PayloadBytes > 6 {
					t.Fatal(got.PayloadBytes)
				}
				if got.ActiveElapsed == nil {
					t.Fatalf("partial phase %+v %v", got, err)
				}
				if mode != "raw-status" && got.HTTPS.BodyComplete {
					t.Fatalf("false completion %+v", got)
				}
			})
		}
	}
}
