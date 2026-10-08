package measurement_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	return measurement.UploadRequest{HTTPS: request(s, kind), PayloadBytes: 128<<10 + 7, TransferTimeout: time.Second, RequireAcknowledgment: true}
}

func acknowledge(w http.ResponseWriter, r *http.Request) {
	digest := sha256.New()
	n, err := io.Copy(digest, r.Body)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"nonce": r.URL.Query().Get("nonce"), "bytes": n, "sha256": hex.EncodeToString(digest.Sum(nil))})
}

func TestDownloadDirectExactStreamDigestAndLimits(t *testing.T) {
	payload := bytes.Repeat([]byte("fixed-payload"), 100000)
	digest := sha256.Sum256(payload)
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
			req.ExpectedSHA256 = &digest
			r, err := e.Download(context.Background(), req)
			if err != nil || r.PayloadBytes != int64(len(payload)) || r.SHA256 == nil || *r.SHA256 != digest || !r.HTTPS.BodyComplete || !r.IntegrityVerified || r.ActiveElapsed == nil || r.DeclaredLength == nil || len(r.HTTPS.Body) != 0 || r.HTTPS.BodyBytes != 0 {
				t.Fatalf("complete stream: %+v %v", r, err)
			}

		}
		limited := downloadRequest(s, kind)
		limited.HTTPS.MaxBodyBytes = 65539
		r, err := e.Download(context.Background(), limited)
		if err != nil || r.PayloadBytes != limited.HTTPS.MaxBodyBytes || !r.ByteLimitReached || r.HTTPS.BodyComplete || r.SHA256 != nil || r.IntegrityVerified {
			t.Fatalf("bounded prefix: %+v %v", r, err)
		}
		limited.ExpectedSHA256 = &digest
		if r, err := e.Download(context.Background(), limited); !errors.Is(err, measurement.ErrIntegrityIncomplete) || r.IntegrityVerified {
			t.Fatalf("partial integrity: %+v %v", r, err)
		}
		exact := downloadRequest(s, kind)
		exact.HTTPS.MaxBodyBytes = int64(len(payload))
		exact.ExpectedSHA256 = &digest
		if r, err := e.Download(context.Background(), exact); err != nil || !r.HTTPS.BodyComplete || !r.IntegrityVerified || !r.ByteLimitReached {
			t.Fatalf("exact fixed-length cap: %+v %v", r, err)
		}
		wrong := digest
		wrong[0] ^= 1
		exact.ExpectedSHA256 = &wrong
		if r, err := e.Download(context.Background(), exact); !errors.Is(err, measurement.ErrDigestMismatch) || r.IntegrityVerified || *r.SHA256 != digest {
			t.Fatalf("digest mismatch: %+v %v", r, err)
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
		if !errors.Is(err, io.ErrUnexpectedEOF) || r.PayloadBytes != 6 || r.HTTPS.BodyComplete || r.SHA256 != nil {
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

func TestUploadDirectExactCountsNonceAndACK(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.ContentLength != -1 || len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" || r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Error("upload counting framing changed")
		}
		acknowledge(w, r)
	}))
	defer s.Close()
	e := executor(t, instance(t))
	nonces := make(map[string]bool)
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		req := uploadRequest(s, kind)
		r, err := e.Upload(context.Background(), req)
		if err != nil || r.GeneratedBytes != req.PayloadBytes || r.WriterAcceptedBytes != req.PayloadBytes || r.ActiveElapsed == nil || r.WriterAcceptedSHA256 == nil || r.Acknowledgment == nil || r.Acknowledgment.Bytes != req.PayloadBytes || r.Acknowledgment.SHA256 != *r.WriterAcceptedSHA256 || !r.HTTPS.BodyComplete {
			t.Fatalf("upload facts: %+v %v", r, err)
		}
		if len(r.Nonce) != 32 || nonces[r.Nonce] {
			t.Fatal("nonce reused")
		}
		nonces[r.Nonce] = true

	}
	if calls.Load() != 2 {
		t.Fatal("extra endpoint exchange")
	}
}

func TestUploadACKRejectionAndRawResponse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any) string
		status int
		media  string
	}{
		{"nonce", func(a map[string]any) string { a["nonce"] = "wrong"; b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"count", func(a map[string]any) string { a["bytes"] = 1; b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"digest", func(a map[string]any) string {
			a["sha256"] = strings.Repeat("0", 64)
			b, _ := json.Marshal(a)
			return string(b)
		}, 200, "application/json"},
		{"duplicate", func(a map[string]any) string {
			b, _ := json.Marshal(a)
			return strings.TrimSuffix(string(b), "}") + `,"bytes":1}`
		}, 200, "application/json"},
		{"unknown", func(a map[string]any) string { a["extra"] = true; b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"null", func(a map[string]any) string { a["bytes"] = nil; b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"string-count", func(a map[string]any) string { a["bytes"] = "131079"; b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"fraction", func(a map[string]any) string { a["bytes"] = 1.5; b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"missing", func(a map[string]any) string { delete(a, "nonce"); b, _ := json.Marshal(a); return string(b) }, 200, "application/json"},
		{"extra-json", func(a map[string]any) string { b, _ := json.Marshal(a); return string(b) + "{}" }, 200, "application/json"},
		{"invalid-utf8", func(a map[string]any) string { return "{\"nonce\":\"\xff\"}" }, 200, "application/json"},
		{"status", func(a map[string]any) string { b, _ := json.Marshal(a); return string(b) }, 201, "application/json"},
		{"media", func(a map[string]any) string { b, _ := json.Marshal(a); return string(b) }, 200, "text/plain"},
		{"parameter", func(a map[string]any) string { b, _ := json.Marshal(a); return string(b) }, 200, "application/json; boundary=x"},
		{"oversize", func(a map[string]any) string { return strings.Repeat("x", (16<<10)+1) }, 200, "application/json"},
	}
	e := executor(t, instance(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h := sha256.New()
				n, err := io.Copy(h, r.Body)
				if err != nil {
					return
				}
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.mutate(map[string]any{"nonce": r.URL.Query().Get("nonce"), "bytes": n, "sha256": hex.EncodeToString(h.Sum(nil))}))
			}))
			defer s.Close()
			req := uploadRequest(s, measurement.Direct)
			req.HTTPS.MaxBodyBytes = 1 << 20
			r, err := e.Upload(context.Background(), req)
			ordinaryJSON := tc.name == "unknown" || tc.name == "media" || tc.name == "parameter"
			if ordinaryJSON {
				if err != nil || r.Acknowledgment == nil {
					t.Fatalf("ordinary ACK decoding failed: %+v %v", r, err)
				}
			} else if !errors.Is(err, measurement.ErrUploadACK) || r.Acknowledgment != nil || r.WriterAcceptedBytes != req.PayloadBytes {
				t.Fatalf("mismatched ACK: %+v %v", r, err)
			}
		})
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "raw-200")
	}))
	defer s.Close()
	req := uploadRequest(s, measurement.ExactOutbound)
	req.RequireAcknowledgment = false
	r, err := e.Upload(context.Background(), req)
	if err != nil || r.Acknowledgment != nil || string(r.HTTPS.Body) != "raw-200" || r.WriterAcceptedBytes != req.PayloadBytes {
		t.Fatalf("raw response: %+v %v", r, err)
	}
}

func TestTransferValidationAndMissingExactNoFallback(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); acknowledge(w, r) }))
	defer s.Close()
	e := executor(t, instance(t))
	d := downloadRequest(s, measurement.ExactOutbound)
	d.HTTPS.Route.Tag = "missing"
	if r, err := e.Download(context.Background(), d); err == nil || r.SHA256 != nil {
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
	u = uploadRequest(s, measurement.Direct)
	u.HTTPS.URL += "?nonce=caller"
	if _, err := e.Upload(context.Background(), u); err == nil {
		t.Fatal("nonce conflict opened")
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
		u.RequireAcknowledgment = false
		r, err := e.Upload(context.Background(), u)
		if err == nil || r.Acknowledgment != nil || r.WriterAcceptedBytes >= u.PayloadBytes || r.GeneratedBytes < r.WriterAcceptedBytes || r.GeneratedBytes > r.WriterAcceptedBytes+(32<<10) {
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
			acknowledge(w, r)
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
			if err != nil || r.Acknowledgment == nil {
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
	sum := sha256.Sum256(payload)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			acknowledge(w, r)
		} else {
			w.Write(payload)
		}
	}))
	defer s.Close()
	e := executor(t, v)
	d := downloadRequest(s, measurement.ExactOutbound)
	d.ExpectedSHA256 = &sum
	if r, err := e.Download(context.Background(), d); err != nil || !r.IntegrityVerified {
		t.Fatalf("VLESS download: %+v %v", r, err)
	}
	if r, err := e.Upload(context.Background(), uploadRequest(s, measurement.ExactOutbound)); err != nil || r.Acknowledgment == nil {
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
		if !errors.Is(err, measurement.ErrTransferTimeout) || r.WriterAcceptedBytes >= u.PayloadBytes || r.Acknowledgment != nil {
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
	if !errors.Is(err, io.ErrUnexpectedEOF) || upload.WriterAcceptedBytes != u.PayloadBytes || upload.HTTPS.BodyComplete || string(upload.HTTPS.Body) != "partial" || upload.Acknowledgment != nil {
		t.Fatalf("partial response: %+v %v", upload, err)
	}
}
