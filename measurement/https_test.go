package measurement

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestExecuteHTTPSExactOutboundRawReceipt(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusTeapot)
		_, _ = response.Write([]byte("abcdef"))
	}))
	t.Cleanup(server.Close)

	instance := startMeasurementCore(t, "node-test")
	tracked := instance.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	if err := tracked.EnableConnectionTracking(8); err != nil {
		t.Fatal(err)
	}
	receipt, err := executeHTTPS(context.Background(), instance, HTTPSRequest{
		URL:                  server.URL,
		OutboundTag:          "node-test",
		Timeout:              2 * time.Second,
		MaxResponseBodyBytes: 5,
	}, testTLSConfig(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != OutcomeSucceeded || receipt.FailureStage != FailureNone {
		t.Fatalf("outcome = %+v", receipt)
	}
	if receipt.SelectedOutbound != "node-test" {
		t.Fatalf("selected outbound = %q", receipt.SelectedOutbound)
	}
	if receipt.Response == nil || receipt.Response.StatusCode != http.StatusTeapot || receipt.Response.Protocol != "HTTP/1.1" {
		t.Fatalf("response = %+v", receipt.Response)
	}
	if string(receipt.Response.Body) != "abcde" || !receipt.Response.BodyTruncated || receipt.Response.ResponseBodyBytesObserved != 6 {
		t.Fatalf("body = %+v", receipt.Response)
	}
	if !receipt.Timing.TLSHandshakeObserved || !receipt.Timing.TTFBObserved || receipt.Timing.Total <= 0 {
		t.Fatalf("timing = %+v", receipt.Timing)
	}
	if receipt.Cleanup != CleanupConnectionClosed {
		t.Fatalf("cleanup = %q", receipt.Cleanup)
	}
	if snapshot := tracked.ConnectionSnapshot(); len(snapshot.Connections) != 0 || len(snapshot.OutboundTotals) != 0 {
		t.Fatalf("measurement contaminated USER totals: %+v", snapshot)
	}
}

func TestExecuteHTTPSMissingExactOutboundDoesNotReachEndpoint(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)

	instance := startMeasurementCore(t, "available")
	receipt, err := executeHTTPS(context.Background(), instance, HTTPSRequest{
		URL:                  server.URL,
		OutboundTag:          "missing",
		Timeout:              time.Second,
		MaxResponseBodyBytes: 1024,
	}, testTLSConfig(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != OutcomeFailed || receipt.FailureStage != FailureExactSelect || receipt.SelectedOutbound != "" {
		t.Fatalf("receipt = %+v", receipt)
	}
	if calls.Load() != 0 {
		t.Fatalf("endpoint calls = %d", calls.Load())
	}
	if receipt.Cleanup != CleanupConnectionClosed {
		t.Fatalf("cleanup = %q", receipt.Cleanup)
	}
}

func TestExecuteHTTPSDeadlineIsRawFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	instance := startMeasurementCore(t, "node-test")
	receipt, err := executeHTTPS(context.Background(), instance, HTTPSRequest{
		URL:                  server.URL,
		OutboundTag:          "node-test",
		Timeout:              50 * time.Millisecond,
		MaxResponseBodyBytes: 1024,
	}, testTLSConfig(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != OutcomeDeadlineExceeded || receipt.FailureStage != FailureResponseHeaders {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.SelectedOutbound != "node-test" {
		t.Fatalf("selected outbound = %q", receipt.SelectedOutbound)
	}
	if receipt.Cleanup != CleanupConnectionClosed {
		t.Fatalf("cleanup = %q", receipt.Cleanup)
	}
}

func TestExecuteHTTPSCallerCancellationIsRawFailure(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)
	instance := startMeasurementCore(t, "node-test")
	tlsConfig := testTLSConfig(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan *HTTPSReceipt, 1)
	go func() {
		receipt, _ := executeHTTPS(ctx, instance, HTTPSRequest{
			URL:                  server.URL,
			OutboundTag:          "node-test",
			Timeout:              2 * time.Second,
			MaxResponseBodyBytes: 1024,
		}, tlsConfig)
		result <- receipt
	}()
	<-started
	cancel()
	receipt := <-result
	if receipt.Outcome != OutcomeCancelled || receipt.FailureStage != FailureResponseHeaders {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.SelectedOutbound != "node-test" || receipt.Cleanup != CleanupConnectionClosed {
		t.Fatalf("route/cleanup = %+v", receipt)
	}
}

func TestExecuteHTTPSPartialBodyFailureIsRaw(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Length", "2")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("x"))
	}))
	t.Cleanup(server.Close)
	instance := startMeasurementCore(t, "node-test")
	receipt, err := executeHTTPS(context.Background(), instance, HTTPSRequest{
		URL:                  server.URL,
		OutboundTag:          "node-test",
		Timeout:              2 * time.Second,
		MaxResponseBodyBytes: 1024,
	}, testTLSConfig(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != OutcomeFailed || receipt.FailureStage != FailureResponseBody {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.SelectedOutbound != "node-test" || receipt.Cleanup != CleanupConnectionClosed {
		t.Fatalf("route/cleanup = %+v", receipt)
	}
}

func TestExecuteHTTPSTLSFailurePreservesSelectedRoute(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	instance := startMeasurementCore(t, "node-test")

	receipt, err := ExecuteHTTPS(context.Background(), instance, HTTPSRequest{
		URL:                  server.URL,
		OutboundTag:          "node-test",
		Timeout:              2 * time.Second,
		MaxResponseBodyBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != OutcomeFailed || receipt.FailureStage != FailureEndpointTLS {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.SelectedOutbound != "node-test" || receipt.Cleanup != CleanupConnectionClosed {
		t.Fatalf("route/cleanup = %+v", receipt)
	}
}

func TestExecuteHTTPSConcurrentReceiptsStayRequestScoped(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	instance := startMeasurementCore(t, "node-test")
	tlsConfig := testTLSConfig(t, server)

	const operations = 12
	var wait sync.WaitGroup
	errors := make(chan error, operations)
	for range operations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := executeHTTPS(context.Background(), instance, HTTPSRequest{
				URL:                  server.URL,
				OutboundTag:          "node-test",
				Timeout:              2 * time.Second,
				MaxResponseBodyBytes: 16,
			}, tlsConfig.Clone())
			if err != nil {
				errors <- err
				return
			}
			if receipt.Outcome != OutcomeSucceeded || receipt.SelectedOutbound != "node-test" {
				errors <- fmt.Errorf("unexpected receipt: %+v", receipt)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestExecuteHTTPSRejectsInvalidRequestBeforeNetwork(t *testing.T) {
	instance := startMeasurementCore(t, "node-test")
	tests := []HTTPSRequest{
		{URL: "http://example.com", OutboundTag: "node-test", Timeout: time.Second, MaxResponseBodyBytes: 1},
		{URL: "https://example.com", OutboundTag: "", Timeout: time.Second, MaxResponseBodyBytes: 1},
		{URL: "https://example.com", OutboundTag: "node-test", Timeout: 0, MaxResponseBodyBytes: 1},
		{URL: "https://example.com", OutboundTag: "node-test", Timeout: time.Second, MaxResponseBodyBytes: maxResponseBodyBytes + 1},
	}
	for _, request := range tests {
		if receipt, err := ExecuteHTTPS(context.Background(), instance, request); err == nil || receipt != nil {
			t.Fatalf("invalid request returned receipt=%+v err=%v", receipt, err)
		}
	}
}

func startMeasurementCore(t *testing.T, outboundTag string) *core.Instance {
	t.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: outboundTag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close core: %v", err)
		}
	})
	return instance
}

func testTLSConfig(t *testing.T, server *httptest.Server) *tls.Config {
	t.Helper()
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("test server TLS config is unavailable")
	}
	return transport.TLSClientConfig.Clone()
}
