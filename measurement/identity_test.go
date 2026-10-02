package measurement_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/measurement"
)

func reflectorBody(ip string) map[string]any {
	return map[string]any{"ip": ip}
}

func identityRequest(s *httptest.Server, kind measurement.RouteKind, family measurement.AddressFamily) measurement.IdentityRequest {
	return measurement.IdentityRequest{HTTPS: request(s, kind), Family: family}
}

func TestEgressIdentityIPv4IPv6AndOneExchangeReuse(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		for _, family := range []measurement.AddressFamily{measurement.IPv4, measurement.IPv6} {
			var calls atomic.Int32
			address := "203.0.113.7"
			if family == measurement.IPv6 {
				address = "2001:db8::7"
			}
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body := reflectorBody(address)
				body["country"], body["countrySource"] = "ZZ", "fixture-declaration"
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_ = json.NewEncoder(w).Encode(body)
			}))
			e := executor(t, instance(t))
			result, err := e.EgressIdentity(context.Background(), identityRequest(s, kind, family))
			if err != nil || result.Address.String() != address || result.Family != family || result.Country != "ZZ" || result.CountrySource != "fixture-declaration" {
				t.Fatalf("%+v %v", result, err)
			}
			reused, err := measurement.IdentityFromHTTPS(result.HTTPS, family)
			if err != nil || reused.Address != result.Address || calls.Load() != 1 {
				t.Fatalf("duplicate/invalid exchange: %+v %v calls=%d", reused, err, calls.Load())
			}
			s.Close()
		}
	}
}

func TestEgressIdentityCancellationAndNoFallback(t *testing.T) {
	entered := make(chan struct{})
	ended := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(ended); close(entered); <-r.Context().Done() }))
	defer s.Close()
	e := executor(t, instance(t))
	req := identityRequest(s, measurement.ExactOutbound, measurement.IPv4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		r, err := e.EgressIdentity(ctx, req)
		if r.Address.IsValid() {
			t.Error("cancel fabricated address")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("identity operation not active")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("identity cancellation hung")
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("identity connection survived")
	}
	req.HTTPS.Route.Tag = "missing"
	if r, err := e.EgressIdentity(context.Background(), req); err == nil || r.Address.IsValid() {
		t.Fatalf("%+v %v", r, err)
	}
}
