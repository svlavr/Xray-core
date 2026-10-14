package measurement_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/measurement"
)

func TestAuditIdentityActualTLSPartialHTTPErrorPair(t *testing.T) {
	for _, route := range []struct {
		name string
		kind measurement.RouteKind
	}{
		{"DIRECT", measurement.Direct},
		{"EXACT", measurement.ExactOutbound},
	} {
		for _, mode := range []string{"EgressIdentity", "HTTPSReuse"} {
			t.Run(route.name+"/"+mode, func(t *testing.T) {
				// Actual local TLS/HTTP exchange: all JSON bytes arrive, but the
				// declared HTTP length is one byte longer. These are fixture
				// declarations, not evidence of a public egress or country.
				const body = `{"ip":"192.0.2.7","country":"ZZ","countrySource":"local-fixture"}`
				var requests, sockets, tlsRequests atomic.Int32
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.TLS != nil && r.TLS.HandshakeComplete {
						tlsRequests.Add(1)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
					_, _ = io.WriteString(w, body)
				}))
				s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						sockets.Add(1)
					}
				}
				s.StartTLS()
				t.Cleanup(s.Close)
				e := executor(t, instance(t))
				req := request(s, route.kind)

				var identity measurement.IdentityReceipt
				var exchangeErr, parseErr error
				if mode == "EgressIdentity" {
					identity, exchangeErr = e.EgressIdentity(context.Background(), measurement.IdentityRequest{HTTPS: req, Family: measurement.IPv4})
				} else {
					// HTTPS returns a receipt/error pair. The parser can reuse
					// the body, but its nil parse error cannot replace exchangeErr.
					var response measurement.HTTPSReceipt
					response, exchangeErr = e.HTTPS(context.Background(), req)
					identity, parseErr = measurement.IdentityFromHTTPS(response, measurement.IPv4)
					if parseErr != nil {
						t.Fatalf("complete JSON failed reuse: %v", parseErr)
					}
				}
				if !errors.Is(exchangeErr, io.ErrUnexpectedEOF) || errors.Is(exchangeErr, measurement.ErrIdentityResponse) {
					t.Fatalf("HTTP error pair lost: exchange=%v parser=%v", exchangeErr, parseErr)
				}
				if identity.Address != netip.MustParseAddr("192.0.2.7") || identity.Family != measurement.IPv4 || identity.Country != "ZZ" || identity.CountrySource != "local-fixture" {
					t.Fatalf("parsed declaration lost: %+v, exchange=%v", identity, exchangeErr)
				}
				response := identity.HTTPS
				if response.StatusCode != http.StatusOK || string(response.Body) != body || response.BodyBytes != int64(len(body)) || response.BodyComplete {
					t.Fatalf("partial HTTP facts lost: %+v, exchange=%v", response, exchangeErr)
				}
				if response.ContentLength == nil || *response.ContentLength != int64(len(body)+1) || response.EndpointTLS == nil {
					t.Fatalf("actual framing/TLS facts lost: %+v", response)
				}
				if requests.Load() != 1 || sockets.Load() != 1 || tlsRequests.Load() != 1 {
					t.Fatalf("expected one exchange: requests=%d sockets=%d TLS=%d", requests.Load(), sockets.Load(), tlsRequests.Load())
				}
			})
		}
	}
}

func TestAuditIdentityParserMappedIPv4FamilyMismatch(t *testing.T) {
	// Parser-only input. Reported address family says nothing about the
	// carrier family, and this fabricated receipt proves no TLS endpoint.
	response := measurement.HTTPSReceipt{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"ip":"::ffff:192.0.2.7","country":"ZZ","countrySource":"parser-fixture"}`),
	}
	identity, err := measurement.IdentityFromHTTPS(response, measurement.IPv6)
	if !errors.Is(err, measurement.ErrIdentityResponse) {
		t.Fatalf("expected family mismatch, got %v", err)
	}
	if identity.Address != netip.MustParseAddr("192.0.2.7") || !identity.Address.Is4() || identity.Address.Is4In6() || identity.Family != measurement.IPv4 || identity.Country != "ZZ" || identity.CountrySource != "parser-fixture" {
		t.Fatalf("unmapped declaration erased by mismatch: %+v", identity)
	}
	if string(identity.HTTPS.Body) != string(response.Body) || identity.HTTPS.StatusCode != response.StatusCode {
		t.Fatalf("parser input facts changed: %+v", identity.HTTPS)
	}
}

func TestAuditIdentityProviderParserFixtures(t *testing.T) {
	// Documented provider response shapes modeled locally, not live provider
	// calls or authenticated receipts. No provider-specific normalization is
	// requested: only the existing JSON ip/country/countrySource fields apply.
	for _, fixture := range []struct {
		name    string
		body    string
		country string
		wantErr bool
	}{
		{"ipify_JSON_without_country", `{"ip":"192.0.2.7"}`, "", false},
		{"IPinfoLite_full_country_and_separate_code", `{"ip":"192.0.2.7","country":"United States","country_code":"US"}`, "United States", false},
		{"Cloudflare_trace_key_value_is_not_JSON", "fl=fixture\nip=192.0.2.7\nloc=US\n", "", true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			response := measurement.HTTPSReceipt{StatusCode: http.StatusOK, Body: []byte(fixture.body)}
			identity, err := measurement.IdentityFromHTTPS(response, measurement.IPv4)
			if fixture.wantErr {
				if !errors.Is(err, measurement.ErrIdentityResponse) || identity.Address.IsValid() || identity.Family != 0 || identity.Country != "" || identity.CountrySource != "" {
					t.Fatalf("non-JSON input accepted: %+v, %v", identity, err)
				}
			} else if err != nil || identity.Address != netip.MustParseAddr("192.0.2.7") || identity.Family != measurement.IPv4 || identity.Country != fixture.country || identity.CountrySource != "" {
				t.Fatalf("provider-shaped declaration changed: %+v, %v", identity, err)
			}
			if string(identity.HTTPS.Body) != fixture.body || identity.HTTPS.StatusCode != response.StatusCode {
				t.Fatalf("parser input facts changed: %+v", identity.HTTPS)
			}
		})
	}
}
