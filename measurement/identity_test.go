package measurement_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport/internet"
)

// Host costs include the local peer/runtime and optional ordinary load.
// Endpoint trust, no reuse/compression, bounds and configuration are matched.
func BenchmarkC5HTTPFactCost(b *testing.B) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		name := "DIRECT"
		if kind == measurement.ExactOutbound {
			name = "ExactFreedom"
		}
		b.Run(name, func(b *testing.B) {
			for _, load := range []bool{false, true} {
				name := "idle"
				if load {
					name = "ordinary-active"
				}
				b.Run(name, func(b *testing.B) {
					for _, mode := range []string{"Combined", "Separate", "NativeHTTP"} {
						b.Run(mode, func(b *testing.B) {
							var calls, payloadBytes, accepts, handshakes atomic.Int64
							body := []byte(`{"ip":"203.0.113.7","country":"ZZ","countrySource":"fixture"}`)
							s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								calls.Add(1)
								if r.TLS != nil && r.TLS.HandshakeComplete {
									handshakes.Add(1)
								}
								w.Header().Set("X-Fact", "fixture")
								n, _ := w.Write(body)
								payloadBytes.Add(int64(n))
							}))
							s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
								if state == http.StateNew {
									accepts.Add(1)
								}
							}
							s.StartTLS()
							b.Cleanup(s.Close)
							v := instance(b)
							e := executor(b, v)
							r := request(s, kind)
							stopLoad := func() {}
							if load {
								stopLoad = c5OrdinaryBenchmarkLoad(b, v, r.Route)
							}
							b.ReportAllocs()
							b.ResetTimer()
							for range b.N {
								var receipt measurement.HTTPSReceipt
								var err error
								if mode == "NativeHTTP" {
									receipt, err = c5NativeHTTP(v, r)
								} else {
									receipt, err = e.HTTPS(context.Background(), r)
								}
								if err != nil || receipt.StatusCode != 200 || receipt.Header.Get("X-Fact") != "fixture" || !bytes.Equal(receipt.Body, body) || !receipt.BodyComplete {
									b.Fatalf("HTTP facts: %+v %v", receipt, err)
								}
								if mode == "Separate" {
									identity, err := e.EgressIdentity(context.Background(), measurement.IdentityRequest{HTTPS: r, Family: measurement.IPv4})
									if err != nil || identity.Address.String() != "203.0.113.7" {
										b.Fatalf("identity: %+v %v", identity, err)
									}
								} else if mode == "Combined" {
									identity, err := measurement.IdentityFromHTTPS(receipt, measurement.IPv4)
									if err != nil || identity.Address.String() != "203.0.113.7" || identity.HTTPS.Elapsed != receipt.Elapsed {
										b.Fatalf("reused identity: %+v %v", identity, err)
									}
								}
							}
							b.StopTimer()
							stopLoad()
							want := int64(b.N)
							if mode == "Separate" {
								want *= 2
							}
							if calls.Load() != want || accepts.Load() != want || handshakes.Load() != want || payloadBytes.Load() != want*int64(len(body)) {
								b.Fatalf("exchange count: requests%d sockets%d TLS%d payload%d expected%d", calls.Load(), accepts.Load(), handshakes.Load(), payloadBytes.Load(), want)
							}
							b.ReportMetric(float64(calls.Load())/float64(b.N), "requests/op")
							b.ReportMetric(float64(accepts.Load())/float64(b.N), "sockets/op")
							b.ReportMetric(float64(handshakes.Load())/float64(b.N), "TLS/op")
							b.ReportMetric(float64(payloadBytes.Load())/float64(b.N), "peer-B/op")
						})
					}
				})
			}
		})
	}
}

func c5NativeHTTP(v *core.Instance, r measurement.HTTPSRequest) (measurement.HTTPSReceipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: r.MaxHeaderBytes, TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper), TLSClientConfig: &tls.Config{RootCAs: r.RootCAs, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}}
	defer transport.CloseIdleConnections()
	transport.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		dest, err := xnet.ParseDestination("tcp:" + address)
		if err != nil {
			return nil, err
		}
		if r.Route.Kind == measurement.Direct {
			return internet.DialSystem(ctx, dest, nil)
		}
		dialCtx := session.ContextWithTrafficOrigin(session.SetForcedOutboundTagToContext(ctx, r.Route.Tag), session.TrafficOriginControlledMeasurement)
		c, err := core.Dial(dialCtx, v, dest)
		if err == nil {
			context.AfterFunc(ctx, func() { c.Close() })
		}
		return c, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return measurement.HTTPSReceipt{}, err
	}
	response, err := transport.RoundTrip(req)
	if err != nil {
		return measurement.HTTPSReceipt{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, r.MaxBodyBytes+1))
	if int64(len(body)) > r.MaxBodyBytes {
		err = measurement.ErrBodyLimit
	}
	return measurement.HTTPSReceipt{StatusCode: response.StatusCode, Header: response.Header, Body: body, BodyBytes: int64(len(body)), BodyComplete: err == nil}, err
}

func c5OrdinaryBenchmarkLoad(b testing.TB, v *core.Instance, route measurement.Route) func() {
	b.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	peer := make(chan net.Conn, 1)
	joined := make(chan struct{})
	announced := make(chan struct{})
	go func() {
		defer close(joined)
		c, err := ln.Accept()
		if err != nil {
			close(announced)
			return
		}
		peer <- c
		close(announced)
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	pc := udpFixture(b, func(pc net.PacketConn, data []byte, a net.Addr) { _, _ = pc.WriteTo(data, a) })
	ctx, cancel := context.WithCancel(context.Background())
	var conns []net.Conn
	var finished chan struct{}
	var loadErr error
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			for _, c := range conns {
				c.Close()
			}
			ln.Close()
			<-announced
			select {
			case c := <-peer:
				c.Close()
			default:
			}
			if finished != nil {
				select {
				case <-finished:
					if loadErr != nil {
						b.Error(loadErr)
					}
				case <-time.After(3 * time.Second):
					b.Error("ordinary load worker retained")
				}
			}
			select {
			case <-joined:
			case <-time.After(3 * time.Second):
				b.Error("ordinary peer retained")
			}
		})
	}
	b.Cleanup(stop)
	for _, address := range []string{"tcp:" + ln.Addr().String(), "udp:" + pc.LocalAddr().String()} {
		dest, err := xnet.ParseDestination(address)
		if err != nil {
			b.Fatal(err)
		}
		var c net.Conn
		if route.Kind == measurement.Direct {
			c, err = net.Dial(dest.Network.SystemString(), dest.NetAddr())
		} else {
			c, err = core.Dial(session.SetForcedOutboundTagToContext(ctx, route.Tag), v, dest)
		}
		if err != nil {
			b.Fatal(err)
		}
		conns = append(conns, c)
	}
	ready := make(chan struct{})
	finished = make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		first := true
		for {
			for _, c := range conns {
				if _, err := c.Write([]byte("load")); err != nil {
					if ctx.Err() == nil {
						loadErr = err
					}
					return
				}
				var data [4]byte
				if _, err := io.ReadFull(c, data[:]); err != nil || string(data[:]) != "load" {
					if ctx.Err() == nil {
						loadErr = errors.Join(err, errors.New("ordinary load mismatch"))
					}
					return
				}
			}
			if first {
				close(ready)
				first = false
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	select {
	case <-ready:
	case <-finished:
		b.Fatal(loadErr)
	case <-time.After(3 * time.Second):
		b.Fatal("ordinary load not active")
	}
	return stop
}

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
