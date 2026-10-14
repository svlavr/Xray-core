package measurement_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

var auditHTTPReadSentinel = errors.New("audit HTTP in-memory read sentinel")

// Returning a connection successfully avoids Freedom's dial-error retry path.
// Reads fail immediately and writes are accepted, without creating any socket.
type auditHTTPMemoryConn struct{}

func (*auditHTTPMemoryConn) Read([]byte) (int, error)    { return 0, auditHTTPReadSentinel }
func (*auditHTTPMemoryConn) Write(p []byte) (int, error) { return len(p), nil }
func (*auditHTTPMemoryConn) Close() error                { return nil }
func (*auditHTTPMemoryConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (*auditHTTPMemoryConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80}
}
func (*auditHTTPMemoryConn) SetDeadline(time.Time) error      { return nil }
func (*auditHTTPMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*auditHTTPMemoryConn) SetWriteDeadline(time.Time) error { return nil }

type auditHTTPGatedConn struct {
	auditHTTPMemoryConn
	readStarted chan struct{}
	released    chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func (c *auditHTTPGatedConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.released
	return 0, auditHTTPReadSentinel
}
func (c *auditHTTPGatedConn) Close() error {
	c.closeOnce.Do(func() { close(c.released) })
	return nil
}

type auditHTTPRecordingDialer struct {
	mu           sync.Mutex
	destinations []xnet.Destination
	occupied     *auditHTTPGatedConn
}

func (d *auditHTTPRecordingDialer) Dial(_ context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	d.mu.Lock()
	d.destinations = append(d.destinations, dest)
	d.mu.Unlock()
	if d.occupied != nil && dest.Address.String() == "occupied.invalid" {
		return d.occupied, nil
	}
	return &auditHTTPMemoryConn{}, nil
}
func (*auditHTTPRecordingDialer) DestIpAddress() xnet.IP { return nil }
func (d *auditHTTPRecordingDialer) snapshot() []xnet.Destination {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]xnet.Destination(nil), d.destinations...)
}

func auditHTTPExecutor(t *testing.T) *measurement.Executor {
	t.Helper()
	// No final rules: domain controls must not invoke Freedom's DNS pre-check.
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:            "audit-http-exact",
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			ProxySettings:  serial.ToTypedMessage(&freedom.Config{}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	e, err := measurement.New(v, 1)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func auditHTTPRequest(rawURL string, kind measurement.RouteKind) measurement.HTTPRequest {
	r := measurement.HTTPRequest{
		URL: rawURL, Route: measurement.Route{Kind: kind},
		Timeout: time.Second, MaxBodyBytes: 1, MaxHeaderBytes: 1024,
	}
	if kind == measurement.ExactOutbound {
		r.Route.Tag = "audit-http-exact"
	}
	return r
}

func TestAuditHTTPEmptyHostRejectedBeforeDial(t *testing.T) {
	if isolatedSystemDialer(t, 20*time.Second) {
		return
	}
	d := &auditHTTPRecordingDialer{}
	internet.UseAlternativeSystemDialer(d)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
	e := auditHTTPExecutor(t)
	for _, route := range []struct {
		name string
		kind measurement.RouteKind
	}{{"direct", measurement.Direct}, {"exact", measurement.ExactOutbound}} {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range []struct{ name, url string }{
				// RFC 9110 sections 4.2.1 and 4.2.2 require a nonempty host.
				// These assertions intentionally fail if :port becomes 0.0.0.0.
				{"http_empty_host_with_port", "http://:80/"},
				{"https_empty_host_with_port", "https://:443/"},
				{"http_absent_host", "http:///path"},
				{"https_absent_host", "https:///path"},
				{"http_opaque", "http:opaque"},
				{"https_opaque", "https:opaque"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := len(d.snapshot())
					r, err := e.HTTP(context.Background(), http.MethodGet, auditHTTPRequest(tc.url, route.kind))
					calls := d.snapshot()[before:]
					t.Logf("URL %q: destinations=%v receipt=%+v error=%v", tc.url, calls, r, err)
					if err == nil || len(calls) != 0 {
						t.Fatalf("URL %q must reject before native dial: destinations=%v receipt=%+v error=%v", tc.url, calls, r, err)
					}
				})
			}
		})
	}
}

func TestAuditHTTPPortOnlyURLRejectsBeforeQueuedAdmission(t *testing.T) {
	if isolatedSystemDialer(t, 20*time.Second) {
		return
	}
	gate := &auditHTTPGatedConn{readStarted: make(chan struct{}), released: make(chan struct{})}
	d := &auditHTTPRecordingDialer{occupied: gate}
	internet.UseAlternativeSystemDialer(d)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
	e := auditHTTPExecutor(t)
	occupied := auditHTTPRequest("http://occupied.invalid/", measurement.Direct)
	occupied.Timeout = 5 * time.Second
	done := make(chan error, 1)
	go func() {
		_, err := e.HTTP(context.Background(), http.MethodHead, occupied)
		done <- err
	}()
	t.Cleanup(func() {
		_ = gate.Close()
		select {
		case err := <-done:
			if !errors.Is(err, auditHTTPReadSentinel) {
				t.Errorf("occupied request did not preserve released read sentinel: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("occupied request did not join after gate release")
		}
	})
	select {
	case <-gate.readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("occupied request did not enter gated read")
	}
	initial := d.snapshot()
	if len(initial) != 1 || initial[0].Address.String() != "occupied.invalid" {
		t.Fatalf("unexpected occupying native destination: %v", initial)
	}
	// A channel-observed active read holds the sole Executor slot. Validation
	// must reject port-only authorities before queuing for that slot. No elapsed
	// duration certifies admission or socket creation in this fixture.
	for _, route := range []struct {
		name string
		kind measurement.RouteKind
	}{{"direct", measurement.Direct}, {"exact", measurement.ExactOutbound}} {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range []struct{ name, url string }{
				{"http", "http://:80/"},
				{"https", "https://:443/"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					q := auditHTTPRequest(tc.url, route.kind)
					q.Timeout = 25 * time.Millisecond
					before := len(d.snapshot())
					r, err := e.HTTP(context.Background(), http.MethodGet, q)
					calls := d.snapshot()[before:]
					t.Logf("queued URL %q: added destinations=%v receipt=%+v error=%v", tc.url, calls, r, err)
					select {
					case <-gate.released:
						t.Fatal("occupying connection released before queued assertion")
					default:
					}
					if err == nil || errors.Is(err, context.DeadlineExceeded) || len(calls) != 0 {
						t.Fatalf("URL %q must reject before queued admission: added destinations=%v receipt=%+v error=%v", tc.url, calls, r, err)
					}
				})
			}
		})
	}
}

func TestAuditHTTPValidURLNativeDestinationAndError(t *testing.T) {
	if isolatedSystemDialer(t, 20*time.Second) {
		return
	}
	d := &auditHTTPRecordingDialer{}
	internet.UseAlternativeSystemDialer(d)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
	e := auditHTTPExecutor(t)
	for _, route := range []struct {
		name string
		kind measurement.RouteKind
	}{{"direct", measurement.Direct}, {"exact", measurement.ExactOutbound}} {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, url, host string
				port            xnet.Port
			}{
				{"http_domain_default", "http://example.invalid/", "example.invalid", 80},
				{"https_domain_default", "https://example.invalid/", "example.invalid", 443},
				{"http_case_explicit", "HTTP://EXAMPLE.invalid:8080/", "EXAMPLE.invalid", 8080},
				{"https_case_explicit", "HTTPS://EXAMPLE.invalid:8443/", "EXAMPLE.invalid", 8443},
				{"http_ipv4_default", "http://192.0.2.9/", "192.0.2.9", 80},
				{"https_ipv4_default", "https://192.0.2.9/", "192.0.2.9", 443},
				{"http_ipv4_explicit", "http://192.0.2.9:8080/", "192.0.2.9", 8080},
				{"https_ipv4_explicit", "https://192.0.2.9:8443/", "192.0.2.9", 8443},
				{"http_ipv6_default", "http://[2001:db8::9]/", "2001:db8::9", 80},
				{"https_ipv6_default", "https://[2001:db8::9]/", "2001:db8::9", 443},
				{"http_ipv6_explicit", "http://[2001:db8::9]:8080/", "2001:db8::9", 8080},
				{"https_ipv6_explicit", "https://[2001:db8::9]:8443/", "2001:db8::9", 8443},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := len(d.snapshot())
					r, err := e.HTTP(context.Background(), http.MethodGet, auditHTTPRequest(tc.url, route.kind))
					calls := d.snapshot()[before:]
					want := xnet.TCPDestination(xnet.ParseAddress(tc.host), tc.port)
					t.Logf("URL %q: destinations=%v receipt=%+v error=%v", tc.url, calls, r, err)
					if len(calls) != 1 || calls[0].Network != want.Network || calls[0].Port != want.Port || calls[0].Address.String() != want.Address.String() {
						t.Fatalf("URL %q: native destinations=%v want=%v receipt=%+v error=%v", tc.url, calls, want, r, err)
					}
					// Exact feedback is a finalization snapshot. The pipe-facing
					// HTTP/TLS error need not contain the native read sentinel.
					if err == nil || route.kind == measurement.Direct && !errors.Is(err, auditHTTPReadSentinel) {
						t.Fatalf("URL %q: native read sentinel lost: receipt=%+v error=%v", tc.url, r, err)
					}
				})
			}
		})
	}
}
