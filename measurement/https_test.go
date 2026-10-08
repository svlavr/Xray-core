package measurement_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	native "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	policyfeature "github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	statsfeature "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func config(tag string, blocked bool) *core.OutboundHandlerConfig {
	proxy := serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})
	if blocked {
		proxy = serial.ToTypedMessage(&blackhole.Config{})
	}
	return &core.OutboundHandlerConfig{Tag: tag, SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: proxy}
}

func instance(t testing.TB, apps ...*serial.TypedMessage) *core.Instance {
	t.Helper()
	c := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{Level: map[uint32]*policy.Policy{0: {Stats: &policy.Policy_Stats{UserUplink: true, UserDownlink: true}}}, System: &policy.SystemPolicy{Stats: &policy.SystemPolicy_Stats{OutboundUplink: true, OutboundDownlink: true}}}),
		},
		Outbound: []*core.OutboundHandlerConfig{config("trap", true), config("exact", false)},
	}
	c.App = append(c.App, apps...)
	v, err := core.New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	return v
}

func request(server *httptest.Server, kind measurement.RouteKind) measurement.HTTPSRequest {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	r := measurement.HTTPSRequest{URL: server.URL, Route: measurement.Route{Kind: kind}, Timeout: 3 * time.Second, MaxBodyBytes: 1024, MaxHeaderBytes: 4096, RootCAs: pool}
	if kind == measurement.ExactOutbound {
		r.Route.Tag = "exact"
	}
	return r
}

func executor(t testing.TB, v *core.Instance) *measurement.Executor {
	t.Helper()
	e, err := measurement.New(v, 8)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestHTTPSDirectExactAndOrdinaryContinuity(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected decompression negotiation")
		}
		w.Header().Set("X-Fact", "raw")
		io.WriteString(w, "payload")
	}))
	defer s.Close()
	v := instance(t)
	e := executor(t, v)
	content := &session.Content{Attributes: map[string]string{"forcedOutboundTag": "trap"}}
	inbound := &session.Inbound{User: &protocol.MemoryUser{Email: "ordinary"}}
	ctx := session.ContextWithContent(context.Background(), content)
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		r, err := e.HTTPS(ctx, request(s, kind))
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 200 || string(r.Body) != "payload" || r.BodyBytes != 7 || !r.BodyComplete || r.Header.Get("X-Fact") != "raw" || r.EndpointTLS == nil || r.FirstByteElapsed == nil {
			t.Fatalf("incomplete raw response: %+v", r)
		}

	}
	if content.Attribute("forcedOutboundTag") != "trap" || inbound.User.Email != "ordinary" || session.TrafficOriginFromContext(ctx) != session.TrafficOriginUser {
		t.Fatal("caller context changed")
	}
	sm := v.GetFeature(statsfeature.ManagerType()).(statsfeature.Manager)
	if sm.GetCounter("user>>>ordinary>>>traffic>>>uplink") != nil || sm.GetCounter("user>>>ordinary>>>traffic>>>downlink") != nil {
		t.Fatal("measurement entered native user counters")
	}
	if sm.GetCounter("outbound>>>exact>>>traffic>>>uplink").Value() == 0 {
		t.Fatal("native mixed-origin outbound counter omitted traffic")
	}
	// A caller-owned ordinary session remains functional after both operations.
	dest, _ := xnet.ParseDestination("tcp:" + strings.TrimPrefix(s.URL, "https://"))
	ordinaryCtx := session.ContextWithContent(context.Background(), &session.Content{})
	ordinaryCtx = session.SetForcedOutboundTagToContext(ordinaryCtx, "exact")
	conn, err := core.Dial(ordinaryCtx, v, dest)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // Local fixture only.
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsConn, "GET /ordinary HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(tlsConn); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("requests = %d", calls.Load())
	}
}

func TestHTTPSBoundsPartialRedirectAndNoRetry(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		for _, mode := range []string{"body", "headers", "partial", "redirect", "compression"} {
			t.Run(fmt.Sprintf("%d/%s", kind, mode), func(t *testing.T) {
				var calls atomic.Int32
				s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if mode == "headers" {
						w.Header().Set("X-Large", strings.Repeat("h", 8192))
					}
					if mode == "partial" {
						w.Header().Set("Content-Length", "30")
					}
					if mode == "redirect" {
						w.Header().Set("Location", "/again")
						w.WriteHeader(302)
					}
					if mode == "compression" {
						w.Header().Set("Content-Encoding", "gzip")
					}
					io.WriteString(w, "0123456789")
				}))
				defer s.Close()
				e := executor(t, instance(t))
				req := request(s, kind)
				if mode == "body" {
					req.MaxBodyBytes = 4
				}
				r, err := e.HTTPS(context.Background(), req)
				switch mode {
				case "body":
					if !errors.Is(err, measurement.ErrBodyLimit) || string(r.Body) != "0123" || r.BodyComplete {
						t.Fatalf("%+v %v", r, err)
					}
				case "headers":
					if err == nil || r.StatusCode != 0 {
						t.Fatalf("%+v %v", r, err)
					}
				case "partial":
					if !errors.Is(err, io.ErrUnexpectedEOF) || r.BodyBytes != 10 || r.BodyComplete {
						t.Fatalf("%+v %v", r, err)
					}
				case "redirect":
					if err != nil || r.StatusCode != 302 {
						t.Fatalf("%+v %v", r, err)
					}
				case "compression":
					if err != nil || string(r.Body) != "0123456789" {
						t.Fatalf("%+v %v", r, err)
					}
				}
				if calls.Load() != 1 {
					t.Fatalf("repeated request: %d", calls.Load())
				}
			})
		}
	}
}

func TestHTTPSCancellationHeadersBodyAndBudget(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		for _, phase := range []string{"headers", "body", "deadline"} {
			t.Run(fmt.Sprintf("%d/%s", kind, phase), func(t *testing.T) {
				entered, ended := make(chan struct{}), make(chan struct{})
				s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(ended)
					if phase == "body" {
						io.WriteString(w, "part")
						w.(http.Flusher).Flush()
					}
					close(entered)
					<-r.Context().Done()
				}))
				defer s.Close()
				e := executor(t, instance(t))
				req := request(s, kind)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if phase == "deadline" {
					req.Timeout = 200 * time.Millisecond
				}
				done := make(chan struct{})
				var result measurement.HTTPSReceipt
				var resultErr error
				go func() { result, resultErr = e.HTTPS(ctx, req); close(done) }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("request never reached endpoint")
				}
				if phase != "deadline" {
					if phase == "body" {
						// Allow the flushed prefix to be consumed before interrupting
						// the stalled remaining body, rather than racing header parsing.
						time.AfterFunc(50*time.Millisecond, cancel)
					} else {
						cancel()
					}
				}
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("cancel did not stop operation")
				}
				want := context.Canceled
				if phase == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(resultErr, want) {
					t.Fatalf("%+v %v", result, resultErr)
				}
				if phase == "body" && string(result.Body) != "part" {
					t.Fatalf("partial body lost: %+v", result)
				}
				select {
				case <-ended:
				case <-time.After(2 * time.Second):
					t.Fatal("endpoint resource survived cancellation")
				}
			})
		}
	}
}

func TestHTTPSPreCanceledMissingAndBadTrust(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer s.Close()
	e := executor(t, instance(t))
	req := request(s, measurement.ExactOutbound)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.HTTPS(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	req.Route.Tag = "absent"
	if _, err := e.HTTPS(context.Background(), req); err == nil {
		t.Fatal(err)
	}
	req.Route.Tag = "exact"
	req.RootCAs = x509.NewCertPool()
	r, err := e.HTTPS(context.Background(), req)
	if err == nil || r.EndpointTLS == nil || r.StatusCode != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP happened on rejected path")
	}
}

func TestHTTPSConcurrentRequests(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.URL.Path) }))
	defer s.Close()
	e := executor(t, instance(t))
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := request(s, measurement.ExactOutbound)
			req.URL += fmt.Sprintf("/%d", i)
			r, err := e.HTTPS(context.Background(), req)
			if err != nil || string(r.Body) != fmt.Sprintf("/%d", i) {
				t.Errorf("cross-talk: %+v %v", r, err)
			}
		}()
	}
	wg.Wait()
}

// Gate the native manager's actual lookup to reproduce remove/add between
// preliminary admission and selection, without a production test hook.
type gatedManager struct {
	outbound.Manager
	mu               sync.Mutex
	calls            int
	entered, release chan struct{}
}

func (m *gatedManager) GetHandler(tag string) outbound.Handler {
	m.mu.Lock()
	m.calls++
	gate := m.calls == 1
	m.mu.Unlock()
	if gate {
		close(m.entered)
		<-m.release
	}
	return m.Manager.GetHandler(tag)
}

func gatedInstance(t *testing.T) (*core.Instance, *gatedManager) {
	t.Helper()
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := native.New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	g := &gatedManager{Manager: m, entered: make(chan struct{}), release: make(chan struct{})}
	if err := v.AddFeature(g); err != nil {
		t.Fatal(err)
	}
	d := new(dispatcher.DefaultDispatcher)
	if err := d.Init(&dispatcher.Config{}, g, routing.DefaultRouter{}, policyfeature.DefaultManager{}, statsfeature.NoopManager{}); err != nil {
		t.Fatal(err)
	}
	if err := v.AddFeature(d); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []*core.OutboundHandlerConfig{config("trap", true), config("exact", false), config("second", false)} {
		if err := core.AddOutboundHandler(v, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	return v, g
}

func TestHTTPSRemovalReplacementAndCancelDuringSelection(t *testing.T) {
	for _, mode := range []string{"remove", "replace", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer s.Close()
			v, g := gatedInstance(t)
			e := executor(t, v)
			req := request(s, measurement.ExactOutbound)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type outcome struct {
				receipt measurement.HTTPSReceipt
				err     error
			}
			done := make(chan outcome, 1)
			go func() { receipt, err := e.HTTPS(ctx, req); done <- outcome{receipt, err} }()
			select {
			case <-g.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("selection not reached")
			}
			if mode == "cancel" {
				cancel()
			} else if mode == "close" {
				if err := g.Manager.GetHandler("exact").Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := g.RemoveHandler(context.Background(), "exact"); err != nil {
					t.Fatal(err)
				}
				if mode == "replace" {
					if err := core.AddOutboundHandler(v, config("exact", false)); err != nil {
						t.Fatal(err)
					}
				}
			}
			close(g.release)
			select {
			case got := <-done:
				if mode == "replace" || mode == "close" {
					if got.err != nil || got.receipt.StatusCode != 200 {
						t.Fatalf("native replacement: %+v", got)
					}
				} else if got.err == nil {
					t.Fatal("removed/canceled route succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("selection failure hung")
			}
			wantCalls := int32(0)
			if mode == "replace" || mode == "close" {
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Fatalf("native selection calls=%d want=%d", calls.Load(), wantCalls)
			}
			for _, route := range []measurement.Route{{Kind: measurement.ExactOutbound, Tag: "second"}, {Kind: measurement.Direct}} {
				control := request(s, route.Kind)
				control.Route = route
				if got, err := e.HTTPS(context.Background(), control); err != nil || got.StatusCode != 200 {
					t.Fatalf("pending %s affected control %+v %v", mode, got, err)
				}
			}
		})
	}
}

func TestHTTPSTLSStallCancellation(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted := make(chan struct{})
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				close(accepted)
				_, _ = io.Copy(io.Discard, conn)
			}()
			e := executor(t, instance(t))
			req := measurement.HTTPSRequest{URL: "https://" + ln.Addr().String(), Route: measurement.Route{Kind: kind}, Timeout: time.Second, MaxBodyBytes: 32, MaxHeaderBytes: 1024}
			if kind == measurement.ExactOutbound {
				req.Route.Tag = "exact"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := e.HTTPS(ctx, req); done <- err }()
			select {
			case <-accepted:
			case <-time.After(time.Second):
				t.Fatal("TLS not entered")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("TLS cancellation hung")
			}
			select {
			case <-ended:
			case <-time.After(2 * time.Second):
				t.Fatal("TLS socket leaked")
			}
		})
	}
}

type originDialer struct {
	t      *testing.T
	native internet.DefaultSystemDialer
	calls  atomic.Int32
}

func (d *originDialer) Dial(ctx context.Context, source xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	if session.TrafficOriginFromContext(ctx) != session.TrafficOriginControlledMeasurement {
		d.t.Error("measurement origin missing at native socket owner")
	}
	if in := session.InboundFromContext(ctx); in == nil || in.User != nil {
		d.t.Error("inherited user admission")
	}
	if session.TimeoutOnlyFromContext(ctx) {
		d.t.Error("inherited detached cancellation")
	}
	d.calls.Add(1)
	return d.native.Dial(ctx, source, dest, sockopt)
}
func (*originDialer) DestIpAddress() xnet.IP { return nil }

// Native dialer replacement requires no concurrent readers. A separate test
// process keeps earlier native outbound workers outside this fixture's owner.
func isolatedSystemDialer(t *testing.T, timeouts ...time.Duration) bool {
	t.Helper()
	const key = "XRAY_MEASUREMENT_DIALER_TEST"
	if os.Getenv(key) == t.Name() {
		return false
	}
	timeout := 20 * time.Second
	if len(timeouts) != 0 {
		timeout = timeouts[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()
	args := []string{"-test.run=^" + t.Name() + "$", "-test.count=1", "-test.timeout=" + timeout.String()}
	if len(timeouts) != 0 {
		args = append(args, "-test.v")
	}
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), key+"="+t.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated system dialer fixture: %v\n%s", err, output)
	} else if len(timeouts) != 0 {
		t.Logf("isolated evidence:\n%s", output)
	}
	return true
}

func TestHTTPSOriginAtSocketOwner(t *testing.T) {
	if isolatedSystemDialer(t) {
		return
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer s.Close()
	e := executor(t, instance(t))
	dialer := &originDialer{t: t}
	internet.UseAlternativeSystemDialer(dialer)
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		if _, err := e.HTTPS(context.Background(), request(s, kind)); err != nil {
			t.Fatal(err)
		}
	}
	if dialer.calls.Load() != 2 {
		t.Fatal("missing independent socket evidence")
	}
}

func TestHTTPSAdmissionCeilingAndQueueCancellation(t *testing.T) {
	entered := make(chan struct{}, 8)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer s.Close()
	e := executor(t, instance(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.HTTPS(ctx, request(s, measurement.ExactOutbound))
			if !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		}()
	}
	for range 8 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("active request missing")
		}
	}
	ninth := request(s, measurement.Direct)
	ninth.Timeout = 50 * time.Millisecond
	if _, err := e.HTTPS(context.Background(), ninth); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-entered:
		t.Fatal("ninth request reached network")
	default:
	}
	cancel()
	wg.Wait()
	if _, err := e.HTTPS(context.Background(), func() measurement.HTTPSRequest {
		r := request(s, measurement.Direct)
		r.Timeout = 50 * time.Millisecond
		return r
	}()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

// The counting relay independently proves an EXACT request crosses a real
// simple VLESS RAW/TCP peer; DIRECT must produce no relay connection.
func TestHTTPSExactVLESSAndDirectBypass(t *testing.T) {
	var endpointCalls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { endpointCalls.Add(1); io.WriteString(w, "vless-fact") }))
	defer s.Close()
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
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var sessions atomic.Int32
	var relayWG sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			sessions.Add(1)
			relayWG.Add(1)
			go func() {
				defer relayWG.Done()
				defer client.Close()
				target, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port.String()))
				if err != nil {
					return
				}
				defer target.Close()
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(target, client); target.Close(); close(copied) }()
				_, _ = io.Copy(client, target)
				client.Close()
				target.Close()
				<-copied
			}()
		}
	}()
	defer func() {
		ln.Close()
		<-acceptDone
		done := make(chan struct{})
		go func() { relayWG.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("relay connections survived operation cleanup")
		}
	}()
	v := instance(t)
	manager := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := manager.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	relayAddr := ln.Addr().(*net.TCPAddr)
	if err := core.AddOutboundHandler(v, &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(relayAddr.Port), User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"})}}})}); err != nil {
		t.Fatal(err)
	}
	e := executor(t, v)
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		r, err := e.HTTPS(context.Background(), request(s, kind))
		if err != nil || string(r.Body) != "vless-fact" {
			t.Fatalf("%+v %v", r, err)
		}
		want := int32(0)
		if kind == measurement.ExactOutbound {
			want = 1
		}
		if sessions.Load() != want {
			t.Fatalf("wrong physical route: %d", sessions.Load())
		}
	}
	if endpointCalls.Load() != 2 {
		t.Fatalf("endpoint calls=%d", endpointCalls.Load())
	}
}

func TestHTTPSDoesNotInheritHeaderBudgetChangingTrace(t *testing.T) {
	var callbacks atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Informational", strings.Repeat("i", 250))
		for range 6 {
			w.WriteHeader(http.StatusEarlyHints)
		}
		w.Header().Del("X-Informational")
		io.WriteString(w, "final")
	}))
	defer s.Close()
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{Got1xxResponse: func(int, textproto.MIMEHeader) error { callbacks.Add(1); return nil }})
	req := request(s, measurement.Direct)
	req.MaxHeaderBytes = 1024
	if r, err := executor(t, instance(t)).HTTPS(ctx, req); err == nil || r.BodyComplete {
		t.Fatalf("aggregate informational headers escaped limit: %+v %v", r, err)
	}
	if callbacks.Load() != 0 {
		t.Fatal("inherited trace received measurement callbacks")
	}
}

func TestHTTPSCancelPreservesAlreadyActiveOrdinaryConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	v := instance(t)
	e := executor(t, v)
	dest, _ := xnet.ParseDestination("tcp:" + ln.Addr().String())
	ctx := session.ContextWithContent(context.Background(), &session.Content{})
	ctx = session.SetForcedOutboundTagToContext(ctx, "exact")
	ordinary, err := core.Dial(ctx, v, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	verify := func() {
		t.Helper()
		if _, err := ordinary.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		bytes := make([]byte, 5)
		if _, err := io.ReadFull(ordinary, bytes); err != nil || string(bytes) != "alive" {
			t.Fatalf("ordinary sibling: %q %v", bytes, err)
		}
	}
	verify()
	entered := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer s.Close()
	measurementCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.HTTPS(measurementCtx, request(s, measurement.ExactOutbound)); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("measurement not active")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("measurement did not cancel")
	}
	verify()
	ordinary.Close()
	select {
	case <-echoDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary socket did not close")
	}
}

type stalledDialer struct {
	entered chan struct{}
	release chan struct{}
	native  internet.DefaultSystemDialer
}

func (d *stalledDialer) Dial(ctx context.Context, source xnet.Address, dest xnet.Destination, opts *internet.SocketConfig) (net.Conn, error) {
	d.entered <- struct{}{}
	<-d.release
	// The test adapter deliberately ignores cancellation during open. Once it
	// resumes, delegate the cancelled context: there must be no late socket.
	return d.native.Dial(ctx, source, dest, opts)
}
func (*stalledDialer) DestIpAddress() xnet.IP { return nil }

func TestHTTPProbeMethodsSchemesAndRoutes(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		start := httptest.NewServer
		if useTLS {
			start = httptest.NewTLSServer
		}
		methods := make(chan string, 8)
		s := start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			methods <- r.Method
			w.Header().Set("Content-Length", "7")
			w.Header().Set("X-Fact", "raw")
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "payload")
			}
		}))
		func() {
			defer s.Close()
			e := executor(t, instance(t))
			for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
				for _, method := range []string{http.MethodHead, http.MethodGet} {
					r := measurement.HTTPRequest{Route: measurement.Route{Kind: kind}, URL: s.URL, Timeout: time.Second, MaxBodyBytes: 8, MaxHeaderBytes: 4096}
					if kind == measurement.ExactOutbound {
						r.Route.Tag = "exact"
					}
					if useTLS {
						r.RootCAs = x509.NewCertPool()
						r.RootCAs.AddCert(s.Certificate())
					}
					if method == http.MethodHead {
						r.MaxBodyBytes = 0
					}
					got, err := e.HTTP(context.Background(), method, r)
					if err != nil || got.StatusCode != 200 || got.Header.Get("X-Fact") != "raw" || got.Header.Get("Content-Length") != "7" || !got.BodyComplete || got.FirstByteElapsed == nil || (got.EndpointTLS != nil) != useTLS {
						t.Fatalf("HTTP probe TLS=%v method=%s route=%v: %+v, %v", useTLS, method, kind, got, err)
					}
					wantBody := "payload"
					if method == http.MethodHead {
						wantBody = ""
					}
					if string(got.Body) != wantBody || got.BodyBytes != int64(len(wantBody)) || <-methods != method {
						t.Fatalf("method/payload facts: %+v", got)
					}
				}
			}
		}()
	}
}

func TestHTTPProbeRawStatusBoundsAndHTTPSCompatibility(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/must-not-follow")
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, "payload")
	}))
	defer s.Close()
	v := instance(t)
	e := executor(t, v)
	r := measurement.HTTPRequest{Route: measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"}, URL: s.URL, Timeout: time.Second, MaxBodyBytes: 16, MaxHeaderBytes: 4096}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		got, err := e.HTTP(context.Background(), method, r)
		if err != nil || got.StatusCode != 302 || got.Header.Get("Location") != "/must-not-follow" {
			t.Fatalf("raw redirect: %+v, %v", got, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("HTTP probe followed a redirect or issued another request")
	}
	r.MaxBodyBytes = 3
	if got, err := e.HTTP(context.Background(), http.MethodGet, r); !errors.Is(err, measurement.ErrBodyLimit) || string(got.Body) != "pay" || got.BodyBytes != 3 || got.BodyComplete {
		t.Fatalf("bounded HTTP payload: %+v, %v", got, err)
	}
	before := calls.Load()
	if _, err := e.HTTP(context.Background(), http.MethodPost, r); err == nil {
		t.Fatal("HTTP probe accepted a different operation method")
	}
	r.MaxBodyBytes = 0
	if _, err := e.HTTP(context.Background(), http.MethodGet, r); err == nil {
		t.Fatal("GET accepted an empty payload budget")
	}
	r.MaxBodyBytes = 16
	legacy := measurement.HTTPSRequest(r)
	if _, err := e.HTTPS(context.Background(), legacy); err == nil {
		t.Fatal("legacy HTTPS accepted plain HTTP")
	}
	if _, err := e.Download(context.Background(), measurement.DownloadRequest{HTTPS: legacy, TransferTimeout: time.Second}); err == nil {
		t.Fatal("download accepted plain HTTP")
	}
	if _, err := e.Upload(context.Background(), measurement.UploadRequest{HTTPS: legacy, PayloadBytes: 1, TransferTimeout: time.Second}); err == nil {
		t.Fatal("upload accepted plain HTTP")
	}
	if _, err := e.EgressIdentity(context.Background(), measurement.IdentityRequest{HTTPS: legacy}); err == nil {
		t.Fatal("identity accepted plain HTTP")
	}
	r.Route.Tag = "absent"
	if _, err := e.HTTP(context.Background(), http.MethodHead, r); err == nil {
		t.Fatal("missing exact HTTP tag fell back")
	}
	if calls.Load() != before {
		t.Fatal("rejected operation reached the endpoint")
	}
	// An inactive candidate uses an explicitly registered native tag, without
	// replacing the default route or creating another Measurement/core owner.
	if err := core.AddOutboundHandler(v, config("new-node", false)); err != nil {
		t.Fatal(err)
	}
	r.Route.Tag = "new-node"
	if got, err := e.HTTP(context.Background(), http.MethodHead, r); err != nil || got.StatusCode != 302 || calls.Load() != before+1 {
		t.Fatalf("new native node route: %+v, %v", got, err)
	}
}

func TestHTTPHeadCancellationAndHeaderLimit(t *testing.T) {
	entered := make(chan struct{}, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			w.Header().Set("X-Large", strings.Repeat("x", 8192))
			return
		}
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer s.Close()
	e := executor(t, instance(t))
	r := measurement.HTTPRequest{Route: measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"}, URL: s.URL, Timeout: time.Second, MaxHeaderBytes: 4096}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.HTTP(ctx, http.MethodHead, r); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("HEAD did not reach the native route")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HEAD cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HEAD cancellation retained native I/O")
	}
	r.URL += "/large"
	if got, err := e.HTTP(context.Background(), http.MethodHead, r); err == nil || got.StatusCode != 0 {
		t.Fatalf("HEAD exceeded its header budget: %+v, %v", got, err)
	}
}

func TestHTTPSProbePreservesCaseInsensitiveScheme(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "case") }))
	defer s.Close()
	e := executor(t, instance(t))
	for _, scheme := range []string{"HTTPS", "hTtPs"} {
		r := request(s, measurement.ExactOutbound)
		r.URL = scheme + strings.TrimPrefix(s.URL, "https")
		if got, err := e.HTTPS(context.Background(), r); err != nil || string(got.Body) != "case" || !got.BodyComplete {
			t.Fatalf("legacy HTTPS scheme %s: %+v, %v", scheme, got, err)
		}
	}
	r := request(s, measurement.ExactOutbound)
	r.URL = "HtTp" + strings.TrimPrefix(s.URL, "https")
	if _, err := e.HTTPS(context.Background(), r); err == nil {
		t.Fatal("case-insensitive HTTP escaped HTTPS-only gateway")
	}
}
