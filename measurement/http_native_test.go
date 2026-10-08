package measurement_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	policyfeature "github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport/internet"
)

// One fixed instance/endpoint, with no per-attempt subtest or receipt retention.
// Endpoint socket closure is an invariant; process-wide memory/G values are raw
// observations, separate from the native carrier pools used in profile tests.
func TestC5HTTPResourceCycles(t *testing.T) {
	var active atomic.Int64
	entered := make(chan struct{}, 1)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/success" {
			w.Header().Set("Content-Length", "100")
		}
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		if r.URL.Path == "/cancel" {
			entered <- struct{}{}
			<-r.Context().Done()
		}
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			active.Add(1)
		} else if state == http.StateClosed {
			active.Add(-1)
		}
	}
	s.StartTLS()
	defer s.Close()
	v := instance(t)
	e, err := measurement.New(v, 1)
	if err != nil {
		t.Fatal(err)
	}
	stopLoad := c5OrdinaryBenchmarkLoad(t, v, measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"})
	defer stopLoad()
	timeouts := v.GetFeature(policyfeature.ManagerType()).(policyfeature.Manager).ForLevel(0).Timeouts
	idle := timeouts.UplinkOnly + timeouts.DownlinkOnly + 50*time.Millisecond
	snapshot := func(label string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for active.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if active.Load() != 0 {
			t.Fatalf("%s retained endpoint sockets%d", label, active.Load())
		}
		// Native Freedom retains inactivity callbacks until its configured
		// one-sided timers and the next periodic check retire. Account for them.
		time.Sleep(idle)
		runtime.GC()
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		t.Logf("%s HeapAlloc=%d HeapObjects=%d goroutines=%d endpoint-sockets=%d", label, memory.HeapAlloc, memory.HeapObjects, runtime.NumGoroutine(), active.Load())
	}
	for wave := range 4 {
		for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
			for repeat := range 12 {
				for _, mode := range []string{"success", "failure", "cancel"} {
					r := request(s, kind)
					r.URL += "/" + mode
					ctx, cancel := context.WithCancel(context.Background())
					type result struct {
						receipt measurement.HTTPSReceipt
						err     error
					}
					done := make(chan result, 1)
					go func() { got, err := e.HTTPS(ctx, r); done <- result{got, err} }()
					if mode == "cancel" {
						select {
						case <-entered:
							cancel()
						case <-time.After(3 * time.Second):
							cancel()
							t.Fatal("cycle did not enter peer")
						}
					}
					select {
					case got := <-done:
						want := mode == "success"
						if (got.err == nil) != want || got.receipt.BodyComplete != want || (mode == "failure" && !errors.Is(got.err, io.ErrUnexpectedEOF)) || (mode == "cancel" && !errors.Is(got.err, context.Canceled)) {
							cancel()
							t.Fatalf("wave%d repeat%d %s: %+v %v", wave, repeat, mode, got.receipt, got.err)
						}
					case <-time.After(4 * time.Second):
						cancel()
						t.Fatal("resource cycle did not return")
					}
					cancel()
				}
			}
		}
		snapshot(fmt.Sprintf("same-config wave%d", wave))
	}
	stopLoad()
	snapshot("ordinary load closed")
}

func TestHTTPSNativeTLSCancellationReusesSlot(t *testing.T) {
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			entered, ended := make(chan struct{}, 1), make(chan struct{}, 1)
			go func() {
				for range 2 {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					var first [1]byte
					if _, err := io.ReadFull(conn, first[:]); err != nil {
						_ = conn.Close()
						return
					}
					entered <- struct{}{} // Endpoint TLS actually transmitted bytes.
					_, _ = io.Copy(io.Discard, conn)
					_ = conn.Close()
					ended <- struct{}{}
				}
			}()
			e, err := measurement.New(instance(t), 1)
			if err != nil {
				t.Fatal(err)
			}
			req := measurement.HTTPSRequest{URL: "https://" + ln.Addr().String(), Route: measurement.Route{Kind: kind}, Timeout: time.Second, MaxBodyBytes: 32, MaxHeaderBytes: 1024}
			if kind == measurement.ExactOutbound {
				req.Route.Tag = "exact"
			}
			type result struct {
				receipt measurement.HTTPSReceipt
				err     error
			}
			for range 2 {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan result, 1)
				go func() { r, err := e.HTTPS(ctx, req); done <- result{r, err} }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("native TLS did not start or slot was not reusable")
				}
				cancel()
				select {
				case r := <-done:
					if !errors.Is(r.err, context.Canceled) || r.receipt.StatusCode != 0 {
						t.Fatalf("native TLS cancellation: %+v", r)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("native TLS cancellation did not return")
				}
				select {
				case <-ended:
				case <-time.After(2 * time.Second):
					t.Fatal("native TLS socket did not close")
				}
			}
		})
	}
}

type nativeHTTPDialer struct {
	conn  net.Conn
	calls atomic.Int32
}

func (d *nativeHTTPDialer) Dial(context.Context, xnet.Address, xnet.Destination, *internet.SocketConfig) (net.Conn, error) {
	d.calls.Add(1)
	return d.conn, nil
}

func (*nativeHTTPDialer) DestIpAddress() xnet.IP { return nil }

func TestHTTPSNativeNilConnectionDoesNotRetainSlot(t *testing.T) {
	if isolatedSystemDialer(t) {
		return
	}
	e, err := measurement.New(instance(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	d := new(nativeHTTPDialer)
	internet.UseAlternativeSystemDialer(d)
	req := measurement.HTTPSRequest{URL: "https://127.0.0.1:443/", Route: measurement.Route{Kind: measurement.Direct}, Timeout: time.Second, MaxBodyBytes: 32, MaxHeaderBytes: 1024}
	for range 2 {
		r, err := e.HTTPS(context.Background(), req)
		if err == nil || r.EndpointTLS != nil {
			t.Fatalf("nil connection: receipt=%+v error=%v", r, err)
		}
	}
	if d.calls.Load() != 2 {
		t.Fatalf("nil connection retained slot: native calls=%d", d.calls.Load())
	}
}
