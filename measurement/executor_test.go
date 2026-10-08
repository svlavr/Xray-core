package measurement_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport/internet"
)

func TestExecutorCanceledAdmissionDoesNotOpenOrRetainSlot(t *testing.T) {
	if isolatedSystemDialer(t) {
		return
	}
	e, err := measurement.New(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &originDialer{t: t}
	internet.UseAlternativeSystemDialer(dialer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for range 16 {
		for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
			if r, err := e.UDPEcho(ctx, udpRequest(addr, kind)); !errors.Is(err, context.Canceled) || r.Elapsed != 0 || len(r.Sends) != 0 {
				t.Fatalf("canceled UDP admission: %+v, %v", r, err)
			}
			for _, transport := range []measurement.DNSTransport{measurement.DNSUDP, measurement.DNSTCP, measurement.DNSDoT, measurement.DNSDoH} {
				req := dnsRequest(addr, transport, kind)
				req.ServerName, req.DoHPath, req.MaxHeaderBytes = "fixture.invalid", "/dns-query", 4096
				if r, err := e.DNSQuery(ctx, req); !errors.Is(err, context.Canceled) || r.Elapsed != 0 || r.WrittenBytes != nil || len(r.Wire) != 0 {
					t.Fatalf("canceled DNS admission: %+v, %v", r, err)
				}
			}
		}
	}
	if dialer.calls.Load() != 0 {
		t.Fatal("canceled admission invoked the native socket owner")
	}
	pc := udpFixture(t, func(pc net.PacketConn, p []byte, a net.Addr) { _, _ = pc.WriteTo(p, a) })
	if r, err := e.UDPEcho(context.Background(), udpRequest(pc.LocalAddr(), measurement.Direct)); err != nil || !r.WindowComplete || len(r.Replies) != 3 {
		t.Fatalf("canceled admissions retained the executor slot: %+v, %v", r, err)
	}
}

func TestExecutorRejectsInvalidConcurrency(t *testing.T) {
	v := instance(t)
	for _, limit := range []int{-1, 0} {
		if e, err := measurement.New(v, limit); err == nil || e != nil {
			t.Fatalf("invalid limit %d: executor=%v error=%v", limit, e, err)
		}
	}
	for _, limit := range []int{-1, 0} {
		if e, err := measurement.New(nil, limit); err == nil || e != nil {
			t.Fatalf("nil instance invalid limit %d: executor=%v error=%v", limit, e, err)
		}
	}
}

func TestExecutorCallerConcurrencyAndSlotReuse(t *testing.T) {
	testExecutorConcurrency(t, instance(t))
}

func TestIndependentDirectConcurrencyAndSlotReuse(t *testing.T) {
	testExecutorConcurrency(t, nil)
}

func testExecutorConcurrency(t *testing.T, v *core.Instance) {
	t.Helper()
	for _, limit := range []int{1, 2, 12} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			entered := make(chan struct{}, limit+1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				select {
				case <-release:
					_, _ = io.WriteString(w, "completed")
				case <-r.Context().Done():
				}
			}))
			defer s.Close()
			defer unblock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e, err := measurement.New(v, limit)
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, limit)
			for i := range limit {
				kind := measurement.Direct
				if v != nil && i%2 != 0 {
					kind = measurement.ExactOutbound
				}
				go func() {
					r, err := e.HTTPS(ctx, request(s, kind))
					if err == nil && (!r.BodyComplete || string(r.Body) != "completed") {
						err = fmt.Errorf("incomplete operation: %+v", r)
					}
					returned <- err
				}()
			}
			for range limit {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("configured concurrent operations did not all reach endpoint")
				}
			}
			queued := request(s, measurement.Direct)
			if v != nil {
				queued.Route = measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"}
			}
			queued.Timeout = 50 * time.Millisecond
			if _, err := e.HTTPS(ctx, queued); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued operation: %v", err)
			}
			select {
			case <-entered:
				t.Fatal("operation exceeded caller concurrency limit")
			default:
			}
			unblock()
			for range limit {
				select {
				case err := <-returned:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("active operation did not complete")
				}
			}
			if _, err := e.HTTPS(ctx, request(s, measurement.Direct)); err != nil {
				t.Fatalf("completed slots were not reusable: %v", err)
			}
		})
	}
}
