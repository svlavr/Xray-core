package measurement_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport/internet"
)

func connectRequest(addr net.Addr) measurement.TCPConnectRequest {
	return measurement.TCPConnectRequest{Route: measurement.Route{Kind: measurement.Direct}, Destination: addr.(*net.TCPAddr).AddrPort(), Timeout: time.Second}
}

// Controller mutation is confined to serial fixtures, as required by the native
// controller API. All blocked calls are released before the fixture returns.
func connectController(t *testing.T, control func(string, string, syscall.RawConn) error) {
	t.Helper()
	original := internet.Controllers
	if err := internet.RegisterDialerController(control); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		internet.ControllersLock.Lock()
		internet.Controllers = original
		internet.ControllersLock.Unlock()
	})
}

func TestTCPConnectNativeSuccessRefusalAndClose(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ln, err := net.Listen("tcp", address)
			if err != nil {
				if address == "[::1]:0" {
					t.Skip("IPv6 loopback unavailable:", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			if address == "[::1]:0" {
				// A listener can bind even when host policy prohibits outbound
				// IPv6 loopback. Establish environmental capability independently.
				probe, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
				if err != nil {
					t.Skip("native IPv6 loopback connect unavailable:", err)
				}
				probe.Close()
				accepted, err := ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				accepted.Close()
			}
			done := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				b, err := io.ReadAll(c)
				if len(b) != 0 {
					err = errors.New("connect operation sent application bytes")
				}
				done <- err
			}()
			e := executor(t, nil)
			req := connectRequest(ln.Addr())
			r, err := e.TCPConnect(context.Background(), req)
			if err != nil || !r.DestinationConnected || r.NativeDialElapsed == nil || r.Elapsed < *r.NativeDialElapsed {
				t.Fatalf("native establishment: %+v %v", r, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("TCP socket did not close")
			}
			ln.Close()
			r, err = e.TCPConnect(context.Background(), req)
			var native *net.OpError
			if !errors.As(err, &native) || native.Op != "dial" || r.DestinationConnected || r.NativeDialElapsed == nil {
				t.Fatalf("native refusal: %+v %v", r, err)
			}
		})
	}
}

func TestTCPConnectValidationExactAndPrecancelBeforeNetwork(t *testing.T) {
	e := executor(t, nil)
	var calls atomic.Int32
	connectController(t, func(string, string, syscall.RawConn) error { calls.Add(1); return nil })
	valid := measurement.TCPConnectRequest{Route: measurement.Route{Kind: measurement.Direct}, Destination: netip.MustParseAddrPort("127.0.0.1:9"), Timeout: time.Second}
	for _, mutate := range []func(*measurement.TCPConnectRequest){
		func(r *measurement.TCPConnectRequest) { r.Destination = netip.AddrPort{} },
		func(r *measurement.TCPConnectRequest) { r.Destination = netip.MustParseAddrPort("127.0.0.1:0") },
		func(r *measurement.TCPConnectRequest) { r.Destination = netip.MustParseAddrPort("[fe80::1%test]:9") },
		func(r *measurement.TCPConnectRequest) { r.Timeout = 0 },
		func(r *measurement.TCPConnectRequest) { r.Route.Kind = 0 },
		func(r *measurement.TCPConnectRequest) { r.Route.Tag = "exact" },
		func(r *measurement.TCPConnectRequest) { r.Route.Kind = measurement.ExactOutbound },
	} {
		req := valid
		mutate(&req)
		if r, err := e.TCPConnect(context.Background(), req); err == nil || r.NativeDialElapsed != nil || r.DestinationConnected {
			t.Fatalf("invalid request: %+v %v", r, err)
		}
	}
	for _, tag := range []string{"exact", "trap", "absent"} {
		req := valid
		req.Route = measurement.Route{Kind: measurement.ExactOutbound, Tag: tag}
		if r, err := e.TCPConnect(context.Background(), req); !errors.Is(err, measurement.ErrUnsupported) || r.NativeDialElapsed != nil || r.DestinationConnected {
			t.Fatalf("logical/carrier connect reported: %+v %v", r, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := e.TCPConnect(ctx, valid); !errors.Is(err, context.Canceled) || r.NativeDialElapsed != nil {
		t.Fatalf("precancel: %+v %v", r, err)
	}
	if r, err := e.TCPConnect(nil, valid); err == nil || r.NativeDialElapsed != nil {
		t.Fatalf("nil context: %+v %v", r, err)
	}
	if calls.Load() != 0 {
		t.Fatal("rejected request performed network work")
	}
}

func TestTCPConnectAlternativeDialerRejectedBeforeInvocation(t *testing.T) {
	if isolatedSystemDialer(t) {
		return
	}
	e := executor(t, nil)
	d := &originDialer{t: t}
	internet.UseAlternativeSystemDialer(d)
	req := measurement.TCPConnectRequest{Route: measurement.Route{Kind: measurement.Direct}, Destination: netip.MustParseAddrPort("127.0.0.1:9"), Timeout: time.Second}
	r, err := e.TCPConnect(context.Background(), req)
	if !errors.Is(err, measurement.ErrUnsupported) || r.NativeDialElapsed != nil || r.DestinationConnected || d.calls.Load() != 0 {
		t.Fatalf("alternative native boundary: %+v %v calls=%d", r, err, d.calls.Load())
	}
}

func TestTCPConnectTimeoutAndActiveCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			connectController(t, func(string, string, syscall.RawConn) error { entered <- struct{}{}; <-release; return nil })
			e := executor(t, nil)
			req := measurement.TCPConnectRequest{Route: measurement.Route{Kind: measurement.Direct}, Destination: netip.MustParseAddrPort("127.0.0.1:9"), Timeout: 80 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type outcome struct {
				r   measurement.TCPConnectReceipt
				err error
			}
			done := make(chan outcome, 1)
			go func() { r, err := e.TCPConnect(ctx, req); done <- outcome{r, err} }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("native connect not reached")
			}
			want := context.DeadlineExceeded
			if mode == "cancel" {
				cancel()
				want = context.Canceled
			} else {
				time.Sleep(120 * time.Millisecond)
			}
			once.Do(func() { close(release) })
			select {
			case got := <-done:
				if !errors.Is(got.err, want) || got.r.NativeDialElapsed == nil {
					t.Fatalf("interrupted dial: %+v %v", got.r, got.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("native connect ignored cancellation")
			}
		})
	}
}

func TestTCPConnectConcurrentNoCrossTalk(t *testing.T) {
	e := executor(t, nil)
	var wg sync.WaitGroup
	for range 12 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err == nil {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, err = io.Copy(io.Discard, c)
					c.Close()
				}
				done <- err
			}()
			r, err := e.TCPConnect(context.Background(), connectRequest(ln.Addr()))
			if err != nil || !r.DestinationConnected || r.NativeDialElapsed == nil {
				t.Errorf("cross-talk: %+v %v", r, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("concurrent socket survived cleanup")
			}
		}()
	}
	wg.Wait()
}
