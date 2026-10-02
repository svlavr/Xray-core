package measurement_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport/internet"
)

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
	e, err := measurement.New(instance(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	d := new(nativeHTTPDialer)
	internet.UseAlternativeSystemDialer(d)
	defer internet.UseAlternativeSystemDialer(nil)
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
