package measurement_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	policyfeature "github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func fragmentInstance(t *testing.T, fragment *freedom.Fragment) *core.Instance {
	t.Helper()
	v := instance(t)
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	cfg := config("exact", false)
	cfg.ProxySettings = serial.ToTypedMessage(&freedom.Config{
		FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		Fragment:   fragment,
	})
	if err := core.AddOutboundHandler(v, cfg); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestHTTPSZeroIntervalFragmentPreservesNativeExecution(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "fragmented") }))
	defer s.Close()
	for _, intervalMax := range []uint64{0, 1} {
		t.Run(fmt.Sprint(intervalMax), func(t *testing.T) {
			f := &freedom.Fragment{PacketsFrom: 0, PacketsTo: 1, LengthMin: 16, LengthMax: 32, MaxSplitMin: 2, MaxSplitMax: 2, IntervalMax: intervalMax}
			e := executor(t, fragmentInstance(t, f))
			r, err := e.HTTPS(context.Background(), request(s, measurement.ExactOutbound))
			if err != nil || string(r.Body) != "fragmented" || !r.BodyComplete {
				t.Fatalf("zero-interval native fragment failed: %+v %v", r, err)
			}
		})
	}
}

func TestDNSUDPUnusedFragmentPreservesNativePacketExecution(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		query := make([]byte, 2048)
		n, addr, err := pc.ReadFrom(query)
		if err == nil {
			_, err = pc.WriteTo(dnsReply(query[:n]), addr)
		}
		serverDone <- err
	}()
	f := &freedom.Fragment{PacketsFrom: 0, PacketsTo: 1, LengthMin: 16, LengthMax: 32, IntervalMin: 60000, IntervalMax: 60000}
	e := executor(t, fragmentInstance(t, f))
	r, err := e.DNSQuery(context.Background(), dnsRequest(pc.LocalAddr(), measurement.DNSUDP, measurement.ExactOutbound))
	if err != nil || r.Message == nil {
		t.Fatalf("unused TCP fragment blocked UDP owner: %+v %v", r, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

type bufferPolicyDialer struct {
	native   internet.DefaultSystemDialer
	observed chan policyfeature.Buffer
}

func (d *bufferPolicyDialer) Dial(ctx context.Context, source xnet.Address, destination xnet.Destination, opts *internet.SocketConfig) (net.Conn, error) {
	d.observed <- policyfeature.BufferPolicyFromContext(ctx)
	return d.native.Dial(ctx, source, destination, opts)
}

func (*bufferPolicyDialer) DestIpAddress() xnet.IP { return nil }

func TestNativeMeasurementPreservesCallerBufferPolicy(t *testing.T) {
	if isolatedSystemDialer(t) {
		return
	}
	d := &bufferPolicyDialer{observed: make(chan policyfeature.Buffer, 1)}
	internet.UseAlternativeSystemDialer(d)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "bounded") }))
	defer s.Close()
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		for _, callerLimit := range []int32{-1, 512 << 10, 64 << 10, 4 << 10, 0} {
			t.Run(fmt.Sprintf("%d/%d", kind, callerLimit), func(t *testing.T) {
				ctx := policyfeature.ContextWithBufferPolicy(context.Background(), policyfeature.Buffer{PerConnection: callerLimit})
				r, err := e.HTTPS(ctx, request(s, kind))
				if err != nil || string(r.Body) != "bounded" {
					t.Fatalf("native request failed: %+v %v", r, err)
				}
				want := callerLimit
				select {
				case observed := <-d.observed:
					if observed.PerConnection != want {
						t.Fatalf("native dispatch/dial buffer policy: got %d want %d", observed.PerConnection, want)
					}
				default:
					t.Fatal("native dial boundary not reached")
				}
				if policyfeature.BufferPolicyFromContext(ctx).PerConnection != callerLimit {
					t.Fatal("caller buffer policy changed")
				}
			})
		}
	}
}
