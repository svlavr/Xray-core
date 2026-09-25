package outbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
)

func preconnectInspection(t *testing.T, target cnet.Destination, flow string, cone bool) (context.Context, context.CancelFunc, *Handler, *transport.Link, fs.FlowInspection, func()) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })

	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.Discard}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	var finish func()
	if target.Network == cnet.Network_UDP {
		ctx, finish = proxy.ObserveUDP(ctx, manager, conn, target, link)
	} else {
		ctx, finish = proxy.ObserveTCP(ctx, manager, conn, target, link)
	}
	observation := session.LogicalObservationFromContext(ctx)
	if observation != nil {
		observation.Exchange.Route(fs.RouteStep{
			Leg: 1, Selection: fs.SelectionDefault,
			Outbound: fs.OutboundRef{Runtime: view.Info().Runtime, Serial: 1, Tag: "vless"},
			Original: target, SelectedTarget: target,
		})
	}
	ctx, cancel := context.WithCancel(ctx)

	handler := &Handler{
		server: &protocol.ServerSpec{
			Destination: cnet.TCPDestination(cnet.LocalHostIP, 1),
			User: &protocol.MemoryUser{Account: &vless.MemoryAccount{
				ID: protocol.NewID(uuid.New()), Flow: flow,
			}},
		},
		cone:     cone,
		testpre:  1,
		preConns: make(chan *ConnExpire),
	}
	handler.initpre.Do(func() {})
	return ctx, cancel, handler, link, view, finish
}

func TestInspectionVLESSPreconnectExactStop(t *testing.T) {
	for _, test := range []struct {
		name   string
		target cnet.Destination
		flow   string
		cone   bool
	}{
		{"tcp", cnet.TCPDestination(cnet.DomainAddress("ordinary.invalid"), 443), "", false},
		{"cone-xudp", cnet.UDPDestination(cnet.DomainAddress("cone.invalid"), 80), "", true},
		{"vision-xudp", cnet.UDPDestination(cnet.DomainAddress("vision.invalid"), 80), vless.XRV, true},
	} {
		t.Run(test.name, func(t *testing.T) { preconnectStopAcceptance(t, test.target, test.flow, test.cone) })
	}
}

func preconnectStopAcceptance(t *testing.T, target cnet.Destination, flow string, cone bool) {
	ctx, cancel, handler, link, view, finish := preconnectInspection(t, target, flow, cone)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- handler.Process(ctx, link, nil) }()

	var ref fs.FlowRef
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 && live.Rows[0].AccountingRoute.Outbound.Tag == "vless" && live.Rows[0].AccountingRoute.Effective == target {
			ref = live.Rows[0].Ref
			break
		}
		time.Sleep(time.Millisecond)
	}
	if ref.ID == 0 {
		t.Fatal("ordinary endpoint was not claimed before preconnect wait")
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("exact stop: %+v %v", outcomes, err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("preconnect wait returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preconnect wait ignored exact endpoint cancellation")
	}
	finish()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) == 1 {
			if page.Rows[0].Reason != fs.EndReasonLocalStop || page.Rows[0].Flow.Ref != ref {
				t.Fatalf("preconnect terminal: %+v", page.Rows[0])
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("preconnect flow did not finish")
}

func TestInspectionVLESSPreconnectCommandClaims(t *testing.T) {
	tests := []struct {
		name    string
		target  cnet.Destination
		flow    string
		cone    bool
		claimed bool
	}{
		{name: "mux", target: cnet.TCPDestination(cnet.DomainAddress("v1.mux.cool"), 0)},
		{name: "reverse", target: cnet.Destination{Address: cnet.DomainAddress("v1.rvs.cool")}},
		{name: "vision", target: cnet.TCPDestination(cnet.DomainAddress("vision.invalid"), 443), flow: vless.XRV, claimed: true},
		{name: "cone-xudp", target: cnet.UDPDestination(cnet.DomainAddress("cone.invalid"), 80), cone: true, claimed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel, handler, link, view, finish := preconnectInspection(t, test.target, test.flow, test.cone)
			done := make(chan error, 1)
			go func() { done <- handler.Process(ctx, link, nil) }()
			select {
			case handler.preConns <- nil:
			case err := <-done:
				t.Fatalf("special branch returned before Testpre receive: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("special branch did not reach Testpre receive")
			}
			observation := session.LogicalObservationFromContext(ctx)
			live, err := view.ReadLive(context.Background())
			claimed := observation != nil && len(live.Rows) == 1 && live.Rows[0].AccountingRoute.Outbound.Serial != 0
			if err != nil || claimed != test.claimed {
				t.Fatal("command claim disagrees with logical endpoint eligibility")
			}
			if test.name == "mux" && observation != nil {
				t.Fatal("reserved carrier created a logical root")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("closed Testpre channel returned nil")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("special preconnect wait did not return")
			}
			cancel()
			if finish != nil {
				finish()
			}
		})
	}
}
