package masque

import (
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	transmasque "github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type inspectionHandler struct{ outbound.Handler }

func (*inspectionHandler) Tag() string { return "masque-test" }

type inspectionPolicy struct{ policy.Manager }

func (inspectionPolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Minute}}
}

type inspectionDialer struct{ internet.Dialer }

func (inspectionDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

type inspectionFailDialer struct{ inspectionDialer }

func (inspectionFailDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return nil, io.ErrClosedPipe
}

type inspectionBlockingDialer struct {
	inspectionDialer
	started chan context.Context
	release chan struct{}
}

func (d *inspectionBlockingDialer) Dial(ctx context.Context, _ net.Destination) (stat.Connection, error) {
	d.started <- ctx
	<-d.release
	return nil, io.ErrClosedPipe
}

func newInspectionClient(t *testing.T) (*Client, *core.Instance) {
	t.Helper()
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	base := context.WithValue(context.Background(), core.XrayKey(1), instance)
	base = session.ContextWithFullHandler(base, new(inspectionHandler))
	base = session.ContextWithStreamSettings(base, &internet.MemoryStreamConfig{
		ProtocolSettings: &transmasque.Config{}, SecuritySettings: &tls.Config{},
	})
	base = session.ContextWithTrafficOrigin(base, session.TrafficOriginUser)
	base = session.ContextWithLogicalObservation(base, &session.LogicalObservation{})
	base = session.ContextWithInbound(base, &session.Inbound{Tag: "first-request"})
	client, err := NewClient(base, &ClientConfig{Server: &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.LocalHostIP), Port: 443,
	}})
	if err != nil {
		instance.Close()
		t.Fatal(err)
	}
	client.policyManager = inspectionPolicy{}
	t.Cleanup(func() { client.Close(); instance.Close() })
	return client, instance
}

func TestInspectionMasqueCarrierContext(t *testing.T) {
	client, instance := newInspectionClient(t)
	server := client.server.Destination
	ctx := client.carrierContext(server, net.LocalHostIP)
	if core.FromContext(ctx) != instance || session.FullHandlerFromContext(ctx).Tag() != "masque-test" ||
		session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal ||
		session.LogicalObservationFromContext(ctx) != nil || session.InboundFromContext(ctx) != nil {
		t.Fatal("physical tunnel retained request identity or lost handler identity")
	}
	first := session.OutboundsFromContext(ctx)[0]
	if first.Target != server || first.Gateway != net.LocalHostIP || first.Tag != "masque-test" {
		t.Fatalf("physical tunnel metadata: %+v", first)
	}
	if session.OutboundsFromContext(client.carrierContext(server, nil))[0] == first {
		t.Fatal("reconnect reused mutable outbound metadata")
	}
}

func TestInspectionMasqueTCPClaimBeforeTunnelFailure(t *testing.T) {
	client, _ := newInspectionClient(t)
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	target := net.TCPDestination(net.ParseAddress("10.232.79.1"), 443)
	local, peer := stdnet.Pipe()
	defer local.Close()
	defer peer.Close()
	link := &transport.Link{Reader: buf.NewReader(local), Writer: buf.NewWriter(local)}
	ctx, finish := proxy.ObserveTCP(context.Background(), manager, local, target, link)
	flow := session.LogicalObservationFromContext(ctx).Exchange
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "masque-test", Serial: 1}})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	if err := client.Process(ctx, link, inspectionFailDialer{}); err == nil {
		t.Fatal("failed tunnel establishment succeeded")
	}
	finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	route := page.Rows[0].Flow.AccountingRoute
	if route.Outbound.Tag != "masque-test" || route.Effective != target {
		t.Fatalf("logical MASQUE route: %+v", route)
	}
}

func TestInspectionMasqueFirstRequestStopDuringEstablishment(t *testing.T) {
	client, _ := newInspectionClient(t)
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	target := net.TCPDestination(net.ParseAddress("10.232.79.1"), 443)
	local, peer := stdnet.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(local), Writer: buf.NewWriter(local)}
	ctx, finish := proxy.ObserveTCP(context.Background(), manager, local, target, link)
	t.Cleanup(finish)
	observation := session.LogicalObservationFromContext(ctx)
	observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "masque-test", Serial: 1}})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})

	release := make(chan struct{})
	dialer := &inspectionBlockingDialer{started: make(chan context.Context, 1), release: release}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	done := make(chan error, 1)
	go func() { done <- client.Process(ctx, link, dialer) }()

	var carrierCtx context.Context
	select {
	case carrierCtx = <-dialer.started:
	case <-time.After(3 * time.Second):
		t.Fatal("first tunnel establishment did not start")
	}
	if session.TrafficOriginFromContext(carrierCtx) != session.TrafficOriginInternal || session.LogicalObservationFromContext(carrierCtx) != nil {
		t.Fatal("first tunnel retained the logical request identity")
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{observation.Exchange.Ref()})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("first request exact stop: %+v %v", outcomes, err)
	}
	finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Ref != observation.Exchange.Ref() || page.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatalf("first request terminal: %+v %v", page, err)
	}
	if carrierCtx.Err() != nil {
		t.Fatalf("request stop canceled shared tunnel establishment: %v", carrierCtx.Err())
	}
	select {
	case err := <-done:
		t.Fatalf("tunnel establishment ended before its dialer: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("failed tunnel establishment succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed tunnel establishment did not return")
	}
}

func TestInspectionMasqueStopVirtualAssociation(t *testing.T) {
	client, _ := newInspectionClient(t)
	dev, tnet, _, err := wireguard.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.232.79.2")}, nil, transmasque.MinPacketSize, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.tunnel.Store(nil); dev.Close() })
	shared := &tunnel{dev: dev, tnet: tnet, done: make(chan struct{})}
	client.tunnel.Store(shared)
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	target := net.UDPDestination(net.ParseAddress("10.232.79.1"), 443)
	local, peer := stdnet.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(local), Writer: buf.NewWriter(local)}
	ctx, finish := proxy.ObserveUDP(context.Background(), manager, local, target, link)
	t.Cleanup(finish)
	observation := session.LogicalObservationFromContext(ctx)
	observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "masque-test", Serial: 1}})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	done := make(chan error, 1)
	go func() { done <- client.Process(ctx, link, inspectionDialer{}) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 && live.Rows[0].AccountingRoute.Outbound.Tag == "masque-test" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flow did not bind to MASQUE")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("virtual association ended early: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := view.CloseFlows(context.Background(), []fs.FlowRef{observation.Exchange.Ref()}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stopped virtual association succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exact stop did not cancel virtual association")
	}
	select {
	case <-shared.done:
		t.Fatal("flow stop closed shared tunnel")
	default:
	}
}
