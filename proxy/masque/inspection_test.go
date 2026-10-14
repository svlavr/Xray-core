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
	"github.com/xtls/xray-core/transport/internet/splithttp"
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
	flow.Route(fs.OutboundRef{Tag: "masque-test"})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	if err := client.Process(ctx, link, inspectionFailDialer{}); err == nil {
		t.Fatal("failed tunnel establishment succeeded")
	}
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != flow.Ref() || live.Rows[0].Outbound.Tag != "masque-test" || live.Rows[0].Destination != target {
		t.Fatalf("failed tunnel logical claim: %+v %v", live, err)
	}
	finish()
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
	observation.Exchange.Route(fs.OutboundRef{Tag: "masque-test"})
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
	if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
		t.Fatalf("first request exact stop: %+v %v", outcomes, err)
	}
	finish()

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
	shared := &tunnel{dev: dev, tnet: tnet, done: make(chan struct{}), onClose: client.removeTunnel}
	client.tunnels[shared] = struct{}{}
	client.xmux = splithttp.NewXmuxManager(splithttp.XmuxConfig{}, func() splithttp.XmuxConn { return shared })
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
	observation.Exchange.Route(fs.OutboundRef{Tag: "masque-test"})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	done := make(chan error, 1)
	go func() { done <- client.Process(ctx, link, inspectionDialer{}) }()
	deadline := time.Now().Add(3 * time.Second)
	var liveStorage232 []fs.FlowRecord
	for {
		live, err := view.ReadLiveInto(liveStorage232)
		liveStorage232 = live.Rows
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 && live.Rows[0].Outbound.Tag == "masque-test" {
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
	if running := client.xmux.GetExistingXmuxClient(context.Background()).Running.Load(); running != 0 {
		t.Fatalf("stopped virtual association retained %d running flows", running)
	}
}

type inspectionCaptureDialer struct {
	inspectionDialer
	ctx context.Context
}

func (d *inspectionCaptureDialer) Dial(ctx context.Context, _ net.Destination) (stat.Connection, error) {
	d.ctx = ctx
	return nil, io.ErrClosedPipe
}

func TestInspectionMasqueCurrentAdmissionCarrierMetadata(t *testing.T) {
	client, instance := newInspectionClient(t)
	var previous *session.Outbound
	for _, gateway := range []net.Address{net.ParseAddress("127.0.0.2"), net.ParseAddress("127.0.0.3")} {
		request := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Gateway: gateway}})
		dialer := new(inspectionCaptureDialer)
		client.lastErrAt = time.Time{}
		if _, _, err := client.getTunnel(request, dialer); err == nil {
			t.Fatal("failed carrier establishment succeeded")
		}
		if dialer.ctx == nil {
			t.Fatal("carrier did not use the current admission dialer")
		}
		carrier := session.OutboundsFromContext(dialer.ctx)[0]
		if carrier == previous || carrier.Gateway != gateway || carrier.Target != client.server.Destination || carrier.Tag != "masque-test" {
			t.Fatalf("carrier retained previous admission metadata: %+v", carrier)
		}
		if core.FromContext(dialer.ctx) != instance || session.FullHandlerFromContext(dialer.ctx).Tag() != "masque-test" ||
			session.TrafficOriginFromContext(dialer.ctx) != session.TrafficOriginInternal ||
			session.LogicalObservationFromContext(dialer.ctx) != nil || session.InboundFromContext(dialer.ctx) != nil {
			t.Fatal("carrier retained logical identity or lost instance/handler identity")
		}
		previous = carrier
	}
}

func TestInspectionMasqueCanceledAdmissionReleasesXmux(t *testing.T) {
	for _, target := range []net.Destination{
		net.TCPDestination(net.ParseAddress("10.232.79.1"), 443),
		net.UDPDestination(net.ParseAddress("10.232.79.1"), 443),
		net.TCPDestination(net.DomainAddress("v1.mux.cool"), 443),
		net.TCPDestination(net.DomainAddress("v1.rvs.cool"), 443),
	} {
		t.Run(target.String(), func(t *testing.T) {
			client, _ := newInspectionClient(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
			shared := &tunnel{done: make(chan struct{}), onClose: client.removeTunnel}
			client.tunnels[shared] = struct{}{}
			client.xmux = splithttp.NewXmuxManager(splithttp.XmuxConfig{}, func() splithttp.XmuxConn {
				cancel()
				return shared
			})
			if err := client.Process(ctx, &transport.Link{}, inspectionDialer{}); err != context.Canceled {
				t.Fatalf("post-establishment cancellation: %v", err)
			}
			xmuxClient := client.xmux.GetExistingXmuxClient(context.Background())
			if xmuxClient == nil || xmuxClient.Running.Load() != 0 || shared.IsClosed() {
				t.Fatal("canceled logical flow leaked its admission or closed the shared carrier")
			}
		})
	}
}
