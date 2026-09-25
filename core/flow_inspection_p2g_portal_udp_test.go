package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	cnet "github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	internetudp "github.com/xtls/xray-core/transport/internet/udp"
)

type portalUDPDataOutbound struct {
	tag string
}

func (h *portalUDPDataOutbound) Tag() string { return h.tag }

func (*portalUDPDataOutbound) Start() error { return nil }

func (*portalUDPDataOutbound) Close() error { return nil }

func (*portalUDPDataOutbound) SenderSettings() *serial.TypedMessage { return nil }

func (*portalUDPDataOutbound) ProxySettings() *serial.TypedMessage { return nil }

func (*portalUDPDataOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	if observation := session.LogicalObservationFromContext(ctx); observation != nil {
		observation.Exchange.BindRoute()
	}
	mb, err := link.Reader.ReadMultiBuffer()
	if err == nil {
		err = link.Writer.WriteMultiBuffer(mb)
	} else {
		buf.ReleaseMulti(mb)
	}
	if err != nil {
		common.Interrupt(link.Writer)
	} else {
		common.Close(link.Writer)
	}
	common.Interrupt(link.Reader)
}

type portalUDPNoClaimOutbound struct {
	portalUDPDataOutbound
	returned chan struct{}
}

func (h *portalUDPNoClaimOutbound) Dispatch(_ context.Context, link *transport.Link) {
	defer close(h.returned)
	mb, _ := link.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	common.Close(link.Writer)
	common.Interrupt(link.Reader)
}

func TestFlowInspectionP2GPortalUDPMixedDataRays(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := manager.AddHandler(context.Background(), &portalUDPDataOutbound{tag: "udp-data"}); err != nil {
		t.Fatal(err)
	}
	portal, err := reverse.NewPortal(&reverse.PortalConfig{Tag: "portal", Domain: "carrier.invalid"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { portal.Close() })
	routerFeature := instance.GetFeature(routing.RouterType()).(routing.Router)
	if err := routerFeature.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{
		{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "data.invalid"}}}}, Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "udp-data"}},
		{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "carrier.invalid"}}}}, Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "portal"}},
	}}), true); err != nil {
		t.Fatal(err)
	}

	root := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
	dispatcherFeature := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	responses := make(chan string, 1)
	callback := func(ctx context.Context, packet *protocoludp.Packet) {
		if observation := session.LogicalObservationFromContext(ctx); observation != nil {
			observation.Exchange.AddDownlink(uint64(packet.Payload.Len()))
		}
		responses <- packet.Payload.String()
		packet.Payload.Release()
	}
	dataRay := internetudp.NewDispatcher(dispatcherFeature, callback)
	dataRay.Observation = root
	dataDestination := cnet.UDPDestination(cnet.DomainAddress("data.invalid"), 53)
	dataPayload := "ordinary association payload"
	dataRay.Dispatch(context.Background(), dataDestination, buf.FromBytes([]byte(dataPayload)))
	select {
	case response := <-responses:
		if response != dataPayload {
			t.Fatalf("ordinary response: %q", response)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary selected handler did not return data")
	}
	dataRay.RemoveRay()

	portalRay := internetudp.NewDispatcher(dispatcherFeature, func(_ context.Context, packet *protocoludp.Packet) {
		packet.Payload.Release()
		t.Error("unavailable Portal worker returned a UDP packet")
	})
	portalRay.Observation = root
	portalDestination := cnet.UDPDestination(cnet.DomainAddress("carrier.invalid"), 443)
	portalPayload := "same-domain UDP child"
	portalRay.Dispatch(context.Background(), portalDestination, buf.FromBytes([]byte(portalPayload)))
	inspectionWait(t, func() bool {
		live, readErr := view.ReadLive(context.Background())
		return readErr == nil && len(live.Rows) == 1 && len(live.Rows[0].Routes) == 2 && live.Rows[0].Uplink.Known == uint64(len(dataPayload)+len(portalPayload))
	})
	portalRay.RemoveRay()
	root.Finish()

	inspectionWait(t, func() bool {
		page, readErr := view.ReadTerminals(context.Background())
		return readErr == nil && len(page.Rows) == 1
	})
	page, err := view.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	flow := page.Rows[0].Flow
	if flow.Uplink.Known != uint64(len(dataPayload)+len(portalPayload)) || flow.Downlink.Known != uint64(len(dataPayload)) || len(flow.Destinations) != 2 || flow.Destinations[0] != dataDestination || flow.Destinations[1] != portalDestination || len(flow.Routes) != 2 || flow.Routes[0].Outbound.Tag != "udp-data" || flow.Routes[1].Outbound.Tag != "portal" {
		t.Fatalf("mixed association facts: %+v", page.Rows[0])
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var up, down uint64
	for _, total := range totals.Rows {
		up += total.Uplink.Known
		down += total.Downlink.Known
	}
	if up != uint64(len(dataPayload)+len(portalPayload)) || down != uint64(len(dataPayload)) {
		t.Fatalf("mixed association totals: %d/%d", up, down)
	}

	// A packet-started association whose only ray targets the Portal domain
	// is still logical UDP data. It must not disappear as a physical carrier.
	onlyRoot := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
	onlyRay := internetudp.NewDispatcher(dispatcherFeature, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
	onlyRay.Observation = onlyRoot
	onlyPayload := "only Portal UDP child"
	onlyRay.Dispatch(context.Background(), portalDestination, buf.FromBytes([]byte(onlyPayload)))
	inspectionWait(t, func() bool {
		live, readErr := view.ReadLive(context.Background())
		return readErr == nil && len(live.Rows) == 1 && live.Rows[0].Uplink.Known == uint64(len(onlyPayload)) && len(live.Rows[0].Routes) == 1 && live.Rows[0].Routes[0].Outbound.Tag == "portal"
	})
	onlyRay.RemoveRay()
	onlyRoot.Finish()
	inspectionWait(t, func() bool {
		page, readErr := view.ReadTerminals(context.Background())
		return readErr == nil && len(page.Rows) == 2 && page.Rows[1].Flow.Uplink.Known == uint64(len(onlyPayload)) && page.Rows[1].Flow.Routes[0].Outbound.Tag == "portal"
	})
}

func TestFlowInspectionP2GUDPCustomHandlerReturnStaysPending(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	handler := &portalUDPNoClaimOutbound{portalUDPDataOutbound: portalUDPDataOutbound{tag: "no-claim"}, returned: make(chan struct{})}
	if err := manager.AddHandler(context.Background(), handler); err != nil {
		t.Fatal(err)
	}
	if err := instance.GetFeature(routing.RouterType()).(routing.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "no-claim"}}}}), true); err != nil {
		t.Fatal(err)
	}
	root := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
	ray := internetudp.NewDispatcher(instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher), func(_ context.Context, packet *protocoludp.Packet) {
		packet.Payload.Release()
		t.Error("non-consuming handler returned a packet")
	})
	ray.Observation = root
	payload := "selected but never consumed"
	ray.Dispatch(context.Background(), cnet.UDPDestination(cnet.DomainAddress("unclaimed.invalid"), 53), buf.FromBytes([]byte(payload)))
	select {
	case <-handler.returned:
	case <-time.After(5 * time.Second):
		t.Fatal("selected non-consuming handler did not return")
	}
	ray.RemoveRay()
	root.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("unclaimed terminal: %+v %v", page, err)
	}
	flow := page.Rows[0].Flow
	if len(flow.Routes) != 1 || flow.Routes[0].Outbound.Tag != "no-claim" || flow.AccountingRoute.Outbound.Serial != 0 || flow.Uplink.Known != uint64(len(payload)) || !flow.Uplink.Incomplete || !flow.Downlink.Incomplete {
		t.Fatalf("custom pending facts: %+v", page.Rows[0])
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, total := range totals.Rows {
		if total.Uplink.Known != 0 || total.Downlink.Known != 0 || total.Uplink.Incomplete || total.Downlink.Incomplete {
			t.Fatalf("custom handler return settled pending credit: %+v", total)
		}
	}
}

func TestFlowInspectionP2GNativeHandlerReturnSettlesNoClaim(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	if err := core.AddOutboundHandler(instance, &core.OutboundHandlerConfig{
		Tag: "native-no-claim",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{MultiplexSettings: &proxyman.MultiplexingConfig{
			Enabled:         true,
			Concurrency:     4,
			XudpProxyUDP443: "reject",
		}}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := instance.GetFeature(routing.RouterType()).(routing.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "native-no-claim"}}}}), true); err != nil {
		t.Fatal(err)
	}
	root := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
	ray := internetudp.NewDispatcher(instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher), func(_ context.Context, packet *protocoludp.Packet) {
		packet.Payload.Release()
		t.Error("rejected native handler returned a packet")
	})
	ray.Observation = root
	payload := "native selected no claim"
	ray.Dispatch(context.Background(), cnet.UDPDestination(cnet.DomainAddress("native-no-claim.invalid"), 443), buf.FromBytes([]byte(payload)))
	inspectionWait(t, func() bool {
		totals, readErr := view.ReadTotals(context.Background())
		if readErr != nil {
			return false
		}
		for _, total := range totals.Rows {
			if total.Origin == fs.TrafficOriginUser && total.Outbound.Serial == 0 {
				return total.Uplink.Known == uint64(len(payload)) && total.Uplink.Incomplete && total.Downlink.Incomplete
			}
		}
		return false
	})
	ray.RemoveRay()
	root.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("native no-claim terminal: %+v %v", page, err)
	}
	flow := page.Rows[0].Flow
	if len(flow.Routes) != 1 || flow.Routes[0].Outbound.Tag != "native-no-claim" || flow.AccountingRoute.Outbound.Serial != 0 || flow.Uplink.Known != uint64(len(payload)) || !flow.Uplink.Incomplete || !flow.Downlink.Incomplete {
		t.Fatalf("native no-claim facts: %+v", page.Rows[0])
	}
}
