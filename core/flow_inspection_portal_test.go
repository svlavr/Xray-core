package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/proto"
)

func TestFlowInspectionPortalVMessCarrier(t *testing.T) {
	for _, test := range []struct {
		name         string
		enabled, mux bool
	}{
		{"tcp", true, false},
		{"mux-tcp", true, true},
		{"off-tcp", false, false},
		{"off-mux-tcp", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			portalCore, view, vmess := inspectionVMessReceiver(t, test.enabled, true)
			portal, err := reverse.NewPortal(&reverse.PortalConfig{Tag: "portal", Domain: "bridge.invalid"}, portalCore.GetFeature(fout.ManagerType()).(fout.Manager))
			if err != nil {
				t.Fatal(err)
			}
			if err = portal.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { portal.Close() })
			setInspectionRoute(t, portalCore, "portal")
			bridgeCore, _, _ := inspectionCore(t, false, false)
			carrierOutbound := proto.Clone(vmess).(*core.OutboundHandlerConfig)
			if test.mux {
				inspectionEnableOutboundMux(t, carrierOutbound)
			}
			if err := core.AddOutboundHandler(bridgeCore, carrierOutbound); err != nil {
				t.Fatal(err)
			}
			if err := bridgeCore.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "bridge.invalid"}}}}, TargetTag: &router.RoutingRule_Tag{Tag: carrierOutbound.Tag}}}}), true); err != nil {
				t.Fatal(err)
			}
			bridge, err := reverse.NewBridgeWorker("bridge.invalid", "bridge", bridgeCore.GetFeature(frouting.DispatcherType()).(frouting.Dispatcher))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { bridge.Worker.Close(); bridge.Timer.SetTimeout(0) })
			inspectionWait(t, func() bool { return bridge.Connections() > 0 })
			client, _, address := inspectionCore(t, false, false)
			if err := core.AddOutboundHandler(client, proto.Clone(vmess).(*core.OutboundHandlerConfig)); err != nil {
				t.Fatal(err)
			}
			setInspectionRoute(t, client, vmess.Tag)
			dest := startOutboundStatsTCPServer(t)
			payload := []byte("GET / HTTP/1.1\r\nHost: ordinary.invalid\r\n\r\n")
			a := inspectionSOCKS(t, address, dest, payload)
			b := inspectionSOCKS(t, address, dest, payload)
			if view == nil {
				a.Close()
				b.Close()
				c := inspectionSOCKS(t, address, dest, payload)
				c.Close()
				return
			}
			var first fs.FlowRef
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				if len(live.Rows) != 2 {
					return false
				}
				for _, r := range live.Rows {
					if r.InitialDestination != dest || r.Origin != fs.TrafficOriginUser || r.AccountingRoute.Outbound.Tag != "portal" || r.Uplink.Known != uint64(len(payload)) || r.Downlink.Known != uint64(len(payload)) {
						return false
					}
					first = r.Ref
				}
				return true
			})
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{first})
			if err != nil || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("stop: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 1
			})
			// A new sibling still traverses the same surviving reverse carrier.
			c := inspectionSOCKS(t, address, dest, payload)
			a.Close()
			b.Close()
			c.Close()
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 3
			})
			totals, _ := view.ReadTotals(context.Background())
			var up, down uint64
			for _, r := range totals.Rows {
				up += r.Uplink.Known
				down += r.Downlink.Known
				if r.Uplink.Known > 0 && r.Outbound.Tag != "portal" {
					t.Fatalf("carrier/control bucket: %+v", r)
				}
			}
			if up != uint64(3*len(payload)) || down != up {
				t.Fatalf("carrier/control counted: %d/%d", up, down)
			}
		})
	}
}

func TestFlowInspectionPortalUDPChildOnTCPCarrier(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled bool
	}{{"observed", true}, {"disabled", false}} {
		t.Run(test.name, func(t *testing.T) {
			inspectionPortalUDPChildOnTCPCarrier(t, test.enabled)
		})
	}
}

func inspectionPortalUDPChildOnTCPCarrier(t *testing.T, enabled bool) {
	const mask = byte(0x53)
	portalCore, view, vmess := inspectionVMessReceiver(t, enabled, true)
	portal, err := reverse.NewPortal(&reverse.PortalConfig{Tag: "portal", Domain: "bridge.invalid"}, portalCore.GetFeature(fout.ManagerType()).(fout.Manager))
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { portal.Close() })
	setInspectionRoute(t, portalCore, "portal")
	if err := portalCore.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "portal"}}}}), true); err != nil {
		t.Fatal(err)
	}

	serverDestination := startOutboundStatsUDPServer(t, mask)
	logicalDestination := cnet.UDPDestination(cnet.DomainAddress("bridge.invalid"), serverDestination.Port)
	bridgeCore, _, _ := inspectionCore(t, false, false)
	if err := core.AddOutboundHandler(bridgeCore, proto.Clone(vmess).(*core.OutboundHandlerConfig)); err != nil {
		t.Fatal(err)
	}
	if err := core.AddOutboundHandler(bridgeCore, &core.OutboundHandlerConfig{Tag: "udp-echo", ProxySettings: serial.ToTypedMessage(&freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(serverDestination.Address), Port: uint32(serverDestination.Port)}},
		FinalRules:          []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
	})}); err != nil {
		t.Fatal(err)
	}
	if err := bridgeCore.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{
		{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "bridge.invalid"}}}}, Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: vmess.Tag}},
		{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "bridge.invalid"}}}}, Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "udp-echo"}},
	}}), true); err != nil {
		t.Fatal(err)
	}
	bridge, err := reverse.NewBridgeWorker("bridge.invalid", "bridge", bridgeCore.GetFeature(frouting.DispatcherType()).(frouting.Dispatcher))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Worker.Close(); bridge.Timer.SetTimeout(0) })
	inspectionWait(t, func() bool { return bridge.Connections() > 0 })

	_, _, address := inspectionUDPInboundThrough(t, logicalDestination, false, false, proto.Clone(vmess).(*core.OutboundHandlerConfig))
	first := inspectionUDPClient(t)
	firstPayload := []byte("reverse udp first")
	inspectionUDPExchange(t, first, address, firstPayload, mask)
	if view == nil {
		second := inspectionUDPClient(t)
		inspectionUDPExchange(t, second, address, []byte("reverse udp disabled sibling"), mask)
		return
	}
	var firstRef fs.FlowRef
	inspectionWait(t, func() bool {
		live, readErr := view.ReadLive(context.Background())
		if readErr != nil || len(live.Rows) != 1 {
			return false
		}
		row := live.Rows[0]
		if row.Kind != fs.FlowKindUDPAssociation || row.Origin != fs.TrafficOriginUser || row.InitialDestination != logicalDestination || row.AccountingRoute.Outbound.Tag != "portal" || row.Uplink.Known != uint64(len(firstPayload)) || row.Downlink.Known != uint64(len(firstPayload)) {
			return false
		}
		firstRef = row.Ref
		return true
	})
	out, err := view.CloseFlows(context.Background(), []fs.FlowRef{firstRef})
	if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("stop first UDP child: %+v %v", out, err)
	}
	inspectionWait(t, func() bool {
		page, readErr := view.ReadTerminals(context.Background())
		return readErr == nil && len(page.Rows) == 1 && page.Rows[0].Reason == fs.EndReasonLocalStop
	})
	if bridge.Connections() == 0 {
		t.Fatal("stopping UDP child closed the reverse carrier")
	}
	second := inspectionUDPClient(t)
	secondPayload := []byte("reverse udp sibling")
	inspectionUDPExchange(t, second, address, secondPayload, mask)
	inspectionWait(t, func() bool {
		live, readErr := view.ReadLive(context.Background())
		return readErr == nil && len(live.Rows) == 1 && live.Rows[0].Ref != firstRef && live.Rows[0].AccountingRoute.Outbound.Tag == "portal" && live.Rows[0].Uplink.Known == uint64(len(secondPayload)) && live.Rows[0].Downlink.Known == uint64(len(secondPayload))
	})
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var up, down uint64
	for _, row := range totals.Rows {
		up += row.Uplink.Known
		down += row.Downlink.Known
		if row.Uplink.Known != 0 && row.Outbound.Tag != "portal" {
			t.Fatalf("reverse carrier counted as a logical outbound: %+v", row)
		}
	}
	if want := uint64(len(firstPayload) + len(secondPayload)); up != want || down != want {
		t.Fatalf("reverse UDP totals: up=%d down=%d want=%d", up, down, want)
	}
}

func setInspectionRoute(t *testing.T, instance *core.Instance, tag string) {
	t.Helper()
	if err := instance.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: tag}}}}), true); err != nil {
		t.Fatal(err)
	}
}

func TestFlowInspectionPortalDomainThroughFreedom(t *testing.T) {
	remote, view, vmess := inspectionVMessReceiver(t, true, true)
	portal, err := reverse.NewPortal(&reverse.PortalConfig{Tag: "portal", Domain: "bridge.invalid"}, remote.GetFeature(fout.ManagerType()).(fout.Manager))
	if err != nil {
		t.Fatal(err)
	}
	if err = portal.Start(); err != nil {
		t.Fatal(err)
	}
	defer portal.Close()
	dest := startOutboundStatsTCPServer(t)
	if err := core.AddOutboundHandler(remote, &core.OutboundHandlerConfig{Tag: "same-domain", ProxySettings: serial.ToTypedMessage(&freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(dest.Address), Port: uint32(dest.Port)}},
		FinalRules:          []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
	})}); err != nil {
		t.Fatal(err)
	}
	setInspectionRoute(t, remote, "same-domain")
	client, _, _ := inspectionCore(t, false, false)
	if err := core.AddOutboundHandler(client, vmess); err != nil {
		t.Fatal(err)
	}
	setInspectionRoute(t, client, vmess.Tag)
	target := cnet.TCPDestination(cnet.DomainAddress("bridge.invalid"), dest.Port)
	conn, err := core.Dial(context.Background(), client, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("GET / HTTP/1.1\r\nHost: ordinary.invalid\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	inspectionResponse(t, conn, payload)
	inspectionWait(t, func() bool {
		live, _ := view.ReadLive(context.Background())
		if len(live.Rows) != 1 {
			return false
		}
		r := live.Rows[0]
		return r.InitialDestination == target && r.AccountingRoute.Outbound.Tag == "same-domain" && r.AccountingRoute.Effective == dest && r.Uplink.Known == uint64(len(payload)) && r.Downlink.Known == uint64(len(payload))
	})
	conn.Close()
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1
	})
}
