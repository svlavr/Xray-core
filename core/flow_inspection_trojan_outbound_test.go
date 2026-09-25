package core_test

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func inspectionTrojanConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	_, _, outbound := inspectionTrojanReceiver(t, false, false)
	return outbound
}

func inspectionTrojanReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	// The receiving core exercises native Trojan codecs and forwarding. Its
	// observation is selected independently by the inbound P2 acceptance cases.
	remote, view, _ := inspectionCore(t, enabled, false)
	port := tcp.PickPort()
	user := &protocol.User{Account: serial.ToTypedMessage(&trojan.Account{Password: "inspection-test-only"})}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:           cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList:         &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http"}},
		}),
		ProxySettings: serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{user}}),
	}); err != nil {
		t.Fatal(err)
	}
	outbound := &core.OutboundHandlerConfig{Tag: "trojan-proxy", ProxySettings: serial.ToTypedMessage(&trojan.ClientConfig{
		Server: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(port), User: user},
	})}
	return remote, view, outbound
}

func inspectionTCPOutboundThrough(t *testing.T, enabled bool, outbound *core.OutboundHandlerConfig) (*core.Instance, fs.FlowInspection, string) {
	t.Helper()
	instance, view, address := inspectionCore(t, enabled, true)
	if err := core.AddOutboundHandler(instance, outbound); err != nil {
		t.Fatal(err)
	}
	routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: outbound.Tag},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	return instance, view, address
}

func inspectionOutboundTotals(t *testing.T, view fs.FlowInspection, tag string, want uint64) {
	t.Helper()
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var up, down uint64
	for _, row := range totals.Rows {
		if row.Uplink.Known == 0 && row.Downlink.Known == 0 {
			continue
		}
		if row.Outbound.Tag != tag || row.Outbound.Serial == 0 || row.Origin != fs.TrafficOriginUser || row.Uplink.Incomplete || row.Downlink.Incomplete {
			t.Fatalf("outbound attribution: %+v", row)
		}
		up += row.Uplink.Known
		down += row.Downlink.Known
	}
	if up != want || down != want {
		t.Fatalf("framing included or payload lost: %d/%d want %d", up, down, want)
	}
}

func TestFlowInspectionTrojanOutboundTCP(t *testing.T) {
	inspectionOutboundTCP(t, inspectionTrojanConfig)
}

func inspectionOutboundTCP(t *testing.T, config func(*testing.T) *core.OutboundHandlerConfig) {
	t.Helper()
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			outbound := config(t)
			instance, view, address := inspectionTCPOutboundThrough(t, enabled, outbound)
			destination := startOutboundStatsTCPServer(t)
			payload := append([]byte("GET / HTTP/1.1\r\nHost: trojan-outbound.invalid\r\n\r\n"), bytes.Repeat([]byte("p"), 8192)...)
			first := inspectionSOCKS(t, address, destination, payload)
			sibling := inspectionSOCKS(t, address, destination, payload)
			if !enabled {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled outbound acquired inspection state")
				}
				return
			}
			var selected fs.FlowRef
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				if len(live.Rows) != 2 {
					return false
				}
				for _, row := range live.Rows {
					if row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) || row.Uplink.Incomplete || row.Downlink.Incomplete {
						return false
					}
					if row.AccountingRoute.Outbound.Tag != outbound.Tag || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != destination || row.Origin != fs.TrafficOriginUser || row.Uplink.Incomplete || row.Downlink.Incomplete {
						t.Fatalf("outbound TCP live facts: %+v", row)
					}
					if row.Source.Port == cnet.Port(first.LocalAddr().(*net.TCPAddr).Port) {
						selected = row.Ref
					}
				}
				return selected.ID != 0
			})
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected})
			if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("outbound exact stop: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected && page.Rows[0].Reason == fs.EndReasonLocalStop
			})
			if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("stopped outbound endpoint returned %d, %v", n, err)
			}
			extra := []byte("Trojan sibling after exact stop")
			if _, err := sibling.Write(extra); err != nil {
				t.Fatal(err)
			}
			inspectionResponse(t, sibling, extra)
			sibling.Close()
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 2
			})
			inspectionOutboundTotals(t, view, outbound.Tag, uint64(2*len(payload)+len(extra)))
		})
	}
}

func TestFlowInspectionTrojanOutboundUDP(t *testing.T) {
	inspectionOutboundUDP(t, inspectionTrojanConfig)
}

func inspectionOutboundUDP(t *testing.T, config func(*testing.T) *core.OutboundHandlerConfig) {
	t.Helper()
	for _, variant := range []string{"enabled", "resolved", "disabled"} {
		t.Run(variant, func(t *testing.T) {
			const mask = byte(0x59)
			destination := startOutboundStatsUDPServer(t, mask)
			if variant == "resolved" {
				destination.Address = cnet.DomainAddress("localhost")
			}
			outbound := config(t)
			instance, view, address := inspectionUDPInboundThrough(t, destination, variant != "disabled", variant == "resolved", outbound)
			client := inspectionUDPClient(t)
			payload := []byte("Trojan UDP payload without protocol framing")
			inspectionUDPExchange(t, client, address, payload, mask)
			if variant == "disabled" {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled outbound UDP acquired inspection state")
				}
				return
			}
			var selected fs.FlowRecord
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				if len(live.Rows) != 1 || live.Rows[0].Uplink.Known != uint64(len(payload)) || live.Rows[0].Downlink.Known != uint64(len(payload)) {
					return false
				}
				selected = live.Rows[0]
				return true
			})
			if selected.Kind != fs.FlowKindUDPAssociation || selected.InitialDestination != destination || selected.AccountingRoute.Outbound.Tag != outbound.Tag || selected.AccountingRoute.Outbound.Serial == 0 || len(selected.Destinations) != 1 || selected.Destinations[0] != destination {
				t.Fatalf("outbound UDP live facts: %+v", selected)
			}
			if variant == "resolved" {
				if !selected.AccountingRoute.Effective.Address.Family().IsIP() || selected.AccountingRoute.Effective.Port != destination.Port {
					t.Fatalf("resolved target: %+v", selected.AccountingRoute)
				}
			} else if selected.AccountingRoute.Effective != destination {
				t.Fatalf("physical server replaced logical target: %+v", selected.AccountingRoute)
			}
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("outbound UDP stop: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected.Ref && page.Rows[0].Reason == fs.EndReasonLocalStop
			})
			inspectionOutboundTotals(t, view, outbound.Tag, uint64(len(payload)))
		})
	}
}

func TestFlowInspectionTrojanOutboundUDPBatch(t *testing.T) {
	instance, view, _ := inspectionUDPInboundThrough(t, cnet.UDPDestination(cnet.LocalHostIP, 9), true, false, inspectionTrojanConfig(t))
	inspectionUDPBatchThrough(t, instance, view, "trojan-proxy")
}

func TestFlowInspectionTrojanOutboundPreparationFailure(t *testing.T) {
	outbound := inspectionTrojanConfig(t)
	message, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	config := message.(*trojan.ClientConfig)
	// Native Process rejects a non-Trojan account after Dial, before starting
	// either copy task. No observed endpoint payload is read by this branch.
	config.Server.User.Account = serial.ToTypedMessage(&socks.Account{})
	outbound.ProxySettings = serial.ToTypedMessage(config)
	inspectionOutboundPreparationFailure(t, outbound)
}

func inspectionOutboundPreparationFailure(t *testing.T, outbound *core.OutboundHandlerConfig) {
	t.Helper()
	_, view, address := inspectionTCPOutboundThrough(t, true, outbound)
	client := inspectionSOCKS(t, address, cnet.TCPDestination(cnet.LocalHostIP, 80), nil)
	payload := []byte("GET / HTTP/1.1\r\nHost: preparation.invalid\r\n\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		if len(page.Rows) != 1 {
			return false
		}
		row := page.Rows[0].Flow
		if row.AccountingRoute.Outbound.Tag != outbound.Tag || row.AccountingRoute.Outbound.Serial == 0 || row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != 0 || row.Uplink.Incomplete || row.Downlink.Incomplete {
			t.Fatalf("failed preparation lost sniff credit or invented payload: %+v", row)
		}
		return true
	})
}
