package core_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

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
	// A peer can read the last response before the endpoint Write returns and
	// publishes its byte credit. Keep the existing inspectionWait deadline.
	deadline := time.Now().Add(5 * time.Second)
	for {
		totals, err := view.ReadTotals()
		if err != nil {
			t.Fatal(err)
		}
		var up, down uint64
		for _, row := range totals.Rows {
			if row.Uplink == 0 && row.Downlink == 0 {
				continue
			}
			if row.Outbound.Tag != tag || row.Outbound.Tag == "" || row.Origin != fs.TrafficOriginUser {
				t.Fatalf("outbound attribution: %+v", row)
			}
			up += row.Uplink
			down += row.Downlink
		}
		if up == want && down == want {
			return
		}
		if up > want || down > want || !time.Now().Before(deadline) {
			t.Fatalf("framing included or payload lost: %d/%d want %d", up, down, want)
		}
		time.Sleep(time.Millisecond)
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
				live, _ := view.ReadLive()
				if len(live.Rows) != 2 {
					return false
				}
				for _, row := range live.Rows {
					if row.Uplink != uint64(len(payload)) || row.Downlink != uint64(len(payload)) {
						return false
					}
					if row.Outbound.Tag != outbound.Tag || row.Outbound.Tag == "" || row.Destination != destination || row.Origin != fs.TrafficOriginUser {
						t.Fatalf("outbound TCP live facts: %+v", row)
					}
					if row.Source.Port == cnet.Port(first.LocalAddr().(*net.TCPAddr).Port) {
						selected = row.Ref
					}
				}
				return selected.ID != 0
			})
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected})
			if err != nil || len(out) != 1 || out[0] != nil {
				t.Fatalf("outbound exact stop: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals()
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected
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
				page, _ := view.ReadTerminals()
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
				live, _ := view.ReadLive()
				if len(live.Rows) != 1 || live.Rows[0].Uplink != uint64(len(payload)) || live.Rows[0].Downlink != uint64(len(payload)) {
					return false
				}
				selected = live.Rows[0]
				return true
			})
			if selected.Kind != cnet.Network_UDP || selected.Destination != destination || selected.Outbound.Tag != outbound.Tag || selected.Outbound.Tag == "" {
				t.Fatalf("outbound UDP live facts: %+v", selected)
			}
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || len(out) != 1 || out[0] != nil {
				t.Fatalf("outbound UDP stop: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals()
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected.Ref
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
		page, _ := view.ReadTerminals()
		if len(page.Rows) != 1 {
			return false
		}
		row := page.Rows[0].Flow
		if row.Outbound.Tag != outbound.Tag || row.Outbound.Tag == "" || row.Uplink != uint64(len(payload)) || row.Downlink != 0 {
			t.Fatalf("failed preparation lost sniff credit or invented payload: %+v", row)
		}
		return true
	})
}
