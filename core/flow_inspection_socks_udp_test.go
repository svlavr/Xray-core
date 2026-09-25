package core_test

import (
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// The receiving core deliberately remains unobserved: this slice proves the
// sending instance's supplied UDP endpoint and SOCKS outbound owner. Receiving
// SOCKS callback/ray observation is a separate, still-required integration.
func inspectionSOCKSUDPRemote(t *testing.T, allowUDP bool) string {
	t.Helper()
	instance, _, _ := inspectionCore(t, false, false)
	port := tcp.PickPort()
	err := core.AddInboundHandler(instance, &core.InboundHandlerConfig{
		Tag: "udp-socks-server",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
		}),
		ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UdpEnabled: allowUDP}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", port.String())
}

func inspectionSOCKSUDPConfig(t *testing.T, remote string) *core.OutboundHandlerConfig {
	t.Helper()
	host, portString, err := net.SplitHostPort(remote)
	if err != nil {
		t.Fatal(err)
	}
	port, err := cnet.PortFromString(portString)
	if err != nil {
		t.Fatal(err)
	}
	return &core.OutboundHandlerConfig{Tag: "socks-proxy", ProxySettings: serial.ToTypedMessage(&socks.ClientConfig{
		Server: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.ParseAddress(host)), Port: uint32(port)},
	})}
}

func TestFlowInspectionSOCKSUDPOutbound(t *testing.T) {
	for _, variant := range []string{"enabled", "resolved", "disabled"} {
		t.Run(variant, func(t *testing.T) {
			const mask = byte(0x59)
			remote := inspectionSOCKSUDPRemote(t, true)
			destination := startOutboundStatsUDPServer(t, mask)
			if variant == "resolved" {
				destination.Address = cnet.DomainAddress("localhost")
			}
			instance, view, address := inspectionUDPInboundThrough(t, destination, variant != "disabled", variant == "resolved", inspectionSOCKSUDPConfig(t, remote))
			first, sibling := inspectionUDPClient(t), inspectionUDPClient(t)
			payload := []byte("SOCKS UDP payload excludes handshake and packet framing")
			inspectionUDPExchange(t, first, address, payload, mask)
			inspectionUDPExchange(t, sibling, address, payload, mask)
			if variant == "disabled" {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled SOCKS UDP allocated inspection state")
				}
				return
			}
			var selected fs.FlowRecord
			inspectionWait(t, func() bool {
				live, err := view.ReadLive(context.Background())
				if err != nil || len(live.Rows) != 2 {
					return false
				}
				for _, row := range live.Rows {
					if row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) || row.Uplink.Incomplete || row.Downlink.Incomplete {
						return false
					}
					if row.Kind != fs.FlowKindUDPAssociation || row.Origin != fs.TrafficOriginUser || row.AccountingRoute.Outbound.Tag != "socks-proxy" || row.AccountingRoute.Outbound.Serial == 0 ||
						row.InitialDestination != destination || len(row.Destinations) != 1 || row.Destinations[0] != destination || row.Uplink.Incomplete || row.Downlink.Incomplete {
						t.Fatalf("SOCKS UDP logical facts: %+v", row)
					}
					if variant == "resolved" {
						if !row.AccountingRoute.Effective.Address.Family().IsIP() || row.AccountingRoute.Effective.Port != destination.Port {
							t.Fatalf("resolved logical target: %+v", row.AccountingRoute)
						}
					} else if row.AccountingRoute.Effective != destination {
						t.Fatalf("physical server became logical target: %+v", row.AccountingRoute)
					}
					if row.Source.Port == cnet.Port(first.LocalAddr().(*net.UDPAddr).Port) {
						selected = row
					}
				}
				return selected.Ref.ID != 0
			})
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("SOCKS UDP exact stop: %+v %v", outcomes, err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				return err == nil && len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected.Ref && page.Rows[0].Reason == fs.EndReasonLocalStop
			})
			extra := []byte("SOCKS UDP sibling survives")
			inspectionUDPExchange(t, sibling, address, extra, mask)
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 {
				t.Fatalf("sibling live facts: %+v %v", live, err)
			}
			if outcomes, err = view.CloseFlows(context.Background(), []fs.FlowRef{live.Rows[0].Ref}); err != nil || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("sibling stop: %+v %v", outcomes, err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				return err == nil && len(page.Rows) == 2
			})
			totals, err := view.ReadTotals(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(2*len(payload) + len(extra))
			var up, down uint64
			for _, total := range totals.Rows {
				if total.Uplink.Known != 0 || total.Downlink.Known != 0 {
					if total.Outbound != selected.AccountingRoute.Outbound || total.Origin != fs.TrafficOriginUser || total.Uplink.Incomplete || total.Downlink.Incomplete {
						t.Fatalf("SOCKS UDP totals: %+v", total)
					}
					up += total.Uplink.Known
					down += total.Downlink.Known
				}
			}
			if up != want || down != want {
				t.Fatalf("framing included or payload lost: %d/%d want %d", up, down, want)
			}
		})
	}
}

func TestFlowInspectionSOCKSUDPOutboundBatch(t *testing.T) {
	remote := inspectionSOCKSUDPRemote(t, true)
	instance, view, _ := inspectionUDPInboundThrough(t, cnet.UDPDestination(cnet.LocalHostIP, 9), true, false, inspectionSOCKSUDPConfig(t, remote))
	inspectionUDPBatchThrough(t, instance, view, "socks-proxy")
}

func TestFlowInspectionSOCKSUDPOutboundRejected(t *testing.T) {
	remote := inspectionSOCKSUDPRemote(t, false)
	destination := cnet.UDPDestination(cnet.LocalHostIP, 9)
	_, view, address := inspectionUDPInboundThrough(t, destination, true, false, inspectionSOCKSUDPConfig(t, remote))
	client := inspectionUDPClient(t)
	if _, err := client.WriteToUDP([]byte("queued payload is not consumed by a failed handshake"), address); err != nil {
		t.Fatal(err)
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil || len(page.Rows) != 1 {
			return false
		}
		row := page.Rows[0].Flow
		if row.Kind != fs.FlowKindUDPAssociation || row.AccountingRoute.Outbound.Tag != "socks-proxy" || row.AccountingRoute.Outbound.Serial == 0 || row.Uplink.Known != 0 || row.Downlink.Known != 0 || row.Uplink.Incomplete || row.Downlink.Incomplete {
			t.Fatalf("failed UDP handshake fabricated payload: %+v", row)
		}
		return true
	})
}
