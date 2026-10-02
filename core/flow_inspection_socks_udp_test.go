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
				live, err := view.ReadLive()
				if err != nil || len(live.Rows) != 2 {
					return false
				}
				for _, row := range live.Rows {
					if row.Uplink != uint64(len(payload)) || row.Downlink != uint64(len(payload)) {
						return false
					}
					if row.Kind != cnet.Network_UDP || row.Origin != fs.TrafficOriginUser || row.Outbound.Tag != "socks-proxy" || row.Outbound.Tag == "" ||
						row.Destination != destination {
						t.Fatalf("SOCKS UDP logical facts: %+v", row)
					}
					if row.Source.Port == cnet.Port(first.LocalAddr().(*net.UDPAddr).Port) {
						selected = row
					}
				}
				return selected.Ref.ID != 0
			})
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
				t.Fatalf("SOCKS UDP exact stop: %+v %v", outcomes, err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals()
				return err == nil && len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected.Ref
			})
			extra := []byte("SOCKS UDP sibling survives")
			inspectionUDPExchange(t, sibling, address, extra, mask)
			var live fs.LiveSnapshot
			inspectionWait(t, func() bool {
				live, err = view.ReadLive()
				want := uint64(len(payload) + len(extra))
				return err == nil && len(live.Rows) == 1 && live.Rows[0].Uplink >= want && live.Rows[0].Downlink >= want
			})
			if outcomes, err = view.CloseFlows(context.Background(), []fs.FlowRef{live.Rows[0].Ref}); err != nil || outcomes[0] != nil {
				t.Fatalf("sibling stop: %+v %v", outcomes, err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals()
				return err == nil && len(page.Rows) == 2
			})
			totals, err := view.ReadTotals()
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(2*len(payload) + len(extra))
			var up, down uint64
			for _, total := range totals.Rows {
				if total.Uplink != 0 || total.Downlink != 0 {
					if total.Outbound != selected.Outbound || total.Origin != fs.TrafficOriginUser {
						t.Fatalf("SOCKS UDP totals: %+v", total)
					}
					up += total.Uplink
					down += total.Downlink
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
		page, err := view.ReadTerminals()
		if err != nil || len(page.Rows) != 1 {
			return false
		}
		row := page.Rows[0].Flow
		if row.Kind != cnet.Network_UDP || row.Outbound.Tag != "socks-proxy" || row.Outbound.Tag == "" || row.Uplink != 0 || row.Downlink != 0 {
			t.Fatalf("failed UDP handshake fabricated payload: %+v", row)
		}
		return true
	})
}
