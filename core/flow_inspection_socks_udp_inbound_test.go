package core_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func inspectionSOCKSUDPListener(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, string) {
	t.Helper()
	instance, view, _ := inspectionCore(t, enabled, false)
	port := tcp.PickPort()
	if err := core.AddInboundHandler(instance, &core.InboundHandlerConfig{
		Tag: "observed-udp-socks",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:           cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList:         &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"quic"}},
		}),
		ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UdpEnabled: true}),
	}); err != nil {
		t.Fatal(err)
	}
	return instance, view, net.JoinHostPort("127.0.0.1", port.String())
}

func inspectionSOCKSAssociation(t *testing.T, address string) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	control, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	control.SetDeadline(time.Now().Add(5 * time.Second))
	response, err := socks.ClientHandshake(&protocol.RequestHeader{Command: protocol.RequestCommandUDP}, control, control)
	if err != nil {
		t.Fatal(err)
	}
	control.SetDeadline(time.Time{})
	return control, inspectionUDPClient(t), &net.UDPAddr{IP: response.Address.IP(), Port: int(response.Port)}
}

func inspectionSOCKSPacket(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, dest cnet.Destination, payload []byte, mask byte) {
	t.Helper()
	message, err := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: dest.Address, Port: dest.Port}, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer message.Release()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.WriteToUDP(message.Bytes(), relay); err != nil {
		t.Fatal(err)
	}
	response := buf.New()
	defer response.Release()
	if _, err := response.ReadFrom(client); err != nil {
		t.Fatal(err)
	}
	request, err := socks.DecodeUDPPacket(response)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), payload...)
	for i := range want {
		want[i] ^= mask
	}
	if request.Destination() != dest || !bytes.Equal(response.Bytes(), want) {
		t.Fatalf("response destination/payload: %+v %q", request, response.Bytes())
	}
}

func TestFlowInspectionSOCKSUDPInbound(t *testing.T) {
	for _, variant := range []string{"enabled", "sniff", "disabled"} {
		t.Run(variant, func(t *testing.T) {
			instance, view, address := inspectionSOCKSUDPListener(t, variant != "disabled", variant == "sniff")
			firstDest, secondDest := startOutboundStatsUDPServer(t, 0x19), startOutboundStatsUDPServer(t, 0x37)
			control, client, relay := inspectionSOCKSAssociation(t, address)
			siblingControl, sibling, siblingRelay := inspectionSOCKSAssociation(t, address)
			payload, extra := []byte("decoded UDP input and response"), []byte("another packet destination")
			inspectionSOCKSPacket(t, client, relay, firstDest, payload, 0x19)
			inspectionSOCKSPacket(t, client, relay, secondDest, extra, 0x37)
			inspectionSOCKSPacket(t, sibling, siblingRelay, firstDest, payload, 0x19)
			if variant == "disabled" {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled collection allocated store")
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
					if len(row.Destinations) == 2 {
						selected = row
					}
				}
				return selected.Uplink.Known == uint64(len(payload)+len(extra)) && selected.Downlink.Known == selected.Uplink.Known
			})
			// The association begins before the first datagram with unavailable
			// peer and target. The first accepted packet fills the native peer;
			// destinations and the consuming route arrive with actual rays.
			if selected.Kind != fs.FlowKindUDPAssociation || selected.Origin != fs.TrafficOriginUser || selected.Source != cnet.DestinationFromAddr(client.LocalAddr()) || selected.InitialDestination.IsValid() || selected.AccountingRoute.Outbound.Tag != "direct" || selected.AccountingRoute.Outbound.Serial == 0 || len(selected.Routes) != 1 || len(selected.Destinations) != 2 || selected.Uplink.Incomplete || selected.Downlink.Incomplete {
				t.Fatalf("association facts: %+v", selected)
			}
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("exact association stop: %+v %v", out, err)
			}
			control.SetReadDeadline(time.Now().Add(3 * time.Second))
			if n, err := control.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("associated TCP did not close: %d %v", n, err)
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal(err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				return err == nil && len(page.Rows) == 1 && page.Rows[0].Flow.Ref == selected.Ref && page.Rows[0].Reason == fs.EndReasonLocalStop
			})
			inspectionSOCKSPacket(t, sibling, siblingRelay, secondDest, extra, 0x37)
			siblingControl.Close()
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				return err == nil && len(page.Rows) == 2
			})
			totals, err := view.ReadTotals(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var up, down uint64
			for _, row := range totals.Rows {
				up += row.Uplink.Known
				down += row.Downlink.Known
				if row.Uplink.Known != 0 && (row.Outbound != selected.AccountingRoute.Outbound || row.Uplink.Incomplete || row.Downlink.Incomplete) {
					t.Fatalf("association totals: %+v", row)
				}
			}
			want := uint64(2 * (len(payload) + len(extra)))
			if up != want || down != want {
				t.Fatalf("framing/double count/loss: %d/%d want %d", up, down, want)
			}
		})
	}
}

func TestFlowInspectionSOCKSUDPInboundPreFirstPayload(t *testing.T) {
	_, view, address := inspectionSOCKSUDPListener(t, true, false)
	control, _, _ := inspectionSOCKSAssociation(t, address)
	var association fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		association = live.Rows[0]
		return association.Ref.ID != 0
	})
	if association.Kind != fs.FlowKindUDPAssociation || association.Origin != fs.TrafficOriginUser || association.Source.IsValid() || association.InitialDestination.IsValid() || len(association.Destinations) != 0 || len(association.Routes) != 0 || association.Uplink.Known != 0 || association.Downlink.Known != 0 || association.Uplink.Incomplete || association.Downlink.Incomplete {
		t.Fatalf("pre-first association: %+v", association)
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{association.Ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("pre-first exact stop: %+v %v", outcomes, err)
	}
	control.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := control.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("pre-first control connection remained open: %d %v", n, err)
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal(err)
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		return err == nil && len(page.Rows) == 1 && page.Rows[0].Flow.Ref == association.Ref && page.Rows[0].Reason == fs.EndReasonLocalStop
	})
}

// A decoded rejected request still has one association; native missing-route
// rejection is complete without inventing a successful default selection.
func TestFlowInspectionSOCKSUDPInboundRejected(t *testing.T) {
	instance, view, address := inspectionSOCKSUDPListener(t, true, false)
	manager := instance.GetFeature(fout.ManagerType()).(fout.Manager)
	if err := manager.RemoveHandler(context.Background(), "direct"); err != nil {
		t.Fatal(err)
	}
	control, client, relay := inspectionSOCKSAssociation(t, address)
	message, _ := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: cnet.LocalHostIP, Port: 53}, []byte("rejected payload"))
	defer message.Release()
	if _, err := client.WriteToUDP(message.Bytes(), relay); err != nil {
		t.Fatal(err)
	}
	inspectionWait(t, func() bool {
		live, _ := view.ReadLive(context.Background())
		return len(live.Rows) == 1 && len(live.Rows[0].Routes) != 0 && live.Rows[0].Routes[0].Selection == fs.SelectionRejected
	})
	control.Close()
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1 && page.Rows[0].Flow.Uplink.Known == uint64(len("rejected payload")) && page.Rows[0].Flow.Downlink.Known == 0
	})
}

func TestFlowInspectionSOCKSUDPInboundStopAfterRejection(t *testing.T) {
	instance, view, address := inspectionSOCKSUDPListener(t, true, false)
	if err := instance.GetFeature(fout.ManagerType()).(fout.Manager).RemoveHandler(context.Background(), "direct"); err != nil {
		t.Fatal(err)
	}
	_, client, relay := inspectionSOCKSAssociation(t, address)
	message, _ := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: cnet.LocalHostIP, Port: 53}, []byte("rejected before exact stop"))
	defer message.Release()
	if _, err := client.WriteToUDP(message.Bytes(), relay); err != nil {
		t.Fatal(err)
	}
	var ref fs.FlowRef
	inspectionWait(t, func() bool {
		live, _ := view.ReadLive(context.Background())
		if len(live.Rows) != 1 || len(live.Rows[0].Routes) == 0 || live.Rows[0].Routes[0].Selection != fs.SelectionRejected {
			return false
		}
		ref = live.Rows[0].Ref
		return true
	})
	result, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || result[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("stop after ray rejection: %+v %v", result, err)
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		if len(page.Rows) != 1 {
			return false
		}
		if page.Rows[0].Reason != fs.EndReasonLocalStop {
			t.Fatalf("earlier ray rejection defeated exact association stop: %+v", page.Rows[0])
		}
		return true
	})
}
