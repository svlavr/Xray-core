package core_test

import (
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestFlowInspectionMuxServerTCP(t *testing.T) {
	inspectionDecodedTCPReceiverAcceptance(t, func(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
		instance, view, outbound := inspectionVMessReceiver(t, enabled, sniff)
		inspectionEnableOutboundMux(t, outbound)
		return instance, view, outbound
	})
}

// A decoded child is observable; its carrier must add neither another row nor
// framing bytes. Shared by earlier protocol-specific carrier exclusions.
func inspectionOnlyMuxFlow(t *testing.T, view fs.FlowInspection, conn net.Conn, destination cnet.Destination, payload []byte, tag string) {
	t.Helper()
	var ref fs.FlowRef
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		r := live.Rows[0]
		if r.InitialDestination != destination || r.AccountingRoute.Outbound.Tag != tag || r.AccountingRoute.Outbound.Serial == 0 || r.AccountingRoute.Effective != destination || r.Origin != fs.TrafficOriginUser {
			t.Fatalf("MUX logical owner: %+v", r)
		}
		ref = r.Ref
		return r.Uplink.Known == uint64(len(payload)) && r.Downlink.Known == uint64(len(payload))
	})
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 0 {
		t.Fatalf("carrier produced terminal: %+v %v", page, err)
	}
	conn.Close()
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == ref
	})
	totals, _ := view.ReadTotals(context.Background())
	var up, down uint64
	for _, r := range totals.Rows {
		up += r.Uplink.Known
		down += r.Downlink.Known
	}
	if up != uint64(len(payload)) || down != up {
		t.Fatalf("MUX framing/control counted: %d/%d", up, down)
	}
}

func TestFlowInspectionMuxServerUDP(t *testing.T) {
	for _, test := range []struct {
		name          string
		receiver      inspectionSuppliedTCPReceiver
		mux, retained bool
	}{
		{"ordinary-mux", inspectionVMessReceiver, true, false},
		{"retained-mux", inspectionVMessReceiver, true, true},
		{"vless-direct-xudp", inspectionVLESSReceiver, false, true},
		{"vless-encrypted-xudp", inspectionVLESSEncryptedReceiver, false, true},
		{"vision-direct-xudp", inspectionVisionReceiver, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.retained {
				t.Setenv("xray.cone.disabled", "false")
			} else {
				t.Setenv("xray.cone.disabled", "true")
			}
			_, remote, outbound := test.receiver(t, true, false)
			if test.mux {
				inspectionEnableOutboundMux(t, outbound)
			}
			instance, local, address := inspectionSOCKSUDPListener(t, true, false)
			if err := core.AddOutboundHandler(instance, outbound); err != nil {
				t.Fatal(err)
			}
			if err := instance.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: outbound.Tag}}}}), true); err != nil {
				t.Fatal(err)
			}
			destination := startOutboundStatsUDPServer(t, 0x25)
			client := inspectionUDPClient(t)
			var retainedRef fs.FlowRef
			var total uint64
			count := 1
			if test.retained {
				count = 2
			}
			for i := 0; i < count; i++ {
				control, unused, relay := inspectionSOCKSAssociation(t, address)
				unused.Close()
				payload := []byte("decoded mux server datagram")
				inspectionSOCKSPacket(t, client, relay, destination, payload, 0x25)
				total += uint64(len(payload))
				var row fs.FlowRecord
				inspectionWait(t, func() bool {
					live, _ := remote.ReadLive(context.Background())
					if len(live.Rows) != 1 {
						return false
					}
					row = live.Rows[0]
					return row.Uplink.Known == total && row.Downlink.Known == total
				})
				if row.Kind != fs.FlowKindUDPAssociation || row.Origin != fs.TrafficOriginUser || row.AccountingRoute.Outbound.Tag != "direct" || row.AccountingRoute.Effective != destination || row.Uplink.Incomplete || row.Downlink.Incomplete {
					t.Fatalf("server facts: %+v", row)
				}
				if i > 0 && row.Ref != retainedRef {
					t.Fatal("retained association changed ref")
				}
				retainedRef = row.Ref
				var clientRef fs.FlowRef
				inspectionWait(t, func() bool {
					live, _ := local.ReadLive(context.Background())
					for _, r := range live.Rows {
						if r.Source.Port == cnet.Port(client.LocalAddr().(*net.UDPAddr).Port) && r.Uplink.Known == uint64(len(payload)) && r.Downlink.Known == uint64(len(payload)) {
							clientRef = r.Ref
							return true
						}
					}
					return false
				})
				out, err := local.CloseFlows(context.Background(), []fs.FlowRef{clientRef})
				if err != nil || out[0].Code != fs.CloseCodeAccepted {
					t.Fatalf("client stop: %+v %v", out, err)
				}
				inspectionWait(t, func() bool { live, _ := local.ReadLive(context.Background()); return len(live.Rows) == 0 })
				control.Close()
			}
			if test.retained {
				out, err := remote.CloseFlows(context.Background(), []fs.FlowRef{retainedRef})
				if err != nil || out[0].Code != fs.CloseCodeAccepted {
					t.Fatalf("retained stop: %+v %v", out, err)
				}
			}
			inspectionWait(t, func() bool {
				page, _ := remote.ReadTerminals(context.Background())
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == retainedRef
			})
			inspectionOutboundTotals(t, remote, "direct", total)
		})
	}
}
