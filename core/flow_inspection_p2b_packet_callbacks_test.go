package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/socks"
)

func inspectionPacketCallbackSender(t *testing.T, outbound *core.OutboundHandlerConfig) string {
	t.Helper()
	sender, _, address := inspectionSOCKSUDPListener(t, false, false)
	if err := core.AddOutboundHandler(sender, outbound); err != nil {
		t.Fatal(err)
	}
	if err := sender.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: outbound.Tag},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestFlowInspectionP2BPacketCallbacks(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{
		{"Trojan", inspectionTrojanReceiver},
		{"Shadowsocks", inspectionShadowsocksReceiver},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"enabled", "sniff", "disabled", "rejected"} {
				t.Run(mode, func(t *testing.T) {
					receiving, view, outbound := test.receiver(t, mode != "disabled", mode == "sniff")
					address := inspectionPacketCallbackSender(t, outbound)
					_, client, relay := inspectionSOCKSAssociation(t, address)
					firstDest, secondDest := startOutboundStatsUDPServer(t, 0x19), startOutboundStatsUDPServer(t, 0x37)
					payload, extra := []byte("decoded callback input and response"), []byte("second packet destination")
					if mode == "rejected" {
						if err := receiving.GetFeature(fout.ManagerType()).(fout.Manager).RemoveHandler(context.Background(), "direct"); err != nil {
							t.Fatal(err)
						}
						message, err := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: firstDest.Address, Port: firstDest.Port}, payload)
						if err != nil {
							t.Fatal(err)
						}
						defer message.Release()
						if _, err := client.WriteToUDP(message.Bytes(), relay); err != nil {
							t.Fatal(err)
						}
						var ref fs.FlowRef
						inspectionWait(t, func() bool {
							live, _ := view.ReadLive(context.Background())
							if len(live.Rows) != 1 || len(live.Rows[0].Routes) == 0 || live.Rows[0].Routes[0].Selection != fs.SelectionRejected || live.Rows[0].Uplink.Known != uint64(len(payload)) {
								return false
							}
							ref = live.Rows[0].Ref
							return true
						})
						inspectionClosePacketCallback(t, view, ref)
						inspectionWait(t, func() bool {
							page, _ := view.ReadTerminals(context.Background())
							return len(page.Rows) == 1 && page.Rows[0].Reason == fs.EndReasonLocalStop && page.Rows[0].Flow.Downlink.Known == 0
						})
						return
					}
					inspectionSOCKSPacket(t, client, relay, firstDest, payload, 0x19)
					inspectionSOCKSPacket(t, client, relay, secondDest, extra, 0x37)
					_, sibling, siblingRelay := inspectionSOCKSAssociation(t, address)
					inspectionSOCKSPacket(t, sibling, siblingRelay, firstDest, payload, 0x19)
					if mode == "disabled" {
						if receiving.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
							t.Fatal("disabled receiver acquired inspection state")
						}
						return
					}
					var first, other fs.FlowRecord
					inspectionWait(t, func() bool {
						live, _ := view.ReadLive(context.Background())
						if len(live.Rows) != 2 {
							return false
						}
						for _, row := range live.Rows {
							if row.Uplink.Known == uint64(len(payload)+len(extra)) {
								first = row
							} else {
								other = row
							}
						}
						return first.Ref.ID != 0 && other.Ref.ID != 0 && first.Downlink.Known == first.Uplink.Known && other.Downlink.Known == uint64(len(payload))
					})
					for _, row := range []fs.FlowRecord{first, other} {
						if row.Kind != fs.FlowKindUDPAssociation || row.Origin != fs.TrafficOriginUser || row.AccountingRoute.Outbound.Tag != "direct" || row.AccountingRoute.Outbound.Serial == 0 || row.Uplink.Incomplete || row.Downlink.Incomplete {
							t.Fatalf("callback facts: %+v", row)
						}
					}
					if first.InitialDestination != firstDest || len(first.Destinations) != 2 {
						t.Fatalf("packet destinations: %+v", first)
					}
					inspectionClosePacketCallback(t, view, first.Ref)
					inspectionWait(t, func() bool {
						page, _ := view.ReadTerminals(context.Background())
						return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == first.Ref && page.Rows[0].Reason == fs.EndReasonLocalStop && page.Rows[0].Flow.Downlink.Known == uint64(len(payload)+len(extra))
					})
					inspectionSOCKSPacket(t, sibling, siblingRelay, secondDest, extra, 0x37)
					inspectionClosePacketCallback(t, view, other.Ref)
					inspectionWait(t, func() bool {
						page, _ := view.ReadTerminals(context.Background())
						return len(page.Rows) == 2
					})
					_, replacement, replacementRelay := inspectionSOCKSAssociation(t, address)
					inspectionSOCKSPacket(t, replacement, replacementRelay, firstDest, payload, 0x19)
					var replacementRef fs.FlowRef
					inspectionWait(t, func() bool {
						live, _ := view.ReadLive(context.Background())
						if len(live.Rows) != 1 || live.Rows[0].Downlink.Known != uint64(len(payload)) {
							return false
						}
						replacementRef = live.Rows[0].Ref
						return true
					})
					if replacementRef == first.Ref || replacementRef == other.Ref {
						t.Fatal("new association reused a stopped reference")
					}
					inspectionClosePacketCallback(t, view, replacementRef)
					inspectionWait(t, func() bool {
						page, _ := view.ReadTerminals(context.Background())
						return len(page.Rows) == 3
					})
					inspectionOutboundTotals(t, view, "direct", uint64(3*len(payload)+2*len(extra)))
				})
			}
		})
	}
}

func inspectionClosePacketCallback(t *testing.T, view fs.FlowInspection, ref fs.FlowRef) {
	t.Helper()
	out, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("callback exact stop: %+v %v", out, err)
	}
}
