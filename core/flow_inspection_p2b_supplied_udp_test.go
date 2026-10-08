package core_test

import (
	"bytes"
	"testing"

	cnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestFlowInspectionP2BSuppliedPacketCodecs(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
		payload  []byte
	}{
		{"VLESS", inspectionVLESSReceiver, []byte("VLESS packet")},
		{"Hysteria", inspectionHysteriaReceiver, []byte("Hysteria packet")},
		{"Hysteria-fragmented", inspectionHysteriaReceiver, bytes.Repeat([]byte("fragment"), 480)},
	} {
		t.Run(test.name, func(t *testing.T) { inspectionSuppliedUDPReceiverAcceptance(t, test.receiver, test.payload) })
	}
}

func inspectionSuppliedUDPReceiverAcceptance(t *testing.T, receiver inspectionSuppliedTCPReceiver, payload []byte) {
	t.Helper()
	for _, mode := range []string{"disabled", "enabled", "sniff"} {
		t.Run(mode, func(t *testing.T) {
			receiving, remote, outbound := receiver(t, mode != "disabled", mode == "sniff")
			destination := startOutboundStatsUDPServer(t, 0x19)
			sending, view, address := inspectionUDPInboundThrough(t, destination, mode != "disabled", false, outbound)
			client, sibling := inspectionUDPClient(t), inspectionUDPClient(t)
			extra := []byte("sibling after packet stop")
			inspectionUDPExchange(t, client, address, payload, 0x19)
			if mode == "disabled" {
				if receiving.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil || sending.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled receiver acquired observation")
				}
				return
			}
			var first fs.FlowRecord
			var liveStorage44 []fs.FlowRecord
			inspectionWait(t, func() bool {
				live, _ := view.ReadLiveInto(liveStorage44)
				liveStorage44 = live.Rows
				if len(live.Rows) != 1 || live.Rows[0].Uplink != uint64(len(payload)) || live.Rows[0].Downlink != uint64(len(payload)) {
					return false
				}
				first = live.Rows[0]
				return true
			})
			if first.Kind != cnet.Network_UDP || first.Origin != fs.TrafficOriginUser || first.Outbound.Tag != outbound.Tag || first.Outbound.Tag == "" || first.Destination != destination {
				t.Fatalf("supplied packet facts: %+v", first)
			}
			inspectionUDPExchange(t, sibling, address, payload, 0x19)
			inspectionClosePacketCallback(t, view, first.Ref)
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals()
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == first.Ref && page.Rows[0].Flow.Downlink == uint64(len(payload))
			})
			inspectionUDPExchange(t, sibling, address, extra, 0x19)
			var other fs.FlowRef
			var liveStorage63 []fs.FlowRecord
			inspectionWait(t, func() bool {
				live, _ := view.ReadLiveInto(liveStorage63)
				liveStorage63 = live.Rows
				if len(live.Rows) != 1 || live.Rows[0].Downlink != uint64(len(payload)+len(extra)) {
					return false
				}
				other = live.Rows[0].Ref
				return true
			})
			inspectionClosePacketCallback(t, view, other)
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals()
				return len(page.Rows) == 2
			})
			inspectionOutboundTotals(t, view, outbound.Tag, uint64(2*len(payload)+len(extra)))
			assertNoDedicatedServerInspection(t, remote)
		})
	}
}

func TestFlowInspectionP2BHysteriaPacketDestinations(t *testing.T) {
	_, remote, outbound := inspectionHysteriaReceiver(t, true, false)
	_, view, address := inspectionPacketCallbackSenderAt(t, outbound, true, false)
	defer assertNoDedicatedServerInspection(t, remote)
	_, client, relay := inspectionSOCKSAssociation(t, address)
	first, second := startOutboundStatsUDPServer(t, 0x19), startOutboundStatsUDPServer(t, 0x37)
	payload, extra := []byte("first target"), []byte("second target")
	inspectionSOCKSPacket(t, client, relay, first, payload, 0x19)
	inspectionSOCKSPacket(t, client, relay, second, extra, 0x37)
	var ref fs.FlowRef
	var liveStorage92 []fs.FlowRecord
	inspectionWait(t, func() bool {
		live, _ := view.ReadLiveInto(liveStorage92)
		liveStorage92 = live.Rows
		if len(live.Rows) != 1 || live.Rows[0].Downlink != uint64(len(payload)+len(extra)) {
			return false
		}
		row := live.Rows[0]
		if row.Destination != second || row.Uplink != row.Downlink {
			t.Fatalf("Hysteria packet destinations: %+v", row)
		}
		ref = row.Ref
		return true
	})
	inspectionClosePacketCallback(t, view, ref)
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals()
		return len(page.Rows) == 1
	})
	inspectionOutboundTotals(t, view, outbound.Tag, uint64(len(payload)+len(extra)))
}
