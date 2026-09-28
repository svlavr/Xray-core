package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
)

func inspectionMuxClientConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	outbound := inspectionVMessConfig(t)
	outbound.SenderSettings = serial.ToTypedMessage(&proxyman.SenderConfig{
		MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8, XudpConcurrency: 8},
	})
	return outbound
}

func TestFlowInspectionMuxClientTCP(t *testing.T) {
	inspectionOutboundTCP(t, inspectionMuxClientConfig)
}

func TestFlowInspectionMuxClientUDP(t *testing.T) {
	// Retained server rebind has a separate ownership/provenance gate. These
	// cases exercise the real XUDP client worker with ordinary server children.
	t.Setenv("xray.cone.disabled", "true")
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			const mask = byte(0x59)
			destination := startOutboundStatsUDPServer(t, mask)
			outbound := inspectionMuxClientConfig(t)
			instance, view, address := inspectionUDPInboundThrough(t, destination, enabled, false, outbound)
			client := inspectionUDPClient(t)
			payload := []byte("MUX UDP logical payload")
			inspectionUDPExchange(t, client, address, payload, mask)
			if !enabled {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled collection acquired a store")
				}
				return
			}
			var ref fs.FlowRef
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive()
				if len(live.Rows) != 1 {
					return false
				}
				row := live.Rows[0]
				if row.Uplink != uint64(len(payload)) || row.Downlink != uint64(len(payload)) {
					return false
				}
				if row.Outbound.Tag != outbound.Tag || row.EffectiveDestination != destination || row.LatestDestination != destination {
					t.Fatalf("UDP child facts: %+v", row)
				}
				ref = row.Ref
				return true
			})
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
			if err != nil || outcomes[0].Err != nil {
				t.Fatalf("close: %+v %v", outcomes, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals()
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == ref
			})
			inspectionOutboundTotals(t, view, outbound.Tag, uint64(len(payload)))
		})
	}
	t.Run("two-destinations", func(t *testing.T) {
		instance, view, _ := inspectionUDPInboundThrough(t, cnet.UDPDestination(cnet.LocalHostIP, 9), true, false, inspectionMuxClientConfig(t))
		inspectionUDPBatchThrough(t, instance, view, "vmess-proxy")
	})
}
