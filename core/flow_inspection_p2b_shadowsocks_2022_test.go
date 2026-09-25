package core_test

import (
	"context"
	"testing"

	fout "github.com/xtls/xray-core/features/outbound"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestFlowInspectionP2BShadowsocks2022TCP(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{
		{"single", inspectionShadowsocks2022Receiver},
		{"multi", inspectionShadowsocks2022MultiReceiver},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspectionDecodedTCPReceiverAcceptanceMode(t, test.receiver, true)
			t.Run("rejected", func(t *testing.T) {
				receiving, view, outbound := test.receiver(t, true, true)
				if err := receiving.GetFeature(fout.ManagerType()).(fout.Manager).RemoveHandler(context.Background(), "direct"); err != nil {
					t.Fatal(err)
				}
				_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
				payload := []byte("GET / HTTP/1.1\r\nHost: rejected.invalid\r\n\r\n")
				client := inspectionSOCKS(t, address, startOutboundStatsTCPServer(t), nil)
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
				inspectionWait(t, func() bool {
					page, err := view.ReadTerminals(context.Background())
					if err != nil || len(page.Rows) != 1 {
						return false
					}
					row := page.Rows[0]
					if row.Reason != fs.EndReasonRejected || row.Flow.Uplink.Known != uint64(len(payload)) || row.Flow.Downlink.Known != 0 || row.Flow.AccountingRoute.Outbound.Serial != 0 {
						t.Fatalf("SS2022 rejected admission: %+v", row)
					}
					return true
				})
			})
			t.Run("mux-child", func(t *testing.T) {
				_, view, outbound := test.receiver(t, true, false)
				inspectionEnableOutboundMux(t, outbound)
				_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
				destination := startOutboundStatsTCPServer(t)
				payload := []byte("decoded SS2022 MUX child")
				conn := inspectionSOCKS(t, address, destination, payload)
				inspectionOnlyMuxFlow(t, view, conn, destination, payload, "direct")
			})
		})
	}
}
