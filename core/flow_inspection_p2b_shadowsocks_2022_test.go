package core_test

import (
	"testing"
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
			inspectionAppClientReceiverAcceptance(t, test.receiver)
			t.Run("rejected", func(t *testing.T) { inspectionAppClientRejectedReceiver(t, test.receiver) })
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
