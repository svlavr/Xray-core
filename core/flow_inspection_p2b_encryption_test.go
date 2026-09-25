package core_test

import (
	"testing"
)

func TestFlowInspectionP2BVLESSEncryption(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		inspectionDecodedTCPReceiverAcceptance(t, inspectionVLESSEncryptedReceiver)
	})
	t.Run("UDP", func(t *testing.T) {
		t.Setenv("xray.cone.disabled", "true")
		inspectionSuppliedUDPReceiverAcceptance(t, inspectionVLESSEncryptedReceiver, []byte("encrypted VLESS packet"))
	})
}

func TestFlowInspectionP2BVLESSEncryptionMuxChild(t *testing.T) {
	_, view, outbound := inspectionVLESSEncryptedReceiver(t, true, false)
	inspectionEnableOutboundMux(t, outbound)
	_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
	destination := startOutboundStatsTCPServer(t)
	payload := []byte("decoded encrypted VLESS MUX child")
	conn := inspectionSOCKS(t, address, destination, payload)
	inspectionOnlyMuxFlow(t, view, conn, destination, payload, "direct")
}
