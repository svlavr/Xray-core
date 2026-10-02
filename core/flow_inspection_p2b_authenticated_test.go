package core_test

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestFlowInspectionP2BAuthenticatedTCP(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{
		{"VMess-AES", inspectionVMessReceiver},
		{"VMess-ChaCha", func(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
			return inspectionVMessReceiverSecurity(t, enabled, sniff, protocol.SecurityType_CHACHA20_POLY1305)
		}},
		{"Shadowsocks", inspectionShadowsocksReceiver},
	} {
		t.Run(test.name, func(t *testing.T) { inspectionAppClientReceiverAcceptance(t, test.receiver) })
	}
}

func TestFlowInspectionP2BAuthenticatedMuxChild(t *testing.T) {
	for _, receiver := range []inspectionSuppliedTCPReceiver{inspectionVMessReceiver, inspectionShadowsocksReceiver} {
		_, view, outbound := receiver(t, true, false)
		inspectionEnableOutboundMux(t, outbound)
		_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
		destination := startOutboundStatsTCPServer(t)
		payload := []byte("decoded authenticated MUX child")
		conn := inspectionSOCKS(t, address, destination, payload)
		inspectionOnlyMuxFlow(t, view, conn, destination, payload, "direct")
	}
}

func TestFlowInspectionP2BAuthenticatedUDP(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305} {
		t.Run(security.String(), func(t *testing.T) {
			inspectionSuppliedUDPReceiverAcceptance(t, func(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
				return inspectionVMessReceiverSecurity(t, enabled, sniff, security)
			}, []byte("authenticated packet"))
		})
	}
}

func TestFlowInspectionP2BAuthenticatedRejection(t *testing.T) {
	for _, receiver := range []inspectionSuppliedTCPReceiver{inspectionVMessReceiver, inspectionShadowsocksReceiver} {
		inspectionAppClientRejectedReceiver(t, receiver)
	}
}
