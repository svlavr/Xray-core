package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
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
		t.Run(test.name, func(t *testing.T) { inspectionDecodedTCPReceiverAcceptance(t, test.receiver) })
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
		receiving, view, outbound := receiver(t, true, true)
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
			if row.Reason != fs.EndReasonRejected || row.Flow.Uplink.Known != uint64(len(payload)) || row.Flow.Downlink.Known != 0 || row.Flow.AccountingRoute.Outbound.Serial != 0 || row.Flow.Downlink.Incomplete {
				t.Fatalf("authenticated rejection: %+v", row)
			}
			return true
		})
	}
}
