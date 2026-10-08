package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
)

func TestFlowInspectionTrojanInboundTCP(t *testing.T) {
	// The shared receiver acceptance sends the SOCKS request and payload in one
	// write. The native Trojan client can coalesce its header and first payload;
	// receiver sniffing must replay that payload without double uplink credit.
	inspectionAppClientReceiverAcceptance(t, inspectionTrojanReceiver)
}

func TestFlowInspectionTrojanInboundRejected(t *testing.T) {
	inspectionAppClientRejectedReceiver(t, inspectionTrojanReceiver)
}

func TestFlowInspectionTrojanInboundUnclaimedOwner(t *testing.T) {
	receiving, remote, outbound := inspectionTrojanReceiver(t, true, true)
	manager := receiving.GetFeature(fout.ManagerType()).(fout.Manager)
	if err := manager.AddHandler(context.Background(), inspectionUnclaimedHandler{}); err != nil {
		t.Fatal(err)
	}
	routing := receiving.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "unclaimed"},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	_, view, address := inspectionTCPOutboundThrough(t, true, outbound)
	client := inspectionSOCKS(t, address, cnet.TCPDestination(cnet.LocalHostIP, 1), nil)
	payload := []byte("GET / HTTP/1.1\r\nHost: trojan-unclaimed.invalid\r\n\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	client.Close()
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals()
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != uint64(len(payload)) {
			return false
		}
		if page.Rows[0].Flow.Outbound.Tag != outbound.Tag || page.Rows[0].Flow.Outbound.Tag == "" {
			t.Fatalf("Trojan unclaimed route: %+v", page.Rows[0].Flow)
		}
		return true
	})
	totals, err := view.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	var known uint64
	for _, row := range totals.Rows {
		if row.Outbound.Tag == outbound.Tag {
			known += row.Uplink
			if row.Downlink != 0 {
				t.Fatalf("unclaimed server produced response bytes: %+v", row)
			}
		}
	}
	if known != uint64(len(payload)) {
		t.Fatalf("app uplink total: %d", known)
	}
	assertNoDedicatedServerInspection(t, remote)
}

func TestFlowInspectionTrojanInboundMuxChild(t *testing.T) {
	_, view, outbound := inspectionTrojanReceiver(t, true, false)
	inspectionEnableOutboundMux(t, outbound)
	_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
	destination := startOutboundStatsTCPServer(t)
	payload := []byte("decoded Trojan MUX child")
	conn := inspectionSOCKS(t, address, destination, payload)
	inspectionOnlyMuxFlow(t, view, conn, destination, payload, "direct")
}
