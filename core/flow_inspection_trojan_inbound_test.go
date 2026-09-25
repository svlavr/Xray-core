package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestFlowInspectionTrojanInboundTCP(t *testing.T) {
	// The shared receiver acceptance sends the SOCKS request and payload in one
	// write. The native Trojan client can coalesce its header and first payload;
	// receiver sniffing must replay that payload without double uplink credit.
	inspectionDecodedTCPReceiverAcceptance(t, inspectionTrojanReceiver)
}

func TestFlowInspectionTrojanInboundRejected(t *testing.T) {
	receiving, view, outbound := inspectionTrojanReceiver(t, true, true)
	routing := receiving.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		RuleTag: "missing", Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "absent"},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
	destination := cnet.TCPDestination(cnet.LocalHostIP, 1)
	client := inspectionSOCKS(t, address, destination, nil)
	payload := []byte("GET / HTTP/1.1\r\nHost: trojan-rejected.invalid\r\n\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil || len(page.Rows) != 1 {
			return false
		}
		row := page.Rows[0]
		if row.Reason != fs.EndReasonRejected || row.Flow.Uplink.Known != uint64(len(payload)) || row.Flow.Downlink.Known != 0 || row.Flow.Uplink.Incomplete || row.Flow.Downlink.Incomplete || row.Flow.AccountingRoute.Outbound.Serial != 0 {
			t.Fatalf("Trojan rejected receipt: %+v", row)
		}
		return true
	})
}

func TestFlowInspectionTrojanInboundUnclaimedOwner(t *testing.T) {
	receiving, view, outbound := inspectionTrojanReceiver(t, true, true)
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
	_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
	client := inspectionSOCKS(t, address, cnet.TCPDestination(cnet.LocalHostIP, 1), nil)
	payload := []byte("GET / HTTP/1.1\r\nHost: trojan-unclaimed.invalid\r\n\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	client.Close()
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != uint64(len(payload)) || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
			return false
		}
		if len(page.Rows[0].Flow.Routes) != 1 || page.Rows[0].Flow.Routes[0].Outbound.Tag != "unclaimed" || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 0 {
			t.Fatalf("Trojan unclaimed route: %+v", page.Rows[0].Flow)
		}
		return true
	})
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatalf("Trojan unclaimed totals: %+v %v", totals, err)
	}
	var known uint64
	var incomplete bool
	for _, row := range totals.Rows {
		if row.Outbound.Serial != 0 {
			t.Fatalf("Trojan unclaimed owner acquired an outbound: %+v", row)
		}
		if row.Origin == fs.TrafficOriginUser {
			known += row.Uplink.Known
			incomplete = incomplete || row.Uplink.Incomplete || row.Downlink.Incomplete
		}
	}
	if known != uint64(len(payload)) || !incomplete {
		t.Fatalf("Trojan unclaimed totals: %+v", totals)
	}
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
