package core_test

import (
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/mux"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestFlowInspectionXUDPRetainedRebind(t *testing.T) {
	t.Setenv("xray.cone.disabled", "false")
	const mask = byte(0x35)
	destination := startOutboundStatsUDPServer(t, mask)
	instance, view, address := inspectionSOCKSUDPListener(t, true, false)
	outbound := inspectionMuxClientConfig(t)
	if err := core.AddOutboundHandler(instance, outbound); err != nil {
		t.Fatal(err)
	}
	if err := instance.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		Networks: []cnet.Network{cnet.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: outbound.Tag},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	client := inspectionUDPClient(t)
	source := client.LocalAddr().(*net.UDPAddr)
	inbound := &session.Inbound{Name: "socks", Source: cnet.UDPDestination(cnet.IPAddress(source.IP), cnet.Port(source.Port))}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = context.WithValue(ctx, "cone", true)
	globalID := xudp.GetGlobalID(ctx)
	if globalID == [8]byte{} {
		t.Fatal("retained identity not enabled")
	}
	t.Cleanup(func() {
		mux.XUDPManager.Lock()
		retained := mux.XUDPManager.Map[globalID]
		mux.XUDPManager.Unlock()
		if retained != nil {
			retained.Interrupt()
		}
	})
	var retained *mux.XUDP
	var prior fs.FlowRef
	for _, payload := range []string{"first retained packet", "packet after client exact stop"} {
		control, unusedClient, relay := inspectionSOCKSAssociation(t, address)
		unusedClient.Close()
		inspectionSOCKSPacket(t, client, relay, destination, []byte(payload), mask)
		var row fs.FlowRecord
		inspectionWait(t, func() bool {
			live, _ := view.ReadLive(context.Background())
			if len(live.Rows) != 1 {
				return false
			}
			row = live.Rows[0]
			return row.Uplink.Known == uint64(len(payload)) && row.Downlink.Known == uint64(len(payload))
		})
		if row.Source.Port != cnet.Port(source.Port) || row.AccountingRoute.Outbound.Tag != "vmess-proxy" || row.AccountingRoute.Effective != destination {
			t.Fatalf("client binding: %+v", row)
		}
		if row.Ref == prior {
			t.Fatal("client endpoint replacement reused logical ref")
		}
		prior = row.Ref
		mux.XUDPManager.Lock()
		current := mux.XUDPManager.Map[globalID]
		mux.XUDPManager.Unlock()
		if current == nil || retained != nil && current != retained {
			t.Fatal("live retained downstream was replaced")
		}
		retained = current
		out, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
		if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("client stop: %+v %v", out, err)
		}
		inspectionWait(t, func() bool { live, _ := view.ReadLive(context.Background()); return len(live.Rows) == 0 })
		control.Close()
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 2 {
		t.Fatalf("client terminals: %+v %v", page, err)
	}
	inspectionOutboundTotals(t, view, "vmess-proxy", uint64(len("first retained packet")+len("packet after client exact stop")))
}
