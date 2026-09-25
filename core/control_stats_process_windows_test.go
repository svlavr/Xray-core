package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	rsession "github.com/xtls/xray-core/features/routing/session"
)

func TestControlStatsP3WindowsProcessIdentity(t *testing.T) {
	instance, view, address := inspectionCore(t, true, false)
	if err := core.AddOutboundHandler(instance, inspectionFreedom("p3-process")); err != nil {
		t.Fatal(err)
	}
	r := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	config := controlRule("direct", net.Network_TCP)
	config.Rule = append([]*router.RoutingRule{{
		RuleTag: "process-only", Process: []string{"self/"},
		TargetTag: &router.RoutingRule_Tag{Tag: "p3-process"},
	}}, config.Rule...)
	if err := r.AddRule(serial.ToTypedMessage(config), false); err != nil {
		t.Fatal(err)
	}
	dest := startOutboundStatsTCPServer(t)
	inspectionSOCKS(t, address, dest, []byte("real Windows socket owner"))
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		row := live.Rows[0]
		if row.AccountingRoute.Outbound.Tag != "p3-process" || row.AccountingRoute.RuleTag != "process-only" || row.AccountingRoute.Outbound.Serial == 0 {
			t.Fatalf("native socket PID lookup did not select process rule: %+v", row)
		}
		return true
	})
	// Port zero has no connected TCP process. A real native lookup failure
	// skips the process-only rule and still permits the later generic route.
	selected, err := r.PickRoute(&rsession.Context{
		Inbound:  &session.Inbound{Source: net.TCPDestination(net.LocalHostIP, 0)},
		Outbound: &session.Outbound{Target: dest},
	})
	if err != nil || selected.GetOutboundTag() != "direct" || selected.GetRuleTag() != "p3-rule" {
		t.Fatalf("native failed-lookup fallback: %+v %v", selected, err)
	}
}
