package stats

import (
	"context"
	"strings"
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestInspectionPreparedCarrierNeverRegisters(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
	flow := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.TCPDestination(xnet.DomainAddress(strings.Repeat("x", 500)), 80), nil)
	flow.AddUplink(17)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1}})
	if flow.Ref() != (fs.FlowRef{}) {
		t.Fatal("prepared endpoint is addressable")
	}
	if !flow.ExcludeCarrier() {
		t.Fatal("unregistered carrier was not excluded")
	}
	flow.BindRoute()
	flow.Unassign()
	flow.AddUplink(99)
	flow.AddDownlink(99)
	flow.MarkUplinkIncomplete()
	flow.MarkDownlinkIncomplete()
	flow.Finish()
	live, _ := s.ReadLive(context.Background())
	page, _ := s.ReadTerminals(context.Background())
	totals, _ := s.ReadTotals(context.Background())
	if len(live.Rows) != 0 || len(page.Rows) != 0 || live.Loss != (fs.LossFacts{}) || s.nextID != 0 {
		t.Fatalf("carrier published state/loss: %+v %+v", live, page)
	}
	for _, row := range totals.Rows {
		if row.Uplink.Known != 0 || row.Downlink.Known != 0 || row.Uplink.Incomplete || row.Downlink.Incomplete {
			t.Fatalf("carrier totals: %+v", row)
		}
	}
	logical := s.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	if logical.Ref().ID != 1 {
		t.Fatal("carrier consumed logical ID/capacity")
	}
	logical.Finish()
}

func TestInspectionPreparedLogicalBindingAndFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		s := testInspectionStore(t, fs.ObservationOptions{})
		flow := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil).(*inspectionExchange)
		opened := flow.snapshot().Opened
		flow.AddUplink(11)
		flow.Route(fs.RouteStep{Selection: fs.SelectionRule, Outbound: fs.OutboundRef{Serial: 1, Tag: "forward"}})
		live, _ := s.ReadLive(context.Background())
		if len(live.Rows) != 0 {
			t.Fatal("forwarding selection published endpoint")
		}
		if failed {
			flow.SetEndReason(fs.EndReasonReadError)
		} else {
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 2, Tag: "consume"}})
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() { defer wg.Done(); flow.BindRoute() }()
			}
			wg.Wait()
			if flow.Ref().ID != 1 || len(s.live) != 1 {
				t.Fatal("concurrent binding duplicated registration")
			}
			if flow.ExcludeCarrier() {
				t.Fatal("visible logical reference was excluded")
			}
			flow.AddUplink(3)
		}
		flow.Finish()
		page, _ := s.ReadTerminals(context.Background())
		want := uint64(14)
		if failed {
			want = 11
		}
		if len(page.Rows) != 1 || page.Rows[0].Flow.Opened != opened || page.Rows[0].Flow.Uplink.Known != want {
			t.Fatalf("early facts lost: %+v", page)
		}
		if failed && page.Rows[0].Reason != fs.EndReasonReadError {
			t.Fatal("early failure lost")
		}
	}
}

func TestInspectionPreparedCapacityIsCheckedAtBinding(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
	a := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	b := s.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	a.AddUplink(5)
	a.BindRoute()
	a.BindRoute()
	if a.Ref().ID != 0 || b.Ref().ID != 1 || s.loss.untrackedAdmissions.load() != 1 {
		t.Fatal("incorrect registration capacity/loss")
	}
	a.Finish()
	b.Finish()
	totals, _ := s.ReadTotals(context.Background())
	if findTotal(t, totals.Rows, 0, fs.TrafficOriginUser).Uplink.Known != 5 {
		t.Fatal("overflow lost actual payload")
	}
}
