package stats

import (
	"context"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestInspectionRayAttributionAndCompletion(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { return nil })
	a, b := root.NewLeg(), root.NewLeg()
	if a.Ref() != root.Ref() || b.Ref() != root.Ref() || a.NewLeg() != nil {
		t.Fatal("ray changed association identity or admitted nested legs")
	}
	a.Route(fs.OutboundRef{Serial: 11, Tag: "old"})
	a.AddUplink(3)
	a.AddDownlink(2)
	b.Route(fs.OutboundRef{Serial: 12, Tag: "new"})
	b.AddUplink(5)
	b.BindRoute()
	newDest := xnet.UDPDestination(xnet.LocalHostIP, 53)
	b.Effective(newDest)
	a.BindRoute() // Late old binding must not roll back the latest route.
	a.BindRoute()
	a.Effective(xnet.UDPDestination(xnet.LocalHostIP, 54))
	a.AddDownlink(7)
	b.AddDownlink(9)
	out, err := s.CloseFlows(context.Background(), []fs.FlowRef{root.Ref()})
	if err != nil || out[0].Err != nil || root.NewLeg() != nil {
		t.Fatalf("association stop did not seal future work: %+v %v", out, err)
	}
	a.Finish()
	b.Finish()
	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 {
		t.Fatalf("association terminal count: %d", len(page.Rows))
	}
	a.AddUplink(13)
	a.Finish()
	root.Finish()
	page, _ = s.ReadTerminals()
	f := page.Rows[0].Flow
	if f.Ref != root.Ref() || f.Uplink != 8 || f.Downlink != 18 || f.Outbound.Serial != 12 || f.EffectiveDestination != newDest {
		t.Fatalf("association facts: %+v", f)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		switch row.Outbound.Serial {
		case 0:
			if row.Uplink != 0 || row.Downlink != 0 {
				t.Fatalf("inactive root fabricated unassigned facts: %+v", row)
			}
		case 11:
			if row.Uplink != 16 || row.Downlink != 9 {
				t.Fatalf("old-ray totals: %+v", row)
			}
		case 12:
			if row.Uplink != 5 || row.Downlink != 9 {
				t.Fatalf("new-ray totals: %+v", row)
			}
		}
	}
}

func TestInspectionRayPendingUnassignedCredit(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginInternal, xnet.Destination{}, xnet.Destination{}, nil)
	a, b := root.NewLeg(), root.NewLeg()
	a.AddUplink(3)

	a.Unassign()
	a.Finish() // No consuming route: only this ray's pending bytes are unassigned.
	b.Route(fs.OutboundRef{Serial: 8})
	b.AddUplink(5)

	b.BindRoute()
	c := root.NewLeg()
	c.Route(fs.OutboundRef{Serial: 8})
	c.BindRoute()

	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Serial == 8 && (row.Uplink != 5) {
			t.Fatalf("independent leg incompleteness: %+v", row)
		}
	}
	b.Finish()
	c.Finish()
	root.Finish()
	totals, _ = s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Origin == fs.TrafficOriginInternal && row.Outbound.Serial == 0 && row.Uplink != 3 {
			t.Fatalf("unassigned pending credit: %+v", row)
		}
	}
}

func TestInspectionFinishedRayLateFactsReachLiveRoot(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg()
	leg.Route(fs.OutboundRef{Serial: 7})
	leg.BindRoute()
	leg.Finish()
	leg.AddUplink(9)

	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 9 {
		t.Fatalf("late leg facts missing from root snapshot: %+v", page)
	}
	leg.AddUplink(4)
	pageAgain, _ := s.ReadTerminals()
	if pageAgain.Rows[0].Flow.Uplink != 9 {
		t.Fatalf("terminal snapshot changed after root finish: %+v", pageAgain)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Serial == 7 && row.Uplink == 13 {
			return
		}
	}
	t.Fatalf("late aggregate credit missing: %+v", totals)
}

func TestInspectionSelectedUnclaimedRayIsUnassigned(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg()
	leg.Route(fs.OutboundRef{Serial: 19, Tag: "selected-only"})
	leg.AddUplink(5)
	leg.Unassign()

	leg.Finish()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Outbound.Serial != 19 {
		t.Fatalf("selected route became a consuming owner: %+v", page)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Origin == fs.TrafficOriginUser && row.Outbound.Serial == 0 && row.Uplink == 5 {
			return
		}
	}
	t.Fatalf("unclaimed selected ray missing from unassigned totals: %+v", totals)
}

func TestInspectionPendingOrdinaryRouteAfterOwnerEnd(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg()
	destination := xnet.UDPDestination(xnet.DomainAddress("late.example"), 53)
	leg.AddUplink(11)
	leg.AddDownlink(13)
	leg.PacketDestination(destination)
	leg.Finish()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 || page.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("pre-classification terminal: %+v", page)
	}
	leg.Route(fs.OutboundRef{Serial: 31, Tag: "ordinary"})
	leg.BindRoute()
	leg.AddUplink(17)

	again, _ := s.ReadTerminals()
	if len(again.Rows) != 1 || again.Rows[0].Flow.Uplink != 0 {
		t.Fatalf("late route changed immutable terminal: %+v", again)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Serial == 31 {
			if row.Uplink != 28 || row.Downlink != 13 {
				t.Fatalf("late ordinary totals: %+v", row)
			}
			return
		}
	}
	t.Fatalf("late ordinary bucket missing: %+v", totals)
}

func TestInspectionRouteThenOwnerEndBeforeBind(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg().(*inspectionExchange)
	destination := xnet.UDPDestination(xnet.DomainAddress("route-before-bind.example"), 53)
	leg.AddUplink(23)
	leg.PacketDestination(destination)
	leg.Route(fs.OutboundRef{Serial: 35, Tag: "later-claim"})
	leg.Finish()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 23 || page.Rows[0].Flow.LatestDestination != destination || page.Rows[0].Flow.Outbound.Serial != 35 {
		t.Fatalf("route-before-bind lower bound: %+v", page)
	}
	leg.BindRoute()
	leg.AddDownlink(29)
	leg.FinishSelectedLeg()

	again, _ := s.ReadTerminals()
	if len(again.Rows) != 1 || again.Rows[0].Flow.Outbound.Serial != 35 || again.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("late claim changed immutable terminal: %+v", again)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Serial == 35 {
			if row.Uplink != 23 || row.Downlink != 29 {
				t.Fatalf("late claim totals: %+v", row)
			}
			return
		}
	}
	t.Fatalf("late claim bucket missing: %+v", totals)
}

func TestInspectionEarlyFinishedSelectedLegWithoutClaimIsUnassigned(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg().(*inspectionExchange)
	leg.AddUplink(19)
	leg.Finish()
	leg.Route(fs.OutboundRef{Serial: 37, Tag: "selected-no-claim"})
	leg.FinishSelectedLeg()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Outbound.Serial != 37 || page.Rows[0].Flow.Uplink != 19 {
		t.Fatalf("selected no-claim terminal: %+v", page)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Origin == fs.TrafficOriginUser && row.Outbound.Serial == 0 && row.Uplink == 19 {
			return
		}
	}
	t.Fatalf("selected no-claim unassigned total missing: %+v", totals)
}

func TestInspectionTCPAttemptLegsKeepPerRouteTotals(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_TCP, fs.TrafficOriginInternal, xnet.Destination{}, xnet.TCPDestination(xnet.LocalHostIP, 443), nil)
	first, second := root.NewLeg(), root.NewLeg()
	if first == nil || second == nil || first.NewLeg() != nil {
		t.Fatal("TCP root did not admit exactly one level of attempt legs")
	}
	for i, leg := range []fs.Exchange{first, second} {
		leg.AddUplink(uint64(11 + i))
		leg.AddDownlink(uint64(21 + i))
		leg.Route(fs.OutboundRef{Serial: uint64(41 + i)})
		leg.BindRoute()
		leg.Finish()
	}
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Kind != xnet.Network_TCP || page.Rows[0].Flow.Uplink != 23 || page.Rows[0].Flow.Downlink != 43 {
		t.Fatalf("TCP attempt root: %+v", page)
	}
	totals, _ := s.ReadTotals()
	for _, serial := range []uint64{41, 42} {
		var found bool
		for _, total := range totals.Rows {
			if total.Outbound.Serial == serial {
				found = true
			}
		}
		if !found {
			t.Fatalf("TCP attempt total %d missing: %+v", serial, totals)
		}
	}
}
