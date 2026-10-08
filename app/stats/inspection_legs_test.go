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
	a.Route(fs.OutboundRef{Tag: "old"})
	a.AddUplink(3)
	a.AddSelectedUplink(3)
	a.AddDownlink(2)
	b.Route(fs.OutboundRef{Tag: "new"})
	b.AddUplink(5)
	b.AddSelectedUplink(5)
	a.Route(fs.OutboundRef{Tag: "old-repeat"}) // Cannot overwrite the newer ray display.
	newDest := xnet.UDPDestination(xnet.LocalHostIP, 53)
	b.PacketDestination(newDest)
	a.AddDownlink(7)
	b.AddDownlink(9)
	out, err := s.CloseFlows(context.Background(), []fs.FlowRef{root.Ref()})
	if err != nil || out[0] != nil || root.NewLeg() != nil {
		t.Fatalf("association stop did not seal future work: %+v %v", out, err)
	}
	a.Finish()
	b.Finish()
	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 {
		t.Fatalf("association terminal count: %d", len(page.Rows))
	}
	a.AddUplink(13)
	a.AddSelectedUplink(13)
	a.Finish()
	root.Finish()
	page, _ = s.ReadTerminals()
	f := page.Rows[0].Flow
	if f.Ref != root.Ref() || f.Uplink != 8 || f.Downlink != 18 || f.Outbound.Tag != "new" || f.Destination != newDest {
		t.Fatalf("association facts: %+v", f)
	}
	totals, _ := s.ReadTotals()
	if totals.User != (fs.ClientTotals{Uplink: 21, Downlink: 18}) || len(totals.Rows) != 2 {
		t.Fatalf("inactive root duplicated general bytes: %+v", totals)
	}
	seen := make(map[string]bool)
	for _, row := range totals.Rows {
		if seen[row.Outbound.Tag] {
			t.Fatalf("duplicate selected tag: %+v", row)
		}
		seen[row.Outbound.Tag] = true
		switch row.Outbound.Tag {
		case "old":
			if row.Uplink != 16 || row.Downlink != 9 {
				t.Fatalf("old-ray totals: %+v", row)
			}
		case "new":
			if row.Uplink != 5 || row.Downlink != 9 {
				t.Fatalf("new-ray totals: %+v", row)
			}
		default:
			t.Fatalf("unexpected selected tag: %+v", row)
		}
	}
}

func TestInspectionRayPendingUnassignedCredit(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	a, b := root.NewLeg(), root.NewLeg()
	a.AddUplink(3)

	a.AddSelectedUplink(3)
	a.Unassign()
	a.Finish() // No consuming route: input remains in the general metric only.
	b.Route(fs.OutboundRef{Tag: "tag-8"})
	b.AddUplink(5)
	b.AddSelectedUplink(5)
	c := root.NewLeg()
	c.Route(fs.OutboundRef{Tag: "tag-8"})

	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Tag == "tag-8" && (row.Uplink != 5) {
			t.Fatalf("independent leg incompleteness: %+v", row)
		}
	}
	b.Finish()
	c.Finish()
	root.Finish()
	totals, _ = s.ReadTotals()
	if totals.User.Uplink != 8 || len(totals.Rows) != 1 || totals.Rows[0].Uplink != 5 {
		t.Fatalf("unassigned pending credit: %+v", totals)
	}
}

func TestInspectionFinishedRayLateFactsReachLiveRoot(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg()
	leg.Route(fs.OutboundRef{Tag: "tag-7"})
	leg.Finish()
	leg.AddUplink(9)

	leg.AddSelectedUplink(9)
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 9 {
		t.Fatalf("late leg facts missing from root snapshot: %+v", page)
	}
	leg.AddUplink(4)
	leg.AddSelectedUplink(4)
	pageAgain, _ := s.ReadTerminals()
	if pageAgain.Rows[0].Flow.Uplink != 9 {
		t.Fatalf("terminal snapshot changed after root finish: %+v", pageAgain)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Tag == "tag-7" && row.Uplink == 13 {
			return
		}
	}
	t.Fatalf("late aggregate credit missing: %+v", totals)
}

func TestInspectionSelectedRayKeepsTagWithoutConsumption(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg()
	leg.Route(fs.OutboundRef{Tag: "selected-only"})
	leg.AddUplink(5)
	leg.Unassign()

	leg.Finish()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Outbound.Tag != "selected-only" {
		t.Fatalf("selected route label changed: %+v", page)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Origin == fs.TrafficOriginUser && row.Outbound.Tag == "selected-only" && row.Uplink == 0 && totals.User.Uplink == 5 {
			return
		}
	}
	t.Fatalf("selected ray missing from selected totals: %+v", totals)
}

func TestInspectionPendingOrdinaryRouteAfterOwnerEnd(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg()
	destination := xnet.UDPDestination(xnet.DomainAddress("late.example"), 53)
	leg.AddUplink(11)
	leg.AddSelectedUplink(11)
	leg.AddDownlink(13)
	leg.PacketDestination(destination)
	leg.Finish()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 11 || page.Rows[0].Flow.Downlink != 13 || page.Rows[0].Flow.Destination != destination {
		t.Fatalf("pre-classification terminal: %+v", page)
	}
	leg.Route(fs.OutboundRef{Tag: "ordinary"})
	leg.AddUplink(17)

	leg.AddSelectedUplink(17)
	again, _ := s.ReadTerminals()
	if len(again.Rows) != 1 || again.Rows[0].Flow.Uplink != 11 || again.Rows[0].Flow.Downlink != 13 {
		t.Fatalf("late route changed immutable terminal: %+v", again)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Tag == "ordinary" {
			if row.Uplink != 17 || row.Downlink != 0 {
				t.Fatalf("late ordinary totals: %+v", row)
			}
			return
		}
	}
	t.Fatalf("late ordinary bucket missing: %+v", totals)
}

func TestInspectionSelectedRayOwnerEndKeepsLateTotals(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg().(*inspectionExchange)
	destination := xnet.UDPDestination(xnet.DomainAddress("selected-before-end.example"), 53)
	leg.AddUplink(23)
	leg.AddSelectedUplink(23)
	leg.PacketDestination(destination)
	leg.Route(fs.OutboundRef{Tag: "selected-ray"})
	leg.Finish()
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 23 || page.Rows[0].Flow.Destination != destination || page.Rows[0].Flow.Outbound.Tag != "selected-ray" {
		t.Fatalf("selected owner-end lower bound: %+v", page)
	}
	leg.AddDownlink(29)

	again, _ := s.ReadTerminals()
	if len(again.Rows) != 1 || again.Rows[0].Flow.Outbound.Tag != "selected-ray" || again.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("late receipt changed immutable terminal: %+v", again)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Outbound.Tag == "selected-ray" {
			if row.Uplink != 0 || row.Downlink != 29 {
				t.Fatalf("late receipt totals: %+v", row)
			}
			return
		}
	}
	t.Fatalf("late receipt bucket missing: %+v", totals)
}

func TestInspectionEarlyFinishedRaySelectionDoesNotCreditInput(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg().(*inspectionExchange)
	leg.AddUplink(19)
	leg.AddSelectedUplink(19)
	leg.Finish()
	leg.Route(fs.OutboundRef{Tag: "selected-ray"})

	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Outbound.Tag != "selected-ray" || page.Rows[0].Flow.Uplink != 19 {
		t.Fatalf("selected ray terminal: %+v", page)
	}
	totals, _ := s.ReadTotals()
	for _, row := range totals.Rows {
		if row.Origin == fs.TrafficOriginUser && row.Outbound.Tag == "selected-ray" && row.Uplink == 0 {
			return
		}
	}
	t.Fatalf("selected ray total missing: %+v", totals)
}

func TestInspectionTCPDoesNotCreatePacketLeg(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_TCP, fs.TrafficOriginInternal, xnet.Destination{}, xnet.TCPDestination(xnet.LocalHostIP, 443), nil)
	if root.NewLeg() != nil {
		t.Fatal("TCP exchange acquired a UDP packet leg")
	}
	root.AddUplink(23)
	root.AddSelectedUplink(23)
	root.AddDownlink(43)
	root.Finish()

	page, _ := s.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Kind != xnet.Network_TCP || page.Rows[0].Flow.Uplink != 23 || page.Rows[0].Flow.Downlink != 43 {
		t.Fatalf("TCP root: %+v", page)
	}
}
