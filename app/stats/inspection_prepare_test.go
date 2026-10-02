package stats

import (
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
	if flow.Ref() != (fs.FlowRef{}) {
		t.Fatal("prepared endpoint is addressable")
	}
	if !flow.ExcludeCarrier() {
		t.Fatal("unregistered carrier was not excluded")
	}
	flow.Route(fs.OutboundRef{Tag: "tag-1"})
	flow.Unassign()
	flow.AddUplink(99)
	flow.AddDownlink(99)

	flow.Finish()
	live, _ := s.ReadLive()
	page, _ := s.ReadTerminals()
	totals, _ := s.ReadTotals()
	if len(live.Rows) != 0 || len(page.Rows) != 0 || s.nextID != 0 {
		t.Fatalf("carrier published state: %+v %+v", live, page)
	}
	for _, row := range totals.Rows {
		if row.Uplink != 0 || row.Downlink != 0 {
			t.Fatalf("carrier totals: %+v", row)
		}
	}
	logical := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	if logical.Ref().ID != 1 {
		t.Fatal("carrier consumed logical ID/capacity")
	}
	logical.Finish()
}

func TestInspectionPreparedFirstRouteAndFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		s := testInspectionStore(t, fs.ObservationOptions{})
		flow := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil).(*inspectionExchange)
		opened := flow.record.Opened
		flow.AddUplink(11)
		flow.Route(fs.OutboundRef{Tag: "forward"})
		live, _ := s.ReadLive()
		if len(live.Rows) != 1 || live.Rows[0].Outbound.Tag != "forward" {
			t.Fatal("first selection did not publish endpoint")
		}
		if !failed {
			flow.Route(fs.OutboundRef{Tag: "consume"})
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() { defer wg.Done(); flow.Route(fs.OutboundRef{Tag: "consume"}) }()
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
		page, _ := s.ReadTerminals()
		want := uint64(14)
		if failed {
			want = 11
		}
		if len(page.Rows) != 1 || page.Rows[0].Flow.Opened != opened || page.Rows[0].Flow.Uplink != want || page.Rows[0].Flow.Outbound.Tag != "forward" {
			t.Fatalf("early facts lost: %+v", page)
		}
	}
}

func TestInspectionRefusedRegistrationCanUseFreedCapacity(t *testing.T) {
	for _, exclude := range []bool{false, true} {
		s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
		first := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		waiting := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		waiting.AddUplink(7)
		if waiting.Ref().ID != 0 {
			t.Fatal("capacity refusal assigned a live identity")
		}
		if exclude && !waiting.ExcludeCarrier() {
			t.Fatal("unaddressable carrier was not excluded")
		}
		first.Finish()
		var bindings sync.WaitGroup
		for range 8 {
			bindings.Go(func() { waiting.Route(fs.OutboundRef{Tag: "freed"}) })
		}
		bindings.Wait()
		live, _ := s.ReadLive()
		if exclude {
			if waiting.Ref().ID != 0 || len(live.Rows) != 0 {
				t.Fatal("excluded carrier acquired the freed capacity")
			}
		} else if waiting.Ref().ID != 2 || len(live.Rows) != 1 || live.Rows[0].Uplink != 7 {
			t.Fatalf("freed capacity lost identity or observed bytes: %+v", live)
		}
	}
}

func TestInspectionPreparedCapacityAtFirstSelection(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
	a := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	b := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	a.AddUplink(5)
	a.Route(fs.OutboundRef{Tag: "capacity"})
	a.Route(fs.OutboundRef{Tag: "capacity"})
	if a.Ref().ID != 0 || b.Ref().ID != 1 {
		t.Fatal("incorrect registration capacity")
	}
	a.Finish()
	b.Finish()
	totals, _ := s.ReadTotals()
	if findTotal(t, totals.Rows, "capacity", fs.TrafficOriginUser).Uplink != 5 {
		t.Fatal("overflow lost actual payload")
	}
}
