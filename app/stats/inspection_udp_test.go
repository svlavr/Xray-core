package stats

import (
	"strings"
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func TestInspectionLatestPacketDestinationPreservedAndCopied(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	flow := store.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	first := xnet.UDPDestination(xnet.DomainAddress("first.example"), 53)
	second := xnet.UDPDestination(xnet.DomainAddress(strings.Repeat("d", 275)), 443)
	third := xnet.UDPDestination(xnet.DomainAddress("over-limit.example"), 123)
	flow.PacketDestination(first)
	flow.PacketDestination(first)
	flow.PacketDestination(second)

	live, err := store.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live packet destinations: %+v %v", live, err)
	}
	row := live.Rows[0]
	if row.Destination != second {
		t.Fatalf("latest packet destination was rewritten: %+v", row)
	}
	live.Rows[0].Destination = third
	again, err := store.ReadLiveInto(nil)
	if err != nil || again.Rows[0].Destination.Port != second.Port {
		t.Fatalf("live snapshot retained caller destination: %+v %v", again, err)
	}

	flow.Finish()
	flow.PacketDestination(third)
	page, err := store.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Destination.Port != second.Port {
		t.Fatalf("terminal packet destinations: %+v %v", page, err)
	}
	page.Rows[0].Flow.Destination = third
	pageAgain, err := store.ReadTerminals()
	if err != nil || pageAgain.Rows[0].Flow.Destination.Port != second.Port {
		t.Fatalf("terminal snapshot retained caller destination: %+v %v", pageAgain, err)
	}
}

func TestInspectionPacketInputLiveAtomic(t *testing.T) {
	s := testInspectionStore(t, featurestats.ObservationOptions{})
	defer s.close()
	flow := s.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.Route(featurestats.OutboundRef{Tag: "packets"})
	start, done := make(chan struct{}), make(chan struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		for i := 1; i <= 10000; i++ {
			flow.RecordPacketInput(xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(i)), 1)
		}
		close(done)
	})
	for range 2 {
		workers.Go(func() {
			<-start
			var rows []featurestats.FlowRecord
			for {
				live, err := s.ReadLiveInto(rows)
				rows = live.Rows
				if err != nil || len(rows) != 1 {
					t.Errorf("live event: %+v %v", live, err)
					return
				}
				if rows[0].Uplink != uint64(rows[0].Destination.Port) {
					t.Errorf("split packet event: %+v", rows[0])
					return
				}
				select {
				case <-done:
					return
				default:
				}
			}
		})
	}
	close(start)
	workers.Wait()
	totals, _ := s.ReadTotals()
	if totals.User.Uplink != 10000 || findTotal(t, totals.Rows, "packets", featurestats.TrafficOriginUser).Uplink != 0 {
		t.Fatal("packet totals lost")
	}
}

func TestInspectionPacketInputFinishAndProvenance(t *testing.T) {
	first := xnet.UDPDestination(xnet.LocalHostIP, 53)
	last := xnet.UDPDestination(xnet.LocalHostIP, 443)
	for _, legInput := range []bool{false, true} {
		for _, fence := range []string{"finish", "rebind"} {
			for range 100 {
				s := testInspectionStore(t, featurestats.ObservationOptions{})
				root := s.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, first, nil)
				input := root
				if legInput {
					input = root.NewLeg()
				}
				input.Route(featurestats.OutboundRef{Tag: "packets"})
				start := make(chan struct{})
				var workers sync.WaitGroup
				workers.Go(func() { <-start; input.RecordPacketInput(last, 7) })
				workers.Go(func() {
					<-start
					if fence == "finish" {
						root.Finish()
					} else {
						root.Rebind(s.runtime, featurestats.TrafficOriginInternal)
					}
				})
				close(start)
				workers.Wait()
				var row featurestats.FlowRecord
				if fence == "finish" {
					page, _ := s.ReadTerminals()
					if len(page.Rows) != 1 {
						t.Fatal("root terminal missing")
					}
					row = page.Rows[0].Flow
				} else {
					page, _ := s.ReadLiveInto(nil)
					row = page.Rows[0]
				}
				if !((row.Destination == first && row.Uplink == 0) || (row.Destination == last && row.Uplink == 7)) {
					t.Fatalf("%s split event, leg=%v: %+v", fence, legInput, row)
				}
				input.RecordPacketInput(first, 3)
				totals, _ := s.ReadTotals()
				want := row.Uplink
				if fence == "finish" {
					want = 10 // Late bytes still update their original bucket.
					page, _ := s.ReadTerminals()
					if page.Rows[0].Flow != row {
						t.Fatal("late event rewrote root terminal")
					}
				}
				if got := totals.User.Uplink; got != want {
					t.Fatalf("%s attribution: got %d want %d", fence, got, want)
				}
				s.close()
			}
		}
	}
}

func TestInspectionPacketInputPendingEmptyInvalidAndLateLeg(t *testing.T) {
	s := testInspectionStore(t, featurestats.ObservationOptions{})
	defer s.close()
	first := xnet.UDPDestination(xnet.LocalHostIP, 53)
	last := xnet.UDPDestination(xnet.LocalHostIP, 443)
	root := s.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, first, nil)
	leg := root.NewLeg()
	leg.RecordPacketInput(last, 0)
	leg.RecordPacketInput(xnet.Destination{}, 7)
	before, _ := s.ReadLiveInto(nil)
	if len(before.Rows) != 1 || before.Rows[0].Destination != last || before.Rows[0].Uplink != 7 {
		t.Fatalf("empty/invalid packet event: %+v", before)
	}
	leg.Route(featurestats.OutboundRef{Tag: "packets"})
	leg.Finish()
	leg.RecordPacketInput(first, 3)
	page, _ := s.ReadLiveInto(nil)
	if len(page.Rows) != 1 || page.Rows[0].Destination != first || page.Rows[0].Uplink != 10 {
		t.Fatalf("late selected leg event: %+v", page)
	}
	totals, _ := s.ReadTotals()
	if totals.User.Uplink != 10 || findTotal(t, totals.Rows, "packets", featurestats.TrafficOriginUser).Uplink != 0 {
		t.Fatal("pending packet attribution lost")
	}
	excluded := s.PrepareTCP(featurestats.TrafficOriginUser, xnet.Destination{}, first, nil)
	if !excluded.ExcludeCarrier() {
		t.Fatal("unregistered carrier not excluded")
	}
	excluded.RecordPacketInput(last, 99)
	excluded.Route(featurestats.OutboundRef{Tag: "packets"})
	excluded.Finish()
	totals, _ = s.ReadTotals()
	if totals.User.Uplink != 10 || findTotal(t, totals.Rows, "packets", featurestats.TrafficOriginUser).Uplink != 0 {
		t.Fatal("excluded carrier credited")
	}
}

func TestInspectionDestinationFollowsPacketsNotRouteCompletion(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	root := store.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	older, newer := root.NewLeg(), root.NewLeg()
	first := xnet.UDPDestination(xnet.DomainAddress("first.example"), 53)
	last := xnet.UDPDestination(xnet.DomainAddress("last.example"), 443)
	older.PacketDestination(first)
	older.AddUplink(3)
	older.AddSelectedUplink(3)
	newer.PacketDestination(last)
	newer.AddUplink(5)
	newer.AddSelectedUplink(5)
	newer.Route(featurestats.OutboundRef{Tag: "newer"})
	older.Route(featurestats.OutboundRef{Tag: "older"})
	live, err := store.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Destination != last || live.Rows[0].Uplink != 8 {
		t.Fatalf("packet order changed by delayed route: %+v %v", live, err)
	}
	totals, _ := store.ReadTotals()
	if totals.User.Uplink != 8 || findTotal(t, totals.Rows, "older", featurestats.TrafficOriginUser).Uplink != 0 || findTotal(t, totals.Rows, "newer", featurestats.TrafficOriginUser).Uplink != 0 {
		t.Fatalf("per-leg byte attribution changed: %+v", totals)
	}
}

func TestInspectionSelectedLegEndBeforePacketReceipt(t *testing.T) {
	s := testInspectionStore(t, featurestats.ObservationOptions{})
	first := xnet.UDPDestination(xnet.DomainAddress("data.invalid"), 53)
	last := xnet.UDPDestination(xnet.DomainAddress("carrier.invalid"), 443)
	root := s.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, first, nil)
	leg := root.NewLeg()
	leg.Route(featurestats.OutboundRef{Tag: "portal"})
	// Native selection/early rejection may finish before Dispatch records the
	// first decoded packet. Its late bytes and destination are still facts.
	leg.Finish()
	leg.PacketDestination(last)
	leg.AddUplink(21)
	leg.AddSelectedUplink(21)
	live, err := s.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Destination != last || live.Rows[0].Uplink != 21 {
		t.Fatalf("late packet receipt lost destination: %+v %v", live, err)
	}
	root.Finish()
	leg.PacketDestination(first)
	leg.AddUplink(7)
	leg.AddSelectedUplink(7)
	page, err := s.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Destination != last || page.Rows[0].Flow.Uplink != 21 {
		t.Fatalf("late packet changed frozen terminal: %+v %v", page, err)
	}
	totals, _ := s.ReadTotals()
	if findTotal(t, totals.Rows, "portal", featurestats.TrafficOriginUser).Uplink != 28 {
		t.Fatal("late packet totals lost")
	}
}
