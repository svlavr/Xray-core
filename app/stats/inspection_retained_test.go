package stats

import (
	"context"
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestInspectionRetainedProvenanceFence(t *testing.T) {
	for _, test := range []struct {
		name     string
		runtime  fs.RuntimeID
		origin   fs.TrafficOrigin
		conflict bool
	}{
		{"matching", fs.RuntimeID{1}, fs.TrafficOriginUser, false},
		{"foreign-runtime", fs.RuntimeID{2}, fs.TrafficOriginUser, true},
		{"missing-runtime", fs.RuntimeID{}, fs.TrafficOriginUser, true},
		{"unknown-origin", fs.RuntimeID{1}, fs.TrafficOriginUnknown, true},
		{"internal-origin", fs.RuntimeID{1}, fs.TrafficOriginInternal, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testInspectionStore(t, fs.ObservationOptions{})
			flow := store.Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil).(*inspectionExchange)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1, Tag: "selected"}})
			flow.BindRoute()
			flow.AddUplink(7)
			flow.AddDownlink(11)
			first := xnet.UDPDestination(xnet.LocalHostIP, 53)
			second := xnet.UDPDestination(xnet.LocalHostIP, 54)
			flow.PacketDestination(first)
			before := flow.snapshot()
			flow.Rebind(test.runtime, test.origin)
			flow.AddUplink(100)
			flow.AddDownlink(200)
			flow.PacketDestination(second)
			flow.Rebind(store.runtime, fs.TrafficOriginUser) // conflict cannot be repaired by a later matching carrier
			row := flow.snapshot()
			if test.conflict {
				if len(row.Destinations) != 1 || row.Destinations[0] != first {
					t.Fatalf("conflict changed packet attribution: %+v", row.Destinations)
				}
				if row.Uplink.Known != 7 || row.Downlink.Known != 11 || row.Origin != fs.TrafficOriginUser || !row.Uplink.Incomplete || !row.Downlink.Incomplete || before.Uplink.Incomplete || before.Downlink.Incomplete {
					t.Fatalf("conflict facts: %+v", row)
				}
			} else if row.Uplink.Known != 107 || row.Downlink.Known != 211 || flow.provenanceConflict {
				t.Fatalf("matching facts: %+v", row)
			} else if len(row.Destinations) != 2 || row.Destinations[1] != second {
				t.Fatalf("matching carrier lost packet attribution: %+v", row.Destinations)
			}
			flow.Finish()
			page, _ := store.ReadTerminals(context.Background())
			if len(page.Rows) != 1 || page.Rows[0].Flow.Ref != row.Ref {
				t.Fatal("fence replaced logical reference")
			}
		})
	}
}

func TestInspectionRetainedFenceRejectsConcurrentLateCredit(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{})
	flow := store.Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil).(*inspectionExchange)
	flow.BindRoute()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			flow.AddUplink(1)
			flow.AddDownlink(1)
		}
	}()
	flow.Rebind(fs.RuntimeID{2}, fs.TrafficOriginUser)
	fenced := flow.snapshot()
	wg.Wait()
	flow.AddUplink(99)
	flow.AddDownlink(99)
	final := flow.snapshot()
	if final.Uplink.Known != fenced.Uplink.Known || final.Downlink.Known != fenced.Downlink.Known {
		t.Fatal("post-fence credit changed known lower bound")
	}
	flow.Finish()
}

func TestInspectionIncompleteAssociationDoesNotContaminateLegBucket(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{})
	flow := store.Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.MarkUplinkIncomplete()
	flow.MarkDownlinkIncomplete()
	leg := flow.NewLeg()
	leg.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1, Tag: "leg"}})
	leg.BindRoute()
	leg.AddUplink(7)
	flow.Finish()
	page, _ := store.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 7 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("owner-end association snapshot: %+v", page)
	}
	leg.Finish()
	page, _ = store.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 7 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("association retirement lost facts: %+v", page)
	}
	totals, _ := store.ReadTotals(context.Background())
	for _, row := range totals.Rows {
		if row.Outbound.Serial == 1 && (row.Uplink.Known != 7 || row.Uplink.Incomplete || row.Downlink.Incomplete) {
			t.Fatalf("root incompleteness contaminated leg bucket: %+v", row)
		}
	}
}
