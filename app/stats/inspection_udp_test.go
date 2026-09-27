package stats

import (
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func TestInspectionLatestPacketDestinationBoundedAndCopied(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	flow := store.Begin(featurestats.FlowKindUDPAssociation, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	first := xnet.UDPDestination(xnet.DomainAddress("first.example"), 53)
	second := xnet.UDPDestination(xnet.DomainAddress(strings.Repeat("d", maxMetadataString+20)), 443)
	third := xnet.UDPDestination(xnet.DomainAddress("over-limit.example"), 123)
	flow.PacketDestination(first)
	flow.PacketDestination(first)
	flow.PacketDestination(second)

	live, err := store.ReadLive()
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live packet destinations: %+v %v", live, err)
	}
	row := live.Rows[0]
	if row.LatestDestination.Port != second.Port || len(row.LatestDestination.Address.Domain()) != maxMetadataString {
		t.Fatalf("bounded latest packet destination: %+v", row)
	}
	live.Rows[0].LatestDestination = third
	again, err := store.ReadLive()
	if err != nil || again.Rows[0].LatestDestination.Port != second.Port {
		t.Fatalf("live snapshot retained caller destination: %+v %v", again, err)
	}

	flow.Finish()
	flow.PacketDestination(third)
	page, err := store.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.LatestDestination.Port != second.Port {
		t.Fatalf("terminal packet destinations: %+v %v", page, err)
	}
	page.Rows[0].Flow.LatestDestination = third
	pageAgain, err := store.ReadTerminals()
	if err != nil || pageAgain.Rows[0].Flow.LatestDestination.Port != second.Port {
		t.Fatalf("terminal snapshot retained caller destination: %+v %v", pageAgain, err)
	}
}

func TestInspectionLatestDestinationFollowsPacketsNotRouteCompletion(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	root := store.Begin(featurestats.FlowKindUDPAssociation, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	older, newer := root.NewLeg(), root.NewLeg()
	first := xnet.UDPDestination(xnet.DomainAddress("first.example"), 53)
	last := xnet.UDPDestination(xnet.DomainAddress("last.example"), 443)
	older.PacketDestination(first)
	older.AddUplink(3)
	newer.PacketDestination(last)
	newer.AddUplink(5)
	newer.Route(featurestats.RouteStep{Outbound: featurestats.OutboundRef{Serial: 2, Tag: "newer"}})
	newer.BindRoute()
	older.Route(featurestats.RouteStep{Outbound: featurestats.OutboundRef{Serial: 1, Tag: "older"}})
	older.BindRoute()
	live, err := store.ReadLive()
	if err != nil || len(live.Rows) != 1 || live.Rows[0].LatestDestination != last || live.Rows[0].Uplink.Known != 8 {
		t.Fatalf("packet order changed by delayed route: %+v %v", live, err)
	}
	totals, _ := store.ReadTotals()
	if findTotal(t, totals.Rows, 1, featurestats.TrafficOriginUser).Uplink.Known != 3 || findTotal(t, totals.Rows, 2, featurestats.TrafficOriginUser).Uplink.Known != 5 {
		t.Fatalf("per-leg byte attribution changed: %+v", totals)
	}
}
