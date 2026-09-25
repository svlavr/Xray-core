package stats

import (
	"context"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func TestInspectionPacketDestinationsBoundedDeduplicatedAndCopied(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxDestinations: 2})
	flow := store.Begin(featurestats.FlowKindUDPAssociation, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	first := xnet.UDPDestination(xnet.DomainAddress("first.example"), 53)
	second := xnet.UDPDestination(xnet.DomainAddress(strings.Repeat("d", maxMetadataString+20)), 443)
	third := xnet.UDPDestination(xnet.DomainAddress("over-limit.example"), 123)
	flow.PacketDestination(first)
	flow.PacketDestination(first)
	flow.PacketDestination(second)
	flow.PacketDestination(third)

	live, err := store.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live packet destinations: %+v %v", live, err)
	}
	row := live.Rows[0]
	if len(row.Destinations) != 2 || row.Destinations[0] != first || row.Destinations[1].Port != second.Port || len(row.Destinations[1].Address.Domain()) != maxMetadataString || !row.MetadataTruncated || !live.Loss.MetadataTruncated {
		t.Fatalf("bounded packet destinations: %+v loss=%+v", row, live.Loss)
	}
	live.Rows[0].Destinations[0] = third
	again, err := store.ReadLive(context.Background())
	if err != nil || again.Rows[0].Destinations[0] != first {
		t.Fatalf("live snapshot retained caller destination slice: %+v %v", again, err)
	}

	flow.Finish()
	flow.PacketDestination(third)
	page, err := store.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || len(page.Rows[0].Flow.Destinations) != 2 || page.Rows[0].Flow.Destinations[0] != first {
		t.Fatalf("terminal packet destinations: %+v %v", page, err)
	}
	page.Rows[0].Flow.Destinations[0] = third
	pageAgain, err := store.ReadTerminals(context.Background())
	if err != nil || pageAgain.Rows[0].Flow.Destinations[0] != first {
		t.Fatalf("terminal snapshot retained caller destination slice: %+v %v", pageAgain, err)
	}
}
