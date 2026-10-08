package stats

import (
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestInspectionClientTotalsAdmissionAndCapture(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxBuckets: 1, MaxLive: 1})
	c, err := s.CaptureObservations(32)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, origin := range []fs.TrafficOrigin{fs.TrafficOriginUnknown, fs.TrafficOriginInternal, fs.TrafficOriginControlledMeasurement, fs.TrafficOriginUser} {
		flow := s.Begin(xnet.Network_UDP, origin, xnet.Destination{}, xnet.Destination{}, nil)
		flow.AddUplink(7)
		flow.AddSelectedUplink(7)
		flow.AddDownlink(3)
		before, _ := s.ReadTotals()
		if origin == fs.TrafficOriginUser && (before.User.Uplink != 7 || len(before.Rows) != 0) {
			t.Fatalf("pre-route bytes missing: %+v", before)
		}
		flow.Route(fs.OutboundRef{Tag: "shared"})
		flow.Finish()
	}
	got, _ := s.ReadTotals()
	if got.User != (fs.ClientTotals{Uplink: 7, Downlink: 3}) || got.BucketsOmitted != 0 || len(got.Rows) != 1 || got.Rows[0].Origin != fs.TrafficOriginUser || got.Rows[0].Uplink != 0 || got.Rows[0].Downlink != 0 {
		t.Fatalf("origin isolation/capacity: %+v", got)
	}
	batch := c.ReadInto(nil)
	ends := make(map[fs.TrafficOrigin]bool)
	for _, fact := range batch.Rows {
		if fact.Kind == fs.ObservationEnd && fact.Flow.Uplink == 7 && fact.Flow.Downlink == 3 {
			ends[fact.Flow.Origin] = true
		}
	}
	if len(ends) != 4 || batch.Dropped != 0 {
		t.Fatalf("C1 origin facts lost: %+v", batch)
	}
}

func TestInspectionClientTotalsPreparedFailureAndCarrier(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	failed := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	failed.AddUplink(11)
	failed.AddSelectedUplink(11)
	failed.AddDownlink(2)
	carrier := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	carrier.AddUplink(19)
	carrier.AddSelectedUplink(19)
	if !carrier.ExcludeCarrier() {
		t.Fatal("prepared carrier not excluded")
	}
	carrier.Finish()
	before, _ := s.ReadTotals()
	if before.User != (fs.ClientTotals{}) {
		t.Fatalf("unclassified prefix published: %+v", before)
	}
	failed.Finish()
	failed.AddUplink(3)
	failed.AddSelectedUplink(3)
	failed.Finish()
	got, _ := s.ReadTotals()
	if got.User != (fs.ClientTotals{Uplink: 14, Downlink: 2}) || len(got.Rows) != 0 || got.BucketsOmitted != 0 {
		t.Fatalf("failure/late prefix lost or duplicated: %+v", got)
	}
	fresh := testInspectionStore(t, fs.ObservationOptions{})
	reset, _ := fresh.ReadTotals()
	if reset.User != (fs.ClientTotals{}) {
		t.Fatalf("new store inherited totals: %+v", reset)
	}
}

func TestInspectionClientTotalsBucketSaturationAndLateRays(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxBuckets: 1, MaxLive: 1})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	a, b := root.NewLeg(), root.NewLeg()
	a.AddUplink(5)
	a.AddSelectedUplink(5)
	b.AddUplink(7)
	b.AddSelectedUplink(7)
	a.Route(fs.OutboundRef{Tag: "kept"})
	b.Route(fs.OutboundRef{Tag: "omitted"})
	b.Route(fs.OutboundRef{Tag: "kept"}) // Refusal cannot retry or change custody.
	root.Finish()
	var workers sync.WaitGroup
	workers.Go(func() { a.AddDownlink(13); a.Finish() })
	workers.Go(func() { b.AddDownlink(17); b.Finish() })
	workers.Wait()
	reused := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	reused.Route(fs.OutboundRef{Tag: "kept"})
	reused.AddUplink(19)
	reused.AddSelectedUplink(19)
	reused.Finish()
	again := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	again.Route(fs.OutboundRef{Tag: "omitted"})
	again.AddUplink(23)
	again.AddSelectedUplink(23)
	again.Finish()
	got, _ := s.ReadTotals()
	if got.User != (fs.ClientTotals{Uplink: 54, Downlink: 30}) || got.BucketsOmitted != 2 || len(got.Rows) != 1 || got.Rows[0].Uplink != 19 || got.Rows[0].Downlink != 13 {
		t.Fatalf("capacity or pending replay contaminated general/selected totals: %+v", got)
	}
}
