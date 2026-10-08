package stats

import (
	"context"
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestObservationCaptureShortFlowsBeyondLiveCapacity(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1, MaxTerminals: 1})
	c, err := s.CaptureObservations(32)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	held := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	dest := xnet.TCPDestination(xnet.DomainAddress("short.example"), 443)
	short := s.PrepareTCP(fs.TrafficOriginUser, xnet.TCPDestination(xnet.LocalHostIP, 1234), dest, nil)
	short.Route(fs.OutboundRef{Tag: "short"})
	short.AddUplink(7)
	short.AddSelectedUplink(7)
	short.Finish()
	if short.Ref().ID != 0 {
		t.Fatal("capture changed live admission or control identity")
	}
	batch := c.ReadInto(nil)
	var id uint64
	var selected, ended bool
	for _, row := range batch.Rows {
		if row.Flow.Destination != dest {
			continue
		}
		if row.FlowID == 0 || row.Flow.Ref.ID != 0 || row.Flow.Source.Port != 1234 {
			t.Fatalf("missing correlation independently of live capacity: %+v", row)
		}
		if id != 0 && row.FlowID != id {
			t.Fatal("one short flow acquired multiple identities")
		}
		id = row.FlowID
		selected = selected || row.Kind == fs.ObservationSelection && row.Selected && row.Flow.Outbound.Tag == "short"
		ended = ended || row.Kind == fs.ObservationEnd && row.Flow.Uplink == 7
	}
	if !selected || !ended || batch.Dropped != 0 {
		t.Fatalf("short flow lost between reads: %+v", batch)
	}
	held.Finish()
}

func TestObservationCapturePairsOverlappingUDPRays(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	c, _ := s.CaptureObservations(64)
	defer c.Close()
	a := xnet.UDPDestination(xnet.DomainAddress("a.example"), 53)
	b := xnet.UDPDestination(xnet.DomainAddress("b.example"), 54)
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, a, nil)
	older, newer := root.NewLeg(), root.NewLeg()
	older.RecordPacketInput(a, 2)
	newer.PacketDestination(b)
	newer.Route(fs.OutboundRef{Tag: "new"})
	older.Route(fs.OutboundRef{Tag: "old"})
	newer.RecordPacketInput(b, 3)
	root.Finish()
	older.RecordPacketInput(a, 4) // A late older ray never inherits newer metadata.
	rows := c.ReadInto(nil).Rows
	var olderID, newerID uint64
	var pending, oldSelected, newSelected, late bool
	for _, row := range rows {
		if row.RayID == 0 {
			if row.Kind == fs.ObservationEnd && (row.Selected || row.Flow.Outbound.Tag != "") {
				t.Fatal("association end advertised an unmatched latest tag")
			}
			continue
		}
		switch row.Flow.Destination {
		case a:
			olderID = row.RayID
			pending = pending || !row.Selected
			if row.Selected {
				if row.Flow.Outbound.Tag != "old" {
					t.Fatalf("older occurrence credited to another ray: %+v", row)
				}
				oldSelected = true
				late = late || row.Kind == fs.ObservationDestination && row.Flow.Uplink == 9
			}
		case b:
			newerID = row.RayID
			if row.Selected {
				if row.Flow.Outbound.Tag != "new" {
					t.Fatalf("newer occurrence credited to another ray: %+v", row)
				}
				newSelected = true
			}
		default:
			t.Fatalf("ray lost its destination: %+v", row)
		}
	}
	if olderID == 0 || newerID == 0 || olderID == newerID || !pending || !oldSelected || !newSelected || !late {
		t.Fatalf("incomplete overlapping-ray facts: %+v", rows)
	}
}

func TestObservationCaptureBoundariesLossAndDetachedDrain(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
	indexed := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	unindexed := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	if _, err := s.CaptureObservations(0); err == nil {
		t.Fatal("zero capacity accepted")
	}
	c, err := s.CaptureObservations(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CaptureObservations(1); err == nil {
		t.Fatal("second concurrent capture accepted")
	}
	// Without any reads, a full queue still permits traffic and stop.
	unindexed.PacketDestination(xnet.UDPDestination(xnet.LocalHostIP, 53))
	unindexed.Finish()
	batch := c.ReadInto(nil)
	if len(batch.Rows) != 1 || batch.Rows[0].Kind != fs.ObservationExisting || !batch.ExistingPartial || batch.Dropped != 3 {
		t.Fatalf("baseline/overflow scope = %+v", batch)
	}
	batch.Rows[0].Flow.Outbound.Tag = "caller mutation"
	unindexed = s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	row := c.ReadInto(batch.Rows)
	if len(row.Rows) != 1 || row.Rows[0].Flow.Outbound.Tag != "" || row.Dropped != 3 {
		t.Fatalf("drain retained caller mutation or reset loss: %+v", row)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	indexed.Finish()
	final := c.ReadInto(row.Rows)
	if !final.Stopped || final.Ended < final.Started || len(final.Rows) != 0 || final.Dropped != 3 || row.Rows[0] != (fs.FlowObservation{}) {
		t.Fatalf("stop/reuse boundary = %+v", final)
	}
	second, err := s.CaptureObservations(8)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close() // An old handle must not unregister its replacement.
	unindexed.Finish()
	if len(second.ReadInto(nil).Rows) != 2 {
		t.Fatal("already-active unindexed flow lost its next fact")
	}
	s.close()
	if !second.ReadInto(nil).Stopped {
		t.Fatal("manager closure left a capture active")
	}
	if _, err := s.CaptureObservations(8); err == nil {
		t.Fatal("closed store accepted capture")
	}
}

func TestObservationCaptureConcurrencyAndCloseIsolation(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxTerminals: 1})
	c, _ := s.CaptureObservations(16)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for j := 0; j < 64; j++ {
				flow := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
				flow.Route(fs.OutboundRef{Tag: "shared"})
				flow.AddUplink(1)
				flow.AddSelectedUplink(1)
				flow.Finish()
			}
		})
	}
	workers.Go(func() {
		var rows []fs.FlowObservation
		for i := 0; i < 64; i++ {
			rows = c.ReadInto(rows).Rows
		}
	})
	workers.Wait()
	_ = c.Close()
	page, _ := s.ReadTerminals()
	if page.Overwritten != 255 || len(page.Rows) != 1 {
		t.Fatalf("ring overwrite count = %+v", page)
	}
	stops := 0
	a := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { stops++; return nil })
	b := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { t.Error("sibling stopped"); return nil })
	_, _ = s.CloseFlows(context.Background(), []fs.FlowRef{a.Ref(), a.Ref()})
	if stops != 1 {
		t.Fatalf("exact close invoked owner %d times", stops)
	}
	b.Finish()
}

func TestObservationCaptureDoesNotPublishExcludedOrConflictingFacts(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	c, _ := s.CaptureObservations(16)
	defer c.Close()
	carrier := s.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	carrier.SetSource(xnet.TCPDestination(xnet.LocalHostIP, 1234))
	if !carrier.ExcludeCarrier() {
		t.Fatal("carrier exclusion failed")
	}
	carrier.Route(fs.OutboundRef{Tag: "carrier"})
	carrier.Finish()
	if len(c.ReadInto(nil).Rows) != 0 {
		t.Fatal("physical carrier became a captured logical endpoint")
	}
	flow := s.Begin(xnet.Network_UDP, fs.TrafficOriginInternal, xnet.Destination{}, xnet.Destination{}, nil)
	_ = c.ReadInto(nil)
	flow.Rebind(s.runtime, fs.TrafficOriginUser)
	flow.PacketDestination(xnet.UDPDestination(xnet.LocalHostIP, 53))
	flow.Route(fs.OutboundRef{Tag: "user"})
	flow.Finish()
	if len(c.ReadInto(nil).Rows) != 0 {
		t.Fatal("conflicting retained provenance acquired capture facts")
	}
}

func TestObservationCaptureConcurrentStopAndRestart(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	flow := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	defer flow.Finish()
	for i := 0; i < 8; i++ {
		capture, err := s.CaptureObservations(4)
		if err != nil {
			t.Fatal(err)
		}
		entered, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			flow.PacketDestination(xnet.UDPDestination(xnet.LocalHostIP, 53))
			close(entered)
			for {
				select {
				case <-stop:
					return
				default:
					flow.RecordPacketInput(xnet.UDPDestination(xnet.LocalHostIP, 54), 1)
				}
			}
		}()
		<-entered
		_ = capture.Close()
		final := capture.ReadInto(nil)
		close(stop)
		<-done
		after := capture.ReadInto(nil)
		if !final.Stopped || after.Ended != final.Ended || after.Dropped != final.Dropped || len(after.Rows) != 0 {
			t.Fatalf("producer committed after stop: final=%+v after=%+v", final, after)
		}
	}
}
