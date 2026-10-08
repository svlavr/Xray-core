package stats

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

// This driver isolates the existing store/cursor contour, not socket forwarding.
// Returned buffers stay owned by the driver and are reused without readv/copy.
type inspectionBenchmarkReader struct{ packets buf.MultiBuffer }

func (r inspectionBenchmarkReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return r.packets, nil }

func BenchmarkInspectionPacketInput(b *testing.B) {
	destination := xnet.UDPDestination(xnet.LocalHostIP, 53)
	for _, contour := range []string{"receipt", "cursor"} {
		for _, packets := range []int{1, 4, 16} {
			if contour == "receipt" && packets != 1 {
				continue
			}
			for _, kind := range []string{"udp", "tcp", "observed"} {
				if contour == "receipt" && kind != "udp" {
					continue
				}
				b.Run(fmt.Sprintf("%s/%s/batch=%d", contour, kind, packets), func(b *testing.B) {
					s := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{}))
					defer s.close()
					flow := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, destination, nil)
					flow.Route(fs.OutboundRef{Tag: "packets"})
					mb := make(buf.MultiBuffer, packets)
					for i := range mb {
						mb[i] = buf.FromBytes(make([]byte, 1200))
						mb[i].UDP = &destination
					}
					defer buf.ReleaseMulti(mb)
					cursor := buf.NewInspectionReader(inspectionBenchmarkReader{packets: mb}, flow, func() {})
					defer cursor.Interrupt()
					if kind != "tcp" {
						cursor.PacketDestination = destination
					}
					cursor.InputAlreadyObserved = kind == "observed"
					b.ReportAllocs()
					b.SetBytes(int64(1200 * packets))
					b.ResetTimer()
					for b.Loop() {
						if contour == "receipt" {
							flow.RecordPacketInput(destination, 1200)
						} else if _, err := cursor.ReadMultiBuffer(); err != nil {
							b.Fatal(err)
						}
					}
					wantUser := uint64(b.N) * uint64(1200*packets)
					if kind == "observed" {
						wantUser = 0
					}
					wantSelected := uint64(b.N) * uint64(1200*packets)
					if contour == "receipt" {
						wantSelected = 0 // Admission alone is not selected execution consumption.
					}
					totals, err := s.ReadTotals()
					if err != nil {
						b.Fatal(err)
					}
					var up uint64
					for _, row := range totals.Rows {
						up += row.Uplink
					}
					if totals.User.Uplink != wantUser || up != wantSelected {
						b.Fatalf("packet totals: %+v want USER=%d selected=%d", totals, wantUser, wantSelected)
					}
				})
			}
		}
	}
}

func BenchmarkInspectionAdmission(b *testing.B) {
	for _, kind := range []string{"tcp", "udp", "udp_leg", "cap_refused"} {
		b.Run(kind, func(b *testing.B) {
			s := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{MaxLive: 1, MaxTerminals: 64}))
			b.Cleanup(s.close)
			if kind == "cap_refused" {
				s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				network := xnet.Network_TCP
				if kind == "udp" || kind == "udp_leg" {
					network = xnet.Network_UDP
				}
				root := s.Begin(network, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
				receipt := root
				if kind == "udp_leg" {
					receipt = root.NewLeg()
				}
				receipt.Route(fs.OutboundRef{Tag: "bench"})
				receipt.AddUplink(1)
				receipt.AddSelectedUplink(1)
				if kind == "udp_leg" {
					receipt.Finish()
				}
				root.Finish()
			}
		})
	}
}

// drain256 includes both producer and reusable consumer work. full measures
// incoming fact loss on a primed queue; it is not a no-loss capture result.
func BenchmarkInspectionCapturePacketInput(b *testing.B) {
	destination := xnet.UDPDestination(xnet.LocalHostIP, 53)
	for _, mode := range []string{"off", "drain256", "full"} {
		b.Run(mode, func(b *testing.B) {
			s := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{}))
			b.Cleanup(s.close)
			flow := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, destination, nil)
			flow.Route(fs.OutboundRef{Tag: "capture"})
			var capture fs.ObservationCapture
			storage := make([]fs.FlowObservation, 0, 256)
			if mode != "off" {
				var err error
				capture, err = s.CaptureObservations(256)
				if err != nil {
					b.Fatal(err)
				}
				storage = capture.ReadInto(storage).Rows
				if mode == "full" {
					for range 256 {
						flow.PacketDestination(destination)
					}
				}
			}
			var receipts uint64
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				flow.RecordPacketInput(destination, 1200)
				receipts++
				if mode == "drain256" && receipts%256 == 0 {
					batch := capture.ReadInto(storage)
					storage = batch.Rows
					if batch.Dropped != 0 || len(batch.Rows) != 256 {
						b.Fatalf("draining capture: rows=%d dropped=%d", len(batch.Rows), batch.Dropped)
					}
				}
			}
			totals, err := s.ReadTotals()
			if err != nil || totals.User != (fs.ClientTotals{Uplink: receipts * 1200}) || len(totals.Rows) != 1 || totals.Rows[0].Uplink != 0 {
				b.Fatalf("general/selected receipt boundary: %+v err=%v", totals, err)
			}
			if capture != nil {
				batch := capture.ReadInto(storage)
				if (mode == "full" && batch.Dropped != receipts) || (mode == "drain256" && batch.Dropped != 0) {
					b.Fatalf("capture loss: mode=%s receipts=%d dropped=%d", mode, receipts, batch.Dropped)
				}
			}
		})
	}
}

func BenchmarkInspectionLiveShrink(b *testing.B) {
	for _, state := range []string{"empty", "one", "closed"} {
		for _, reuse := range []bool{false, true} {
			mode := "detached"
			if reuse {
				mode = "reuse"
			}
			b.Run(state+"/"+mode, func(b *testing.B) {
				s := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{}))
				b.Cleanup(s.close)
				if state == "one" {
					s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
				}
				if state == "closed" {
					s.close()
				}
				var reader fs.FlowInspection = s
				storage := make([]fs.FlowRecord, 0, 50000)
				read := func() {
					var snapshot fs.LiveSnapshot
					var err error
					if reuse {
						snapshot, err = reader.ReadLiveInto(storage)
					} else {
						snapshot, err = s.ReadLiveInto(nil)
					}
					if (err != nil) != (state == "closed") {
						b.Fatalf("unexpected error: %v", err)
					}
					if err == nil && reuse {
						storage = snapshot.Rows
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					read()
				}
			})
		}
	}
}

func BenchmarkInspectionLiveRead(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		name := "detached"
		if reuse {
			name = "reuse"
		}
		b.Run(name, func(b *testing.B) {
			s := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{MaxLive: 50000}))
			b.Cleanup(s.close)
			for range 50000 {
				s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
			}
			var reader fs.FlowInspection = s
			var rows []fs.FlowRecord
			if reuse {
				rows = make([]fs.FlowRecord, 0, 50000)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var snapshot fs.LiveSnapshot
				var err error
				if reuse {
					snapshot, err = reader.ReadLiveInto(rows)
					rows = snapshot.Rows
				} else {
					snapshot, err = s.ReadLiveInto(nil)
				}
				if err != nil || len(snapshot.Rows) != 50000 {
					b.Fatalf("snapshot len=%d err=%v", len(snapshot.Rows), err)
				}
			}
		})
	}
}

// Measure the first read after a peak inventory, separately from steady empty
// reads. Preparing prior caller rows is outside the timed operation.
func BenchmarkInspectionLiveFirstShrink(b *testing.B) {
	for _, live := range []int{0, 1} {
		b.Run(string(rune('0'+live)), func(b *testing.B) {
			s := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{}))
			if live == 1 {
				s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
			}
			storage := make([]fs.FlowRecord, 50000)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				b.StopTimer()
				for i := range storage {
					storage[i].Ref.ID = 1
				}
				b.StartTimer()
				page, err := s.ReadLiveInto(storage)
				if err != nil || len(page.Rows) != live {
					b.Fatalf("first shrink: %d %v", len(page.Rows), err)
				}
			}
		})
	}
}

// Report post-GC live heap while only late UDP legs retain ended roots.
// The measurement deliberately has no platform-dependent byte assertion.
func TestInspectionLateLegRetainedHeap(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1, MaxTerminals: 1})
	const count = 100000
	legs := make([]fs.Exchange, count)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range legs {
		root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { return nil })
		legs[i] = root.NewLeg()
		legs[i].Route(fs.OutboundRef{Tag: "late"})
		root.Finish()
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("late legs=%d retained heap delta=%d bytes, %.2f bytes/leg", count, int64(after.HeapAlloc)-int64(before.HeapAlloc), float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/count)
	for _, leg := range legs {
		leg.AddDownlink(1)
		leg.Finish()
	}
	totals, _ := s.ReadTotals()
	if findTotal(t, totals.Rows, "late", fs.TrafficOriginUser).Downlink != count {
		t.Fatal("late totals lost")
	}
	runtime.KeepAlive(legs)
}

func TestInspectionFinishRetriesRegistration(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
	first := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	waiting := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	waiting.AddUplink(7)
	waiting.AddSelectedUplink(7)
	first.Finish()
	waiting.Finish()
	terminals, _ := s.ReadTerminals()
	if len(terminals.Rows) != 2 || waiting.Ref().ID == 0 || terminals.Rows[1].Flow.Uplink != 7 {
		t.Fatalf("final binding opportunity lost: %+v", terminals)
	}
}

func TestInspectionFinishRootLegRace(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	root := s.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	leg := root.NewLeg().(*inspectionExchange)
	var workers sync.WaitGroup
	workers.Go(func() { root.Finish() })
	workers.Go(func() { leg.AddUplink(3); leg.Finish() })
	workers.Wait()
	terminal, _ := s.ReadTerminals()
	totals, _ := s.ReadTotals()
	if len(terminal.Rows) != 1 || totals.User.Uplink != 3 || len(totals.Rows) != 0 {
		t.Fatalf("root/leg completion lost facts: %+v %+v", terminal, totals)
	}
}

func TestInspectionReusableLiveOwnership(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	var reader fs.FlowInspection = s
	initial, err := s.ReadLiveInto(nil)
	if err != nil || initial.Rows == nil || len(initial.Rows) != 0 {
		t.Fatal("ordinary empty snapshot changed")
	}
	storage := make([]fs.FlowRecord, 0, 4)
	stale := storage[:cap(storage)]
	for i := range stale {
		stale[i].Outbound.Tag = "stale"
	}
	flow := s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.AddUplink(1)
	flow.AddSelectedUplink(1)
	snapshot, err := reader.ReadLiveInto(stale)
	if err != nil || len(snapshot.Rows) != 1 || &snapshot.Rows[0] != &stale[0] || snapshot.Rows[0].Uplink != 1 {
		t.Fatalf("reuse: %+v %v", snapshot, err)
	}
	detached, _ := s.ReadLiveInto(nil)
	flow.AddUplink(2)
	flow.AddSelectedUplink(2)
	snapshot, err = reader.ReadLiveInto(snapshot.Rows)
	if err != nil || snapshot.Rows[0].Uplink != 3 || detached.Rows[0].Uplink != 1 {
		t.Fatal("freshness or detached snapshot independence lost")
	}
	flow.Finish()
	empty, err := reader.ReadLiveInto(snapshot.Rows)
	if err != nil || len(empty.Rows) != 0 || cap(empty.Rows) != 4 {
		t.Fatalf("shrinking inventory: %+v %v", empty, err)
	}
	for _, row := range stale {
		if row != (fs.FlowRecord{}) {
			t.Fatal("stale backing-array tail retained a record")
		}
	}
	stale[3].Outbound.Tag = "error tail"
	s.close()
	if _, err := reader.ReadLiveInto(stale); err == nil || stale[3] != (fs.FlowRecord{}) {
		t.Fatal("closed read did not clear caller storage and fail")
	}
}

func TestInspectionReusableLiveGrowthAndIndependentReaders(t *testing.T) {
	s := testInspectionStore(t, fs.ObservationOptions{})
	var reader fs.FlowInspection = s
	flows := make([]fs.Exchange, 8)
	for i := range flows {
		flows[i] = s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	}
	old := []fs.FlowRecord{{Outbound: fs.OutboundRef{Tag: "old"}}}
	grown, err := reader.ReadLiveInto(old)
	if err != nil || len(grown.Rows) != len(flows) || old[0] != (fs.FlowRecord{}) {
		t.Fatalf("replacement: %+v %v", grown, err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 100 {
			for _, flow := range flows {
				flow.AddUplink(1)
				flow.AddSelectedUplink(1)
			}
		}
	})
	for range 4 {
		workers.Go(func() {
			var rows []fs.FlowRecord
			for range 100 {
				snapshot, err := reader.ReadLiveInto(rows)
				if err != nil || len(snapshot.Rows) != len(flows) {
					t.Error("concurrent full read lost cardinality")
					return
				}
				rows = snapshot.Rows
				rows[0].Outbound.Tag = "caller mutation"
			}
		})
	}
	workers.Wait()
	final, _ := reader.ReadLiveInto(grown.Rows)
	for _, row := range final.Rows {
		if row.Uplink != 100 || row.Outbound.Tag != "" {
			t.Fatalf("caller mutation or stale bytes: %+v", row)
		}
	}
}

func TestInspectionReusableLiveLargeShrink(t *testing.T) {
	const count = 50000
	s := testInspectionStore(t, fs.ObservationOptions{MaxLive: count})
	var reader fs.FlowInspection = s
	flows := make([]fs.Exchange, count)
	for i := range flows {
		flows[i] = s.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	}
	first, err := reader.ReadLiveInto(nil)
	if err != nil || len(first.Rows) != count {
		t.Fatalf("initial inventory: %d %v", len(first.Rows), err)
	}
	for _, flow := range flows[1:] {
		flow.Finish()
	}
	one, err := reader.ReadLiveInto(first.Rows)
	if err != nil || len(one.Rows) != 1 || &one.Rows[0] != &first.Rows[0] {
		t.Fatalf("large shrink: %d %v", len(one.Rows), err)
	}
	for _, row := range first.Rows[1:] {
		if row != (fs.FlowRecord{}) {
			t.Fatal("retired large-inventory row retained")
		}
	}
	flows[0].Finish()
	empty, err := reader.ReadLiveInto(one.Rows)
	if err != nil || len(empty.Rows) != 0 || cap(empty.Rows) != cap(first.Rows) {
		t.Fatalf("empty inventory: %+v %v", empty, err)
	}
	if first.Rows[0] != (fs.FlowRecord{}) {
		t.Fatal("last retired row retained")
	}
	again, err := reader.ReadLiveInto(empty.Rows)
	if err != nil || len(again.Rows) != 0 || cap(again.Rows) != cap(empty.Rows) {
		t.Fatalf("recurring empty read: %+v %v", again, err)
	}
}
