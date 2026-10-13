package stats

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

// Large logical ownership tables exercise the tracker itself, not physical
// socket capacity. Network forwarding/fast paths have separate core tests.
func TestInspectionLargeTableConcurrentUpdatesAndControl(t *testing.T) {
	const live = 50000
	store := testInspectionStore(t, fs.ObservationOptions{MaxLive: live})
	flows := make([]fs.Exchange, live)
	refs := make([]fs.FlowRef, live)
	stops := make([]atomic.Uint32, live)
	for i := range flows {
		index := i
		flows[i] = store.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { stops[index].Add(1); return nil })
		flows[i].Route(fs.OutboundRef{Tag: "large"})
		refs[i] = flows[i].Ref()
		if refs[i].ID == 0 {
			t.Fatal("large table silently lost admission")
		}
	}
	const workers, iterations = 6, 10000
	var updates sync.WaitGroup
	var entered sync.WaitGroup
	var readDone atomic.Bool
	var credited atomic.Uint64
	updates.Add(workers)
	entered.Add(workers)
	defer func() { readDone.Store(true); updates.Wait() }()
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer updates.Done()
			var count uint64
			for i := 0; i < iterations || !readDone.Load(); i++ {
				flow := flows[(worker*iterations+i)%live]
				flow.AddUplink(1)
				flow.AddSelectedUplink(1)
				flow.AddDownlink(2)
				count++
				if i == 0 {
					entered.Done()
				}
			}
			credited.Add(count)
		}(worker)
	}
	entered.Wait()
	var rows []fs.FlowRecord
	for i := 0; i < 10; i++ {
		page, err := store.ReadLiveInto(rows)
		rows = page.Rows
		if err != nil || len(page.Rows) != live {
			t.Fatalf("large live snapshot: %d %v", len(page.Rows), err)
		}
		if _, err := store.ReadTotals(); err != nil {
			t.Fatal(err)
		}
	}
	readDone.Store(true)
	updates.Wait()
	totals, err := store.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	var up, down uint64
	for _, row := range totals.Rows {
		up += row.Uplink
		down += row.Downlink
	}
	if up != credited.Load() || down != 2*credited.Load() {
		t.Fatalf("concurrent credit lost: %d/%d", up, down)
	}
	outcomes, err := store.CloseFlows(context.Background(), refs[:live/2])
	if err != nil || len(outcomes) != live/2 {
		t.Fatalf("large control: %v", err)
	}
	for i, outcome := range outcomes {
		if outcome != nil || stops[i].Load() != 1 {
			t.Fatalf("close %d: %v calls=%d", i, outcome, stops[i].Load())
		}
	}
	page, err := store.ReadLiveInto(rows)
	if err != nil || len(page.Rows) != live/2 {
		t.Fatalf("sibling table: %d %v", len(page.Rows), err)
	}
	for i := live / 2; i < live; i++ {
		if stops[i].Load() != 0 {
			t.Fatal("control stopped a sibling")
		}
		flows[i].Finish()
	}
}

func BenchmarkInspectionLargeTablePolling(b *testing.B) {
	for _, count := range []int{256, 2000, 10000, 50000} {
		b.Run(fmt.Sprintf("live=%d", count), func(b *testing.B) {
			store := newInspectionStore(fs.RuntimeID{}, normalizeObservationOptions(fs.ObservationOptions{MaxLive: uint32(count)}))
			b.Cleanup(store.close)
			for i := 0; i < count; i++ {
				flow := store.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
				flow.Route(fs.OutboundRef{Tag: "polling"})
			}
			page, err := store.ReadLiveInto(nil)
			if err != nil {
				b.Fatal(err)
			}
			rows := page.Rows
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				page, err := store.ReadLiveInto(rows)
				if err != nil {
					b.Fatal(err)
				}
				rows = page.Rows
				if _, err := store.ReadTotals(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestInspectionHighChurnIdentityAndBoundedRetention(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{MaxLive: 1})
	var previous uint64
	start := time.Now()
	for i := 0; i < 100000; i++ {
		flow := store.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		flow.Route(fs.OutboundRef{Tag: "churn"})
		id := flow.Ref().ID
		if id <= previous {
			t.Fatal("churn reused identity")
		}
		previous = id
		flow.AddUplink(1)
		flow.AddSelectedUplink(1)
		flow.Finish()
	}
	live, err := store.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("churn retained live exchanges: %+v %v", live, err)
	}
	totals, err := store.ReadTotals()
	if err != nil || totals.User.Uplink != 100000 {
		t.Fatalf("churn USER bytes: %+v %v", totals, err)
	}

	t.Logf("100000 logical register/route/credit/finish operations: %s; no physical-connection rate claim", time.Since(start))
}

type acceptanceStopTarget struct {
	calls   atomic.Int32
	padding [1024]byte
	pointer *int
}

func acceptanceOwnedExchange(store *inspectionStore, carrier bool) (fs.Exchange, weak.Pointer[acceptanceStopTarget]) {
	target := &acceptanceStopTarget{pointer: new(int)}
	ref := weak.Make(target)
	stop := func() error { target.calls.Add(1); return nil }
	if carrier {
		return store.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, stop), ref
	}
	exchange := store.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, stop)
	exchange.Route(fs.OutboundRef{Tag: "direct"})
	return exchange, ref
}

func acceptanceCollected(ref weak.Pointer[acceptanceStopTarget]) bool {
	for i := 0; i < 20; i++ {
		runtime.GC()
		if ref.Value() == nil {
			return true
		}
	}
	return false
}

func TestInspectionAcceptanceReleasedStopReferences(t *testing.T) {
	t.Run("ended-with-late-receipt", func(t *testing.T) {
		store := testInspectionStore(t, fs.ObservationOptions{})
		exchange, ref := acceptanceOwnedExchange(store, false)
		exchange.AddDownlink(3)
		exchange.Finish()
		if !acceptanceCollected(ref) {
			t.Error("ended exchange retained native stop target")
		}
		exchange.AddDownlink(5)
		totals, err := store.ReadTotals()
		if err != nil {
			t.Fatal(err)
		}
		if row := findTotal(t, totals.Rows, "direct", fs.TrafficOriginUser); row.Downlink != 8 {
			t.Fatalf("late total: %+v", row)
		}

		runtime.KeepAlive(exchange)
		runtime.KeepAlive(store)
	})
	t.Run("shutdown-drops-store-owned-target", func(t *testing.T) {
		store := testInspectionStore(t, fs.ObservationOptions{})
		_, ref := acceptanceOwnedExchange(store, false)
		store.close()
		if !acceptanceCollected(ref) {
			t.Error("closed store retained native stop target")
		}
		runtime.KeepAlive(store)
	})
	t.Run("excluded-root-with-late-receipt", func(t *testing.T) {
		store := testInspectionStore(t, fs.ObservationOptions{})
		exchange, ref := acceptanceOwnedExchange(store, true)
		if !exchange.ExcludeCarrier() {
			t.Fatal("prepared carrier was registered")
		}
		exchange.Finish()
		if !acceptanceCollected(ref) {
			t.Error("excluded ended root retained native stop target")
		}
		runtime.KeepAlive(exchange)
		runtime.KeepAlive(store)
	})
	t.Run("leg-end-keeps-root-stop", func(t *testing.T) {
		store := testInspectionStore(t, fs.ObservationOptions{})
		var stopped atomic.Int32
		root := store.Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { stopped.Add(1); return nil })
		leg := root.NewLeg()
		leg.Route(fs.OutboundRef{Tag: "tag-1"})
		leg.Finish()
		outcomes, err := store.CloseFlows(context.Background(), []fs.FlowRef{root.Ref()})
		if err != nil || outcomes[0] != nil || stopped.Load() != 1 {
			t.Fatalf("leg ending removed root stop: %+v %v", outcomes, err)
		}
	})
}

func TestInspectionAcceptanceStopRequestedIsVisible(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{})
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(proceed) })
	e := store.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { close(entered); <-proceed; return nil })
	done := make(chan struct{})
	go func() { defer close(done); _, _ = store.CloseFlows(context.Background(), []fs.FlowRef{e.Ref()}) }()
	<-entered
	live, err := store.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || e.NewLeg() != nil {
		t.Errorf("stop in progress: %+v %v", live, err)
	}
	once.Do(func() { close(proceed) })
	<-done
}

func acceptanceFillMetadata(store *inspectionStore, tagIndex uint64, index int) *inspectionExchange {
	domain := func(label string) xnet.Destination {
		return xnet.UDPDestination(xnet.DomainAddress(fmt.Sprintf("%08d-%s-", index, label)+strings.Repeat("d", 300)), 53)
	}
	e := store.Begin(xnet.Network_UDP, fs.TrafficOriginUser, domain("source"), domain("initial"), nil).(*inspectionExchange)
	for i := 0; i < 4; i++ {
		e.Route(fs.OutboundRef{Tag: fmt.Sprintf("%08d", tagIndex) + strings.Repeat("t", 292)})
	}
	for i := 0; i < 8; i++ {
		e.PacketDestination(domain(fmt.Sprintf("packet-%d", i)))
	}
	return e
}

// This records one host's retained heap, not an Android budget or a process bound.
func TestInspectionAcceptanceDefaultCapRetainedHeap(t *testing.T) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	store := testInspectionStore(t, fs.ObservationOptions{})
	if store.limits != defaultObservationOptions {
		t.Fatalf("effective defaults: %+v", store.limits)
	}
	for i := 0; i < int(store.limits.MaxBuckets); i++ {
		e := acceptanceFillMetadata(store, uint64(i+1), i)
		if len(e.record.Outbound.Tag) != 300 || !e.record.Destination.IsValid() {
			t.Fatalf("latest bounded metadata missing: %+v", e.record)
		}
		e.Finish()
	}
	for i := 0; i < int(store.limits.MaxLive); i++ {
		acceptanceFillMetadata(store, uint64(i+1), i+int(store.limits.MaxBuckets))
	}
	if len(store.live) != 256 || len(store.buckets) != 1024 {
		t.Fatalf("store sizes: %d %d", len(store.live), len(store.buckets))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("default-cap store retained HeapAlloc delta=%d bytes; live=%d attributed-buckets=%d; caller copies/native connections/DNS caches excluded", int64(after.HeapAlloc)-int64(before.HeapAlloc), len(store.live), len(store.buckets))
	runtime.KeepAlive(store)
}
