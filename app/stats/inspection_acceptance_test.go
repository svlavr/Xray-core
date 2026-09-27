package stats

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"weak"

	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

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
	exchange := store.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, stop)
	exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1, Tag: "direct"}})
	exchange.BindRoute()
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
		if row := findTotal(t, totals.Rows, 1, fs.TrafficOriginUser); row.Downlink.Known != 8 {
			t.Fatalf("late total: %+v", row)
		}
		terminal, err := store.ReadTerminals()
		if err != nil || len(terminal.Rows) != 1 || terminal.Rows[0].Flow.Downlink.Known != 3 {
			t.Fatalf("terminal changed: %+v %v", terminal, err)
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
		root := store.Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { stopped.Add(1); return nil })
		leg := root.NewLeg()
		leg.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1}})
		leg.BindRoute()
		leg.Finish()
		outcomes, err := store.CloseFlows(context.Background(), []fs.FlowRef{root.Ref()})
		if err != nil || outcomes[0].Code != fs.CloseCodeAccepted || stopped.Load() != 1 {
			t.Fatalf("leg ending removed root stop: %+v %v", outcomes, err)
		}
	})
}

func TestInspectionAcceptanceIndependentSlowReaders(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{MaxTerminals: 2})
	add := func(n int) {
		e := store.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		e.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1}, RuleTag: "original"})
		e.BindRoute()
		e.AddUplink(uint64(n))
		e.Finish()
	}
	add(1)
	slow, err := store.ReadTerminals()
	if err != nil {
		t.Fatal(err)
	}
	savedRef := slow.Rows[0].Flow.Ref
	var wg sync.WaitGroup
	for reader := 0; reader < 3; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				page, err := store.ReadTerminals()
				if err != nil {
					t.Error(err)
					return
				}
				for j := range page.Rows {
					if page.Rows[j].Flow.SelectedRoute.RuleTag != "original" {
						t.Error("another reader mutated store")
					}
					page.Rows[j].Flow.SelectedRoute.RuleTag = "reader mutation"
				}
				_, _ = store.ReadLive()
				_, _ = store.ReadTotals()
			}
		}()
	}
	for i := 2; i <= 101; i++ {
		add(i)
	}
	wg.Wait()
	if len(slow.Rows) != 1 || slow.Rows[0].Flow.Ref != savedRef || slow.Rows[0].Flow.Uplink.Known != 1 || slow.Rows[0].Flow.SelectedRoute.RuleTag != "original" {
		t.Fatal("retained reader snapshot changed")
	}
	fresh, err := store.ReadTerminals()
	if err != nil || len(fresh.Rows) != 2 {
		t.Fatalf("fresh bounded view: %+v %v", fresh, err)
	}
	outcomes, err := store.CloseFlows(context.Background(), []fs.FlowRef{savedRef, fresh.Rows[0].Flow.Ref})
	if err != nil || outcomes[0].Code != fs.CloseCodeNoAction || outcomes[1].Code != fs.CloseCodeNoAction {
		t.Fatalf("retention close outcomes: %+v %v", outcomes, err)
	}
}

func TestInspectionAcceptanceExhaustionPreservesTotals(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{})
	store.nextID = math.MaxUint64
	for i := 0; i < 2; i++ {
		e := store.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		if e == nil || e.Ref() != (fs.FlowRef{}) {
			t.Fatal("exhaustion wrapped or rejected native receipt")
		}
		e.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1}})
		e.BindRoute()
		e.AddUplink(7)
		e.Finish()
	}
	totals, err := store.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	if store.nextID != math.MaxUint64 {
		t.Fatalf("exhaustion wrapped ID: %d", store.nextID)
	}
	if row := findTotal(t, totals.Rows, 1, fs.TrafficOriginUser); row.Uplink.Known != 14 {
		t.Fatalf("exhaustion lost native byte facts: %+v", row)
	}
}

func TestInspectionAcceptanceStopRequestedIsVisible(t *testing.T) {
	store := testInspectionStore(t, fs.ObservationOptions{})
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(proceed) })
	e := store.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { close(entered); <-proceed; return nil })
	done := make(chan struct{})
	go func() { defer close(done); _, _ = store.CloseFlows(context.Background(), []fs.FlowRef{e.Ref()}) }()
	<-entered
	live, err := store.ReadLive()
	if err != nil || len(live.Rows) != 1 || live.Rows[0].State != fs.FlowStateStopRequested {
		t.Errorf("stop in progress: %+v %v", live, err)
	}
	once.Do(func() { close(proceed) })
	<-done
}

func acceptanceFillMetadata(store *inspectionStore, serial uint64, index int) *inspectionExchange {
	domain := func(label string) xnet.Destination {
		return xnet.UDPDestination(xnet.DomainAddress(fmt.Sprintf("%08d-%s-", index, label)+strings.Repeat("d", maxMetadataString)), 53)
	}
	e := store.Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, domain("source"), domain("initial"), nil).(*inspectionExchange)
	for i := 0; i < 4; i++ {
		e.Route(fs.RouteStep{Selection: fs.SelectionRule, Outbound: fs.OutboundRef{Serial: serial, Tag: strings.Repeat("t", maxMetadataString)}, RuleTag: strings.Repeat("r", maxMetadataString), SelectedTarget: domain("selected")})
		e.Effective(domain("effective"))
	}
	e.BindRoute()
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
	for i := 0; i < int(store.limits.MaxTerminals); i++ {
		e := acceptanceFillMetadata(store, uint64(i+1), i)
		if len(e.record.SelectedRoute.Outbound.Tag) != maxMetadataString || !e.record.LatestDestination.IsValid() {
			t.Fatalf("latest bounded metadata missing: %+v", e.record)
		}
		e.Finish()
	}
	for i := 0; i < int(store.limits.MaxLive); i++ {
		acceptanceFillMetadata(store, uint64(i+1), i+int(store.limits.MaxTerminals))
	}
	if len(store.live) != 256 || len(store.terminals) != 1024 || len(store.buckets) != 1024 {
		t.Fatalf("store sizes: %d %d %d", len(store.live), len(store.terminals), len(store.buckets))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("default-cap store retained HeapAlloc delta=%d bytes; live=%d terminals=%d attributed-buckets=%d; caller copies/native connections/DNS caches excluded", int64(after.HeapAlloc)-int64(before.HeapAlloc), len(store.live), len(store.terminals), len(store.buckets))
	runtime.KeepAlive(store)
}
