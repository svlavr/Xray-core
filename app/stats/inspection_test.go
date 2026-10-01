package stats

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func testInspectionStore(t *testing.T, options featurestats.ObservationOptions) *inspectionStore {
	t.Helper()
	return newInspectionStore(featurestats.RuntimeID{1}, normalizeObservationOptions(options))
}

func TestInspectionConcurrentRetirementRejectsNewFacts(t *testing.T) {
	manager := new(Manager)
	view, err := manager.EnableInspection(featurestats.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	store := manager.Observation()
	start := make(chan struct{})
	var workers sync.WaitGroup
	var admitted sync.WaitGroup
	admitted.Add(4)
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			flow := store.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { return nil })
			admitted.Done()
			<-start
			for j := 0; j < 32; j++ {
				if j != 0 {
					flow = store.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { return nil })
				}
				if flow != nil {
					flow.Route(featurestats.OutboundRef{Serial: 1})
					flow.BindRoute()
					flow.AddUplink(1)
					flow.Finish()
				}
				_, _ = view.ReadLive()
				_, _ = view.ReadTotals()
				_, _ = view.ReadTerminals()
			}
		}()
	}
	admitted.Wait()
	close(start)
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	_ = manager.Close()
	if manager.Observation() != nil || store.Begin(xnet.Network_UDP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil) != nil {
		t.Fatal("closed manager or captured store admitted new facts")
	}
	if _, err := view.ReadLive(); err == nil {
		t.Fatal("closed live view accepted")
	}
	if _, err := view.ReadTotals(); err == nil {
		t.Fatal("closed totals accepted")
	}
	if _, err := view.ReadTerminals(); err == nil {
		t.Fatal("closed ended view accepted")
	}
	if _, err := view.CloseFlows(context.Background(), nil); err == nil {
		t.Fatal("closed control accepted")
	}
	if _, err := manager.EnableInspection(featurestats.ObservationOptions{}); err == nil {
		t.Fatal("closed manager accepted a second enablement")
	}
}

func TestInspectionEnablement(t *testing.T) {
	manager, err := NewManager(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Observation() != nil {
		t.Fatal("disabled manager exposed an admission store")
	}
	inspection, err := manager.EnableInspection(featurestats.ObservationOptions{MaxLive: 1})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Runtime() == (featurestats.RuntimeID{}) || manager.Observation() == nil {
		t.Fatal("enabled inspection did not expose a nonzero runtime and store")
	}
	if _, err := manager.EnableInspection(featurestats.ObservationOptions{}); err == nil {
		t.Fatalf("second enable error = %v", err)
	}

	started, err := NewManager(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := started.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := started.EnableInspection(featurestats.ObservationOptions{}); err == nil {
		t.Fatalf("post-start enable error = %v", err)
	}
	if got := normalizeObservationOptions(featurestats.ObservationOptions{MaxLive: defaultObservationOptions.MaxLive + 1}); got.MaxLive != defaultObservationOptions.MaxLive+1 || got.MaxTerminals != defaultObservationOptions.MaxTerminals || got.MaxBuckets != defaultObservationOptions.MaxBuckets {
		t.Fatalf("configured capacity was rewritten: %+v", got)
	}
}

func TestInspectionLifecycleTotalsClonesAndOwnerEnd(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 2, MaxTerminals: 2, MaxBuckets: 2})
	longDomain := strings.Repeat("a", 300)
	exchange := store.Begin(
		xnet.Network_TCP,
		featurestats.TrafficOriginUser,
		xnet.TCPDestination(xnet.DomainAddress(longDomain), 1000),
		xnet.TCPDestination(xnet.DomainAddress("destination.example"), 443),
		nil,
	)
	if exchange.Ref().ID == 0 {
		t.Fatal("tracked exchange has no reference")
	}
	exchange.AddUplink(5)
	exchange.Route(featurestats.OutboundRef{
		Serial: 7,
		Tag:    strings.Repeat("t", 300),
	})
	exchange.BindRoute()
	exchange.Effective(xnet.TCPDestination(xnet.DomainAddress("effective.example"), 443))
	exchange.AddUplink(2)
	exchange.AddDownlink(3)

	live, err := store.ReadLive()
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Rows) != 1 || live.Rows[0].Uplink != 7 || live.Rows[0].Downlink != 3 {
		t.Fatalf("unexpected live rows: %+v", live.Rows)
	}
	if live.Rows[0].Source.Address.Domain() != longDomain || live.Rows[0].Outbound.Tag != strings.Repeat("t", 300) {
		t.Fatalf("native metadata was rewritten: %+v", live.Rows[0])
	}
	live.Rows[0].Outbound.Tag = "caller mutation"
	again, err := store.ReadLive()
	if err != nil {
		t.Fatal(err)
	}
	if again.Rows[0].Outbound.Tag != strings.Repeat("t", 300) {
		t.Fatal("live snapshot retained caller mutation")
	}

	exchange.Finish()
	page, err := store.ReadTerminals()
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Flow.Downlink != 3 {
		t.Fatalf("owner-end snapshot: %+v", page)
	}
	exchange.AddDownlink(2)

	page, err = store.ReadTerminals()
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Flow.Downlink != 3 {
		t.Fatalf("late result mutated history: %+v", page)
	}
	page.Rows[0].Flow.Outbound.Tag = "caller mutation"
	pageAgain, err := store.ReadTerminals()
	if err != nil {
		t.Fatal(err)
	}
	if pageAgain.Rows[0].Flow.Outbound.Tag != strings.Repeat("t", 300) {
		t.Fatal("terminal page retained caller mutation")
	}

	totals, err := store.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	row := findTotal(t, totals.Rows, 7, featurestats.TrafficOriginUser)
	if row.Uplink != 7 || row.Downlink != 5 {
		t.Fatalf("unexpected attributed totals: %+v", row)
	}
}

func TestInspectionCapacityRejectedAttributionAndBoundedHistory(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 1, MaxTerminals: 2, MaxBuckets: 1})
	first := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	first.Route(featurestats.OutboundRef{Serial: 1, Tag: "one"})
	first.BindRoute()
	first.AddUplink(1)

	overflow := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	if overflow.Ref() != (featurestats.FlowRef{}) {
		t.Fatalf("capacity-overflow exchange unexpectedly addressable: %+v", overflow.Ref())
	}
	overflow.Route(featurestats.OutboundRef{Tag: "attempted"})
	overflow.BindRoute()
	overflow.AddUplink(3)
	overflow.Finish()

	totals, err := store.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	unassigned := findTotal(t, totals.Rows, 0, featurestats.TrafficOriginUser)
	if unassigned.Uplink != 3 {
		t.Fatalf("rejected selection did not retain known unassigned bytes: %+v", unassigned)
	}
	first.Finish()

	var retained []featurestats.FlowRef
	for i := 0; i < 2; i++ {
		exchange := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUnknown, xnet.Destination{}, xnet.Destination{}, nil)
		retained = append(retained, exchange.Ref())

		exchange.Finish()
	}
	page, err := store.ReadTerminals()
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.Rows[0].Flow.Ref != retained[0] || page.Rows[1].Flow.Ref != retained[1] {
		t.Fatalf("bounded oldest-first history = %+v", page)
	}
}

func TestInspectionCloseOutcomesAndCallbackOutsideLocks(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 4, MaxTerminals: 4})
	entered, release := make(chan struct{}), make(chan struct{})
	var exchange featurestats.Exchange
	exchange = store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error {
		if _, err := store.ReadLive(); err != nil {
			return err
		}
		close(entered)
		<-release

		return nil
	})
	type closeResult struct {
		outcomes []error
		err      error
	}
	done := make(chan closeResult, 1)
	go func() {
		outcomes, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
		done <- closeResult{outcomes: outcomes, err: err}
	}()
	<-entered
	outcomes, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
	if err != nil || outcomes[0] != nil {
		t.Fatalf("repeated close = %+v, %v", outcomes, err)
	}
	close(release)
	first := <-done
	if first.err != nil || first.outcomes[0] != nil {
		t.Fatalf("first close = %+v, %v", first.outcomes, first.err)
	}
	outcomes, err = store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
	if err != nil || outcomes[0] != nil {
		t.Fatalf("ended close = %+v, %v", outcomes, err)
	}

	unsupported := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	outcomes, err = store.CloseFlows(context.Background(), []featurestats.FlowRef{unsupported.Ref()})
	if err != nil || !errors.Is(outcomes[0], errors.ErrUnsupported) {
		t.Fatalf("unsupported close = %+v, %v", outcomes, err)
	}
	stale := unsupported.Ref()
	stale.Runtime[1] = 9
	outcomes, err = store.CloseFlows(context.Background(), []featurestats.FlowRef{stale})
	if err != nil || outcomes[0] != nil {
		t.Fatalf("stale close = %+v, %v", outcomes, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	outcomes, err = store.CloseFlows(canceled, []featurestats.FlowRef{unsupported.Ref()})
	if err != nil || !errors.Is(outcomes[0], context.Canceled) {
		t.Fatalf("canceled close = %+v, %v", outcomes, err)
	}
	batch, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{{}, {}, {}})
	if err != nil || len(batch) != 3 || batch[0] != nil || batch[1] != nil || batch[2] != nil {
		t.Fatalf("idempotent batch close: %+v %v", batch, err)
	}
	unsupported.Finish()
}

func TestInspectionConcurrentSnapshotAndLateTotals(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 1, MaxTerminals: 1, MaxBuckets: 1})
	exchange := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	exchange.Route(featurestats.OutboundRef{Serial: 1})
	exchange.BindRoute()

	const workers = 8
	const additions = 500
	release := make(chan struct{})
	var wg sync.WaitGroup
	var done atomic.Uint32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			for j := 0; j < additions; j++ {
				exchange.AddUplink(1)
			}
			done.Add(1)
		}()
	}
	exchange.Finish()
	if page, err := store.ReadTerminals(); err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 {
		t.Fatalf("owner-end snapshot = %+v, %v", page, err)
	}
	close(release)
	for done.Load() != workers {
		if live, err := store.ReadLive(); err != nil || len(live.Rows) != 0 {
			t.Fatal(err)
		}
		if _, err := store.ReadTotals(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	page, err := store.ReadTerminals()
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 {
		t.Fatalf("concurrent terminal = %+v", page)
	}
	totals, _ := store.ReadTotals()
	if got := findTotal(t, totals.Rows, 1, featurestats.TrafficOriginUser).Uplink; got != workers*additions {
		t.Fatalf("late totals = %d", got)
	}
}

func findTotal(t *testing.T, rows []featurestats.TotalRecord, serial uint64, origin featurestats.TrafficOrigin) featurestats.TotalRecord {
	t.Helper()
	for _, row := range rows {
		if row.Outbound.Serial == serial && row.Origin == origin {
			return row
		}
	}
	t.Fatalf("missing total serial=%d origin=%d", serial, origin)
	return featurestats.TotalRecord{}
}

func TestInspectionStopPublishesAndPreservesLateTotals(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	exchange := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { return nil })

	out, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
	if err != nil || out[0] != nil {
		t.Fatalf("close: %+v %v", out, err)
	}

	exchange.Finish()
	page, _ := store.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 {
		t.Fatalf("close snapshot: %+v", page)
	}
	exchange.AddUplink(3)
	page, _ = store.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 {
		t.Fatalf("owner completion: %+v", page)
	}
	totals, _ := store.ReadTotals()
	if got := findTotal(t, totals.Rows, 0, featurestats.TrafficOriginUser).Uplink; got != 3 {
		t.Fatalf("late close totals: %d", got)
	}
}

func TestInspectionCloseFailureAndCanceledSuffix(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	nativeFailure := errors.New("native failure")
	first := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { cancel(); return nativeFailure })
	var secondCalled bool
	second := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { secondCalled = true; return nil })
	out, err := store.CloseFlows(ctx, []featurestats.FlowRef{first.Ref(), second.Ref()})
	if err != nil || len(out) != 2 || !errors.Is(out[0], nativeFailure) || !errors.Is(out[1], context.Canceled) || secondCalled {
		t.Fatalf("partial close: %+v %v", out, err)
	}
	first.Finish()
	second.Finish()
}

func TestInspectionRouteCaptureRequiresOwnerBinding(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	flow := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.AddUplink(9)
	flow.Route(featurestats.OutboundRef{Serial: 1, Tag: "forward"})
	live, _ := store.ReadLive()
	if live.Rows[0].Outbound.Serial != 1 {
		t.Fatal("selection was not visible before owner binding")
	}
	totals, _ := store.ReadTotals()
	if len(totals.Rows) != 4 {
		t.Fatal("selection created a bucket")
	}
	flow.Route(featurestats.OutboundRef{Serial: 2, Tag: "consumer"})
	flow.BindRoute()
	flow.AddUplink(1)
	flow.Finish()
	page, _ := store.ReadTerminals()
	row := page.Rows[0].Flow
	if row.Outbound.Serial != 2 || row.Uplink != 10 {
		t.Fatalf("selected route and bytes: %+v", row)
	}
	totals, _ = store.ReadTotals()
	if len(totals.Rows) != 5 || findTotal(t, totals.Rows, 2, featurestats.TrafficOriginUser).Uplink != 10 {
		t.Fatalf("consuming totals: %+v", totals)
	}
}

func TestInspectionIndependentSample(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	cell := &store.unassigned[int(featurestats.TrafficOriginUser)]
	cell.uplink.Add(1)
	snapshot, err := store.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	fact := findTotal(t, snapshot.Rows, 0, featurestats.TrafficOriginUser).Uplink
	if fact != 1 || snapshot.At < 0 {
		t.Fatalf("independent sample: %+v", snapshot)
	}
}

func TestInspectionTerminalStorageGrowsWithinLimit(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxTerminals: 3})
	if cap(store.terminals) != 0 {
		t.Fatal("terminal storage allocated before first ending")
	}
	for i := 0; i < 8; i++ {
		flow := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		flow.Finish()
		if cap(store.terminals) > 3 || len(store.terminals) != min(i+1, 3) {
			t.Fatalf("terminal storage len=%d cap=%d after ending %d", len(store.terminals), cap(store.terminals), i+1)
		}
	}
}

func TestInspectionKnownDownlink(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	flow := store.Begin(xnet.Network_TCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.AddDownlink(3)
	flow.Route(featurestats.OutboundRef{Serial: 1})
	flow.BindRoute()
	flow.AddDownlink(4)

	flow.Finish()
	page, err := store.ReadTerminals()
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	final := page.Rows[0].Flow.Downlink
	if final != 7 {
		t.Fatalf("known facts: %+v", final)
	}
	totals, err := store.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	if got := findTotal(t, totals.Rows, 1, featurestats.TrafficOriginUser).Downlink; got != 7 {
		t.Fatalf("known totals: %+v", got)
	}
}
