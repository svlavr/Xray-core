package stats

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func testInspectionStore(t *testing.T, options featurestats.ObservationOptions) *inspectionStore {
	t.Helper()
	limits, err := normalizeObservationOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	return newInspectionStore(featurestats.RuntimeID{1}, limits)
}

func TestInspectionEnablementAndEntropy(t *testing.T) {
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
	if inspection.Info().Runtime == (featurestats.RuntimeID{}) || manager.Observation() == nil {
		t.Fatal("enabled inspection did not expose a nonzero runtime and store")
	}
	if _, err := manager.EnableInspection(featurestats.ObservationOptions{}); !errors.Is(err, featurestats.ErrInspectionAlreadyEnabled) {
		t.Fatalf("second enable error = %v", err)
	}

	started, err := NewManager(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := started.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := started.EnableInspection(featurestats.ObservationOptions{}); !errors.Is(err, featurestats.ErrInspectionTooLate) {
		t.Fatalf("post-start enable error = %v", err)
	}
	if _, err := normalizeObservationOptions(featurestats.ObservationOptions{MaxLive: defaultObservationOptions.MaxLive + 1}); !errors.Is(err, featurestats.ErrInspectionLimit) {
		t.Fatalf("oversized option error = %v", err)
	}
	if _, err := newRuntimeID(bytes.NewReader(make([]byte, 16))); !errors.Is(err, featurestats.ErrInspectionEntropy) {
		t.Fatalf("zero runtime error = %v", err)
	}
	if _, err := newRuntimeID(bytes.NewReader([]byte{1})); !errors.Is(err, featurestats.ErrInspectionEntropy) {
		t.Fatalf("short entropy error = %v", err)
	}
}

func TestInspectionLifecycleTotalsClonesAndOwnerEnd(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 2, MaxTerminals: 2, MaxBuckets: 2})
	longDomain := strings.Repeat("a", 300)
	exchange := store.Begin(
		featurestats.FlowKindTCP,
		featurestats.TrafficOriginUser,
		xnet.TCPDestination(xnet.DomainAddress(longDomain), 1000),
		xnet.TCPDestination(xnet.DomainAddress("destination.example"), 443),
		nil,
	)
	if exchange.Ref().ID == 0 {
		t.Fatal("tracked exchange has no reference")
	}
	exchange.AddUplink(5)
	exchange.Route(featurestats.RouteStep{
		Leg:       1,
		Selection: featurestats.SelectionRule,
		Outbound: featurestats.OutboundRef{
			Runtime: store.runtime,
			Serial:  7,
			Tag:     strings.Repeat("t", 300),
		},
		RuleTag:     "rule",
		RouteTarget: xnet.TCPDestination(xnet.DomainAddress("destination.example"), 443),
	})
	exchange.BindRoute()
	exchange.Effective(xnet.TCPDestination(xnet.DomainAddress("effective.example"), 443))
	exchange.AddUplink(2)
	exchange.AddDownlink(3)

	live, err := store.ReadLive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Rows) != 1 || live.Rows[0].Uplink.Known != 7 || live.Rows[0].Downlink.Known != 3 {
		t.Fatalf("unexpected live rows: %+v", live.Rows)
	}
	if !live.Rows[0].MetadataTruncated || len(live.Rows[0].Source.Address.Domain()) > maxMetadataString || len(live.Rows[0].Routes[0].Outbound.Tag) > maxMetadataString {
		t.Fatalf("metadata bounds were not applied: %+v", live.Rows[0])
	}
	live.Rows[0].Routes[0].RuleTag = "caller mutation"
	live.Rows[0].Routes = nil
	again, err := store.ReadLive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Rows[0].Routes) != 1 || again.Rows[0].Routes[0].RuleTag != "rule" {
		t.Fatal("live snapshot retained caller-owned slice state")
	}

	exchange.SetEndReason(featurestats.EndReasonEOF)
	exchange.Finish()
	page, err := store.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Reason != featurestats.EndReasonEOF || page.Rows[0].Flow.Downlink.Known != 3 {
		t.Fatalf("owner-end snapshot: %+v", page)
	}
	exchange.AddDownlink(2)
	exchange.SetEndReason(featurestats.EndReasonWriteError)
	page, err = store.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Reason != featurestats.EndReasonEOF || page.Rows[0].Flow.Downlink.Known != 3 {
		t.Fatalf("late result mutated history: %+v", page)
	}
	page.Rows[0].Flow.Routes[0].RuleTag = "caller mutation"
	pageAgain, err := store.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pageAgain.Rows[0].Flow.Routes[0].RuleTag != "rule" {
		t.Fatal("terminal page retained caller-owned slice state")
	}

	totals, err := store.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := findTotal(t, totals.Rows, 7, featurestats.TrafficOriginUser)
	if row.Uplink.Known != 7 || row.Downlink.Known != 5 {
		t.Fatalf("unexpected attributed totals: %+v", row)
	}
}

func TestInspectionCapacityRejectedAttributionAndBoundedHistory(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 1, MaxTerminals: 2, MaxBuckets: 1})
	first := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	first.Route(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Runtime: store.runtime, Serial: 1, Tag: "one"}})
	first.BindRoute()
	first.AddUplink(1)

	overflow := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	if overflow.Ref() != (featurestats.FlowRef{}) {
		t.Fatalf("capacity-overflow exchange unexpectedly addressable: %+v", overflow.Ref())
	}
	overflow.Route(featurestats.RouteStep{Selection: featurestats.SelectionRejected, Outbound: featurestats.OutboundRef{Tag: "attempted"}})
	overflow.BindRoute()
	overflow.AddUplink(3)
	overflow.Finish()

	totals, err := store.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unassigned := findTotal(t, totals.Rows, 0, featurestats.TrafficOriginUser)
	if unassigned.Uplink.Known != 3 || unassigned.Uplink.Incomplete {
		t.Fatalf("rejected selection did not retain known unassigned bytes: %+v", unassigned)
	}
	if totals.Loss.UntrackedAdmissions != 1 {
		t.Fatalf("untracked admission loss = %d", totals.Loss.UntrackedAdmissions)
	}
	first.Finish()

	var retained []featurestats.FlowRef
	for i := 0; i < 2; i++ {
		exchange := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUnknown, xnet.Destination{}, xnet.Destination{}, nil)
		retained = append(retained, exchange.Ref())
		exchange.SetEndReason(featurestats.EndReasonEOF)
		exchange.Finish()
	}
	page, err := store.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.Rows[0].Flow.Ref != retained[0] || page.Rows[1].Flow.Ref != retained[1] || page.Loss.TerminalOverwrite != 1 {
		t.Fatalf("bounded oldest-first history = %+v", page)
	}
}

func TestInspectionCloseOutcomesAndCallbackOutsideLocks(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 4, MaxTerminals: 4, MaxClose: 2})
	entered, release := make(chan struct{}), make(chan struct{})
	var exchange featurestats.Exchange
	exchange = store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error {
		if _, err := store.ReadLive(context.Background()); err != nil {
			return err
		}
		close(entered)
		<-release
		exchange.SetEndReason(featurestats.EndReasonLocalStop)
		return nil
	})
	type closeResult struct {
		outcomes []featurestats.CloseOutcome
		err      error
	}
	done := make(chan closeResult, 1)
	go func() {
		outcomes, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
		done <- closeResult{outcomes: outcomes, err: err}
	}()
	<-entered
	outcomes, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
	if err != nil || outcomes[0].Code != featurestats.CloseCodeAlreadyRequested {
		t.Fatalf("repeated close = %+v, %v", outcomes, err)
	}
	close(release)
	first := <-done
	if first.err != nil || first.outcomes[0].Code != featurestats.CloseCodeAccepted {
		t.Fatalf("first close = %+v, %v", first.outcomes, first.err)
	}
	outcomes, err = store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
	if err != nil || outcomes[0].Code != featurestats.CloseCodeAlreadyEnded {
		t.Fatalf("ended close = %+v, %v", outcomes, err)
	}

	unsupported := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	outcomes, err = store.CloseFlows(context.Background(), []featurestats.FlowRef{unsupported.Ref()})
	if err != nil || outcomes[0].Code != featurestats.CloseCodeUnsupportedOwner {
		t.Fatalf("unsupported close = %+v, %v", outcomes, err)
	}
	stale := unsupported.Ref()
	stale.Runtime[1] = 9
	outcomes, err = store.CloseFlows(context.Background(), []featurestats.FlowRef{stale})
	if err != nil || outcomes[0].Code != featurestats.CloseCodeStaleRuntime {
		t.Fatalf("stale close = %+v, %v", outcomes, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	outcomes, err = store.CloseFlows(canceled, []featurestats.FlowRef{unsupported.Ref()})
	if err != nil || outcomes[0].Code != featurestats.CloseCodeNotStartedCanceled {
		t.Fatalf("canceled close = %+v, %v", outcomes, err)
	}
	if _, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{{}, {}, {}}); !errors.Is(err, featurestats.ErrInspectionLimit) {
		t.Fatalf("oversized close error = %v", err)
	}
	unsupported.Finish()
}

func TestInspectionConcurrentSnapshotAndLateTotals(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxLive: 1, MaxTerminals: 1, MaxBuckets: 1})
	exchange := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	exchange.Route(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Runtime: store.runtime, Serial: 1}})
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
	if page, err := store.ReadTerminals(context.Background()); err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 0 {
		t.Fatalf("owner-end snapshot = %+v, %v", page, err)
	}
	close(release)
	for done.Load() != workers {
		if live, err := store.ReadLive(context.Background()); err != nil || len(live.Rows) != 0 {
			t.Fatal(err)
		}
		if _, err := store.ReadTotals(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	page, err := store.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 0 {
		t.Fatalf("concurrent terminal = %+v", page)
	}
	totals, _ := store.ReadTotals(context.Background())
	if got := findTotal(t, totals.Rows, 1, featurestats.TrafficOriginUser).Uplink.Known; got != workers*additions {
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
	exchange := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { return nil })
	exchange.SetEndReason(featurestats.EndReasonEOF)
	out, err := store.CloseFlows(context.Background(), []featurestats.FlowRef{exchange.Ref()})
	if err != nil || out[0].Code != featurestats.CloseCodeAccepted {
		t.Fatalf("close: %+v %v", out, err)
	}
	exchange.SetEndReason(featurestats.EndReasonReadError)
	exchange.Finish()
	page, _ := store.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Reason != featurestats.EndReasonLocalStop || page.Rows[0].Flow.Uplink.Known != 0 {
		t.Fatalf("close snapshot: %+v", page)
	}
	exchange.AddUplink(3)
	page, _ = store.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Reason != featurestats.EndReasonLocalStop || page.Rows[0].Flow.Uplink.Known != 0 {
		t.Fatalf("owner completion: %+v", page)
	}
	totals, _ := store.ReadTotals(context.Background())
	if got := findTotal(t, totals.Rows, 0, featurestats.TrafficOriginUser).Uplink.Known; got != 3 {
		t.Fatalf("late close totals: %d", got)
	}
}

func TestInspectionCloseFailureAndCanceledSuffix(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	first := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { cancel(); return errors.New("native failure") })
	var secondCalled bool
	second := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, func() error { secondCalled = true; return nil })
	out, err := store.CloseFlows(ctx, []featurestats.FlowRef{first.Ref(), second.Ref()})
	if err != nil || len(out) != 2 || out[0].Code != featurestats.CloseCodeFailed || out[1].Code != featurestats.CloseCodeNotStartedCanceled || secondCalled {
		t.Fatalf("partial close: %+v %v", out, err)
	}
	first.Finish()
	second.Finish()
}

func TestInspectionRouteCaptureRequiresOwnerBinding(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxRouteSteps: 1})
	flow := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.AddUplink(9)
	flow.Route(featurestats.RouteStep{Selection: featurestats.SelectionRule, Outbound: featurestats.OutboundRef{Serial: 1, Tag: "forward"}})
	live, _ := store.ReadLive(context.Background())
	if live.Rows[0].AccountingRoute.Outbound.Serial != 0 {
		t.Fatal("selection was an accounting claim")
	}
	totals, _ := store.ReadTotals(context.Background())
	if len(totals.Rows) != 4 {
		t.Fatal("selection created a bucket")
	}
	flow.Route(featurestats.RouteStep{Selection: featurestats.SelectionRule, Outbound: featurestats.OutboundRef{Serial: 2, Tag: "consumer"}})
	flow.BindRoute()
	flow.AddUplink(1)
	flow.Finish()
	page, _ := store.ReadTerminals(context.Background())
	row := page.Rows[0].Flow
	if len(row.Routes) != 1 || row.Routes[0].Outbound.Serial != 1 || row.AccountingRoute.Outbound.Serial != 2 || row.Routes[0].Leg == row.AccountingRoute.Leg || !row.MetadataTruncated || row.Uplink.Known != 10 {
		t.Fatalf("bounded route projection: %+v", row)
	}
	totals, _ = store.ReadTotals(context.Background())
	if len(totals.Rows) != 5 || findTotal(t, totals.Rows, 2, featurestats.TrafficOriginUser).Uplink.Known != 10 {
		t.Fatalf("consuming totals: %+v", totals)
	}
}

func TestInspectionIndependentSample(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	cell := store.unassigned[int(featurestats.TrafficOriginUser)]
	cell.uplink.addKnown(1)
	snapshot, err := store.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fact := findTotal(t, snapshot.Rows, 0, featurestats.TrafficOriginUser).Uplink
	if fact.Known != 1 || fact.Incomplete || snapshot.Sample.Runtime != store.runtime || snapshot.Sample.At < 0 {
		t.Fatalf("independent sample: %+v", snapshot)
	}
}

func TestInspectionTerminalStorageGrowsWithinLimit(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{MaxTerminals: 3})
	if cap(store.terminals) != 0 {
		t.Fatal("terminal storage allocated before first ending")
	}
	for i := 0; i < 8; i++ {
		flow := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
		flow.Finish()
		if cap(store.terminals) > 3 || len(store.terminals) != min(i+1, 3) {
			t.Fatalf("terminal storage len=%d cap=%d after ending %d", len(store.terminals), cap(store.terminals), i+1)
		}
	}
}

func TestInspectionKnownDownlink(t *testing.T) {
	store := testInspectionStore(t, featurestats.ObservationOptions{})
	flow := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.AddDownlink(3)
	flow.Route(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Serial: 1}})
	flow.BindRoute()
	flow.AddDownlink(4)
	flow.SetEndReason(featurestats.EndReasonWriteError)
	flow.Finish()
	page, err := store.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	final := page.Rows[0].Flow.Downlink
	if final.Known != 7 || final.Incomplete {
		t.Fatalf("known facts: %+v", final)
	}
	totals, err := store.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := findTotal(t, totals.Rows, 1, featurestats.TrafficOriginUser).Downlink; got.Known != 7 || got.Incomplete {
		t.Fatalf("known totals: %+v", got)
	}
}

func TestInspectionPrebindAcceptedSaturation(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact-limit", true: "overflow"}[overflow], func(t *testing.T) {
			store := testInspectionStore(t, featurestats.ObservationOptions{})
			flow := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
			flow.AddUplink(math.MaxUint64)
			flow.AddDownlink(math.MaxUint64)
			if overflow {
				flow.AddUplink(1)
				flow.AddDownlink(1)
			}
			flow.Route(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Serial: 1}})
			flow.BindRoute()
			flow.BindRoute()
			flow.Unassign()
			flow.Finish()
			totals, err := store.ReadTotals(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			row := findTotal(t, totals.Rows, 1, featurestats.TrafficOriginUser)
			for _, fact := range []featurestats.ByteFact{row.Uplink, row.Downlink} {
				if fact.Known != math.MaxUint64 || fact.Incomplete != overflow {
					t.Fatalf("accepted saturation changed on binding: %+v", fact)
				}
			}
		})
	}
}
