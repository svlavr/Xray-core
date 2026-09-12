package flow

import (
	"math"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestServerMuxCarrierUsesSeparateTwoSeriesAndCoverage(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 1, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c := r.NewMuxCarrierObservation()
	if c == nil || c.FrameObservation() == nil {
		t.Fatal("missing carrier observation")
	}
	f := c.FrameObservation()
	f.Read(7)
	f.Write(11, nil)
	s := r.Snapshot()
	if len(s.Records) != 0 || len(s.CarrierRecords) != 1 || len(s.CarrierCounterSeries) != 2 {
		t.Fatalf("wrong independent namespaces: %+v", s)
	}
	if s.AccountingCoverage.State != AccountingCoverageComplete || s.CarrierAccountingCoverage[0].State != AccountingCoverageComplete || s.CarrierCounterSeries[0].CumulativeBytes.Value+s.CarrierCounterSeries[1].CumulativeBytes.Value != 18 {
		t.Fatalf("unexpected carrier accounting: %+v", s)
	}
	started := 0
	for _, event := range r.EventsAfter(0, 64).Events {
		if event.Type == EventCounterSeriesStarted && event.CarrierSeries != nil {
			started++
			if event.CarrierSeries.ActiveCarrierCount != (OptionalUint64{Known: true, Value: 1}) {
				t.Fatalf("carrier series start event has false active count: %+v", event.CarrierSeries)
			}
		}
	}
	if started != 2 {
		t.Fatalf("carrier series start events = %d, want 2", started)
	}
	f.Write(9, assertErr{})
	s = r.Snapshot()
	if s.AccountingCoverage.State != AccountingCoverageComplete || carrierCoverageForTest(t, s, DirectionDownlink).State != AccountingCoverageIndeterminate {
		t.Fatalf("downlink carrier uncertainty leaked: %+v", s)
	}
	f.ReaderExited()
	f.UplinkSealed()
	f.MonitorCompleted()
	f.DownlinkSealed()
	c.Close()
	if s = r.Snapshot(); s.CarrierRecords[0].CompletionState != CompletionTerminal || s.CarrierRecords[0].TerminalClass != "" {
		t.Fatalf("carrier did not terminalize: %+v", s.CarrierRecords[0])
	}
}

func TestServerCarrierReferenceExhaustionIsKindLocal(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.nextCarrier.Store(math.MaxUint64)
	if carrier := r.NewMuxCarrierObservation(); carrier != nil {
		t.Fatal("server carrier reference exhaustion admitted capability")
	}
	snapshot := r.Snapshot()
	if snapshot.DroppedFlowCount != 0 || snapshot.AccountingCoverage.State != AccountingCoverageComplete || snapshot.DroppedCarrierObservationCount != 1 {
		t.Fatalf("server carrier exhaustion crossed flow accounting: %+v", snapshot)
	}
	for _, coverage := range snapshot.CarrierAccountingCoverage {
		wantIndeterminate := coverage.Key.CarrierKind == CarrierKindServerMuxFrameLink
		if (coverage.State == AccountingCoverageIndeterminate) != wantIndeterminate {
			t.Fatalf("server carrier exhaustion crossed kind: %+v", snapshot.CarrierAccountingCoverage)
		}
	}
}

func TestServerMuxCarrierFenceWaitsForConcurrentHandlers(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 128, MaxSeries: 1, MaxEvents: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c := r.NewMuxCarrierObservation()
	f := c.FrameObservation()
	const siblings = 64
	for i := 0; i < siblings; i++ {
		f.Reserve()
	}
	f.ReaderExited()
	f.UplinkSealed()
	f.MonitorCompleted()
	f.DownlinkSealed()
	c.Close()
	if s := r.Snapshot(); s.CarrierRecords[0].CompletionState == CompletionTerminal {
		t.Fatal("terminal before handler fence")
	}
	var wg sync.WaitGroup
	for i := 0; i < siblings; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.Write(1, nil); f.Release() }()
	}
	wg.Wait()
	if s := r.Snapshot(); s.CarrierRecords[0].CompletionState != CompletionTerminal {
		t.Fatalf("terminal missing after all handlers: %+v", s.CarrierRecords[0])
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "write" }

func TestCarrierPendingExhaustionDoesNotSuppressFlowAdmission(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.mu.Lock()
	r.pendingCarriers <- &serverMuxCarrier{r: r, ref: "pending", kind: CarrierKindServerMuxFrameLink, state: carrierCommitted}
	carrier := r.NewMuxCarrierObservation()
	r.mu.Unlock()
	if carrier == nil {
		t.Fatal("carrier reference was suppressed")
	}
	destination := net.TCPDestination(net.DomainAddress("pending-child.example"), 443)
	scope, ok := carrier.NewTCPSession([8]byte{}, destination, "").(*MuxSessionScope)
	if !ok || r.AdmitMuxTCP(scope, destination) == nil {
		t.Fatal("carrier pressure suppressed decoded child admission")
	}
	s := r.Snapshot()
	if s.DroppedFlowCount != 0 || s.AccountingCoverage.State != AccountingCoverageComplete || s.DroppedCarrierObservationCount == 0 || len(s.Records) != 1 || s.Records[0].CarrierReference != carrier.reference {
		t.Fatalf("wrong independent loss: %+v", s)
	}
	for _, coverage := range s.CarrierAccountingCoverage {
		if coverage.Key.CarrierKind != CarrierKindServerMuxFrameLink {
			continue
		}
		if coverage.State != AccountingCoverageIndeterminate {
			t.Fatalf("omitted carrier did not make membership unknown: %+v", s.CarrierAccountingCoverage)
		}
	}
	r.NewMuxCarrierObservation()
	if current := r.Snapshot(); carrierCoverageForTest(t, current, DirectionUplink).State != AccountingCoverageIndeterminate || carrierCoverageForTest(t, current, DirectionDownlink).State != AccountingCoverageIndeterminate {
		t.Fatalf("omitted membership recovered before runtime reset: %+v", current.CarrierAccountingCoverage)
	}
	fresh, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 8})
	if err != nil {
		t.Fatal(err)
	}
	if reset := fresh.Snapshot(); carrierCoverageForTest(t, reset, DirectionUplink).State != AccountingCoverageComplete || carrierCoverageForTest(t, reset, DirectionDownlink).State != AccountingCoverageComplete {
		fresh.Close()
		t.Fatalf("runtime reset did not restore initial carrier coverage: %+v", reset.CarrierAccountingCoverage)
	}
	fresh.Close()
}

func TestCarrierEventsShareRetentionRingAndResyncProgresses(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 1, MaxEvents: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c := r.NewMuxCarrierObservation()
	f := c.FrameObservation()
	start := make(chan struct{})
	retentionExceeded := make(chan struct{})
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		<-start
		for i := 0; i < 256; i++ {
			f.Read(1)
			_ = r.Snapshot()
			if i == 15 {
				close(retentionExceeded)
			}
			runtime.Gosched()
		}
	}()
	close(start)
	<-retentionExceeded
	cursor := uint64(0)
	resyncs := 0
	producerFinished := false
	for attempts := 0; attempts < 10000; attempts++ {
		batch := r.EventsAfter(cursor, 1)
		if batch.ResyncRequired {
			if batch.GapReason != EventGapRetentionExceeded {
				t.Fatalf("unexpected carrier event gap: %+v", batch)
			}
			snapshot := r.Snapshot()
			if snapshot.Watermark < cursor {
				t.Fatalf("snapshot moved consumer backwards: cursor=%d snapshot=%+v", cursor, snapshot)
			}
			cursor = snapshot.Watermark
			resyncs++
		} else if len(batch.Events) != 0 {
			if batch.DeliveredThroughSequence <= cursor {
				t.Fatalf("carrier event consumer made no progress: cursor=%d batch=%+v", cursor, batch)
			}
			cursor = batch.DeliveredThroughSequence
		}
		if !producerFinished {
			select {
			case <-producerDone:
				producerFinished = true
			default:
			}
		}
		if producerFinished {
			final := r.Snapshot()
			if cursor >= final.Watermark {
				if resyncs == 0 {
					t.Fatal("bounded concurrent churn produced no full-snapshot resync")
				}
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("carrier event consumer did not converge under bounded concurrent churn")
}

func TestPendingCarrierPreservesBytesBeforePublication(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.mu.Lock()
	c := r.NewMuxCarrierObservation()
	if c == nil || c.FrameObservation() == nil {
		r.mu.Unlock()
		t.Fatal("missing pending carrier observation")
	}
	c.FrameObservation().Read(13)
	c.FrameObservation().Write(17, nil)
	r.mu.Unlock()
	snapshot := r.Snapshot()
	if len(snapshot.CarrierRecords) != 1 {
		t.Fatalf("pending carrier record count = %d, want 1", len(snapshot.CarrierRecords))
	}
	uplink := carrierObservationForTest(t, snapshot.CarrierRecords[0], DirectionUplink)
	downlink := carrierObservationForTest(t, snapshot.CarrierRecords[0], DirectionDownlink)
	if uplink.ObservedBytes != (OptionalUint64{Known: true, Value: 13}) || downlink.ObservedBytes != (OptionalUint64{Known: true, Value: 17}) {
		t.Fatalf("early pending bytes were lost: %+v", snapshot.CarrierRecords[0].ByteObservations)
	}
}

func TestCarrierKnownZeroRestartsOnlyAffectedSeries(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 4, MaxSeries: 1, MaxEvents: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c1 := r.NewMuxCarrierObservation()
	f1 := c1.FrameObservation()
	f1.Write(9, assertErr{})
	first := r.Snapshot()
	var firstDownlinkID string
	for _, series := range first.CarrierCounterSeries {
		if series.Key.Direction == DirectionDownlink {
			firstDownlinkID = series.SeriesID
		}
	}
	f1.ReaderExited()
	f1.UplinkSealed()
	f1.MonitorCompleted()
	f1.DownlinkSealed()
	c1.Close()
	afterClose := r.Snapshot()
	if carrierCoverageForTest(t, afterClose, DirectionDownlink).State != AccountingCoverageComplete {
		t.Fatalf("known-zero downlink did not recover: %+v", afterClose.CarrierAccountingCoverage)
	}
	c2 := r.NewMuxCarrierObservation()
	second := r.Snapshot()
	if len(second.CarrierCounterSeries) != 2 {
		t.Fatalf("carrier series cardinality = %d, want 2", len(second.CarrierCounterSeries))
	}
	for _, series := range second.CarrierCounterSeries {
		if series.Key.Direction == DirectionDownlink {
			if series.SeriesID == firstDownlinkID || series.StartReason != SeriesStartAfterCoverageLoss || series.CoverageGeneration != 2 {
				t.Fatalf("downlink series did not restart after known zero: before=%s after=%+v", firstDownlinkID, series)
			}
		}
	}
	finishCarrierForTest(c2)
}

func TestRegistryCloseMakesOpenCarrierIndeterminateAndLateCallbacksInert(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	c := r.NewMuxCarrierObservation()
	f := c.FrameObservation()
	f.Read(3)
	f.Reserve()
	var closes sync.WaitGroup
	for i := 0; i < 8; i++ {
		closes.Add(1)
		go func() {
			defer closes.Done()
			r.Close()
		}()
	}
	closes.Wait()
	before := r.Snapshot()
	if len(before.CarrierRecords) != 1 || before.CarrierRecords[0].CompletionState != CompletionIndeterminate || before.CarrierRecords[0].IndeterminateReason != IndeterminateRuntimeStopped {
		t.Fatalf("registry close fabricated carrier completion: %+v", before.CarrierRecords)
	}
	if before.CarrierAccountingCoverage[0].State != AccountingCoverageIndeterminate || before.CarrierAccountingCoverage[1].State != AccountingCoverageIndeterminate {
		t.Fatalf("registry close kept carrier coverage complete: %+v", before.CarrierAccountingCoverage)
	}
	f.Read(100)
	f.Write(100, nil)
	f.Release()
	f.ReaderExited()
	f.MonitorCompleted()
	f.UplinkSealed()
	f.DownlinkSealed()
	c.Close()
	after := r.Snapshot()
	if after.Watermark != before.Watermark || after.CarrierRecords[0].CompletionState != CompletionIndeterminate || !byteObservationsEqual(after.CarrierRecords[0].ByteObservations, before.CarrierRecords[0].ByteObservations) {
		t.Fatalf("late carrier callbacks changed closed registry: before=%+v after=%+v", before, after)
	}
}

func TestRegistryCloseLinearizesBlockedOwnerCallback(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	c := r.NewMuxCarrierObservation()
	f := c.FrameObservation()
	f.ReaderExited()
	f.UplinkSealed()
	f.MonitorCompleted()
	f.DownlinkSealed()
	_ = r.Snapshot()

	c.frame.mu.Lock()
	callbackDone := make(chan struct{})
	go func() {
		c.Close()
		close(callbackDone)
	}()
	closeDone := make(chan struct{})
	go func() {
		r.Close()
		close(closeDone)
	}()
	deadline := time.Now().Add(time.Second)
	for !r.continuationsClosed.Load() {
		if time.Now().After(deadline) {
			c.frame.mu.Unlock()
			t.Fatal("registry close did not revoke carrier authority")
		}
		time.Sleep(time.Millisecond)
	}
	c.frame.mu.Unlock()
	<-callbackDone
	<-closeDone
	snapshot := r.Snapshot()
	if len(snapshot.CarrierRecords) != 1 || snapshot.CarrierRecords[0].CompletionState != CompletionIndeterminate || snapshot.CarrierRecords[0].IndeterminateReason != IndeterminateRuntimeStopped || snapshot.CarrierRecords[0].TerminalClass != "" {
		t.Fatalf("late owner callback fabricated terminal state: %+v", snapshot.CarrierRecords)
	}
	watermark := snapshot.Watermark
	if again := r.Snapshot(); again.Watermark != watermark || again.CarrierRecords[0].CompletionState != CompletionIndeterminate {
		t.Fatalf("closed carrier state changed after linearization: before=%+v after=%+v", snapshot, again)
	}
}

func TestRegistryCloseRejectsAllPendingCarriersBeforeReturning(t *testing.T) {
	const pending = 128
	r, err := NewRegistry(Config{MaxRecords: pending, MaxSeries: 2, MaxEvents: 256})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	for i := 0; i < pending; i++ {
		r.pendingCarriers <- &serverMuxCarrier{r: r, ref: "pending-close-" + encodeUint64(uint64(i+1)), kind: CarrierKindServerMuxFrameLink, state: carrierCommitted}
	}
	closeDone := make(chan struct{})
	go func() {
		r.Close()
		close(closeDone)
	}()
	deadline := time.Now().Add(time.Second)
	for !r.continuationsClosed.Load() {
		if time.Now().After(deadline) {
			r.mu.Unlock()
			t.Fatal("registry close did not start")
		}
		time.Sleep(time.Millisecond)
	}
	r.mu.Unlock()
	<-closeDone
	if got := len(r.pendingCarriers); got != 0 {
		t.Fatalf("registry close retained %d pending carriers", got)
	}
	first := r.Snapshot()
	second := r.Snapshot()
	if first.DroppedCarrierObservationCount != pending || second.DroppedCarrierObservationCount != pending || first.Watermark != second.Watermark {
		t.Fatalf("closed registry remained mutable: first=%+v second=%+v", first, second)
	}
}

func TestSustainedCarrierAdmissionDoesNotStarveMuxChildren(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 256, MaxSeries: 4, MaxEvents: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	parent := r.NewMuxCarrierObservation()
	if parent == nil {
		t.Fatal("missing parent carrier")
	}
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < 512; i++ {
			r.NewMuxCarrierObservation()
		}
	}()
	const children = 64
	for i := 0; i < children; i++ {
		destination := net.TCPDestination(net.DomainAddress("sustained-child.example"), net.Port(1000+i))
		scope, ok := parent.NewTCPSession([8]byte{}, destination, "").(*MuxSessionScope)
		if !ok || r.AdmitMuxTCP(scope, destination) == nil {
			t.Fatalf("carrier pressure rejected decoded child %d", i)
		}
	}
	<-producerDone
	snapshot := r.Snapshot()
	if len(snapshot.Records) != children || snapshot.DroppedFlowCount != 0 || snapshot.AccountingCoverage.State != AccountingCoverageComplete {
		t.Fatalf("carrier pressure changed flow domain: records=%d dropped=%d coverage=%+v", len(snapshot.Records), snapshot.DroppedFlowCount, snapshot.AccountingCoverage)
	}
	for _, record := range snapshot.Records {
		if record.CarrierReference != parent.reference {
			t.Fatalf("decoded child lost carrier correlation: %+v", record)
		}
	}
}

func TestDroppedCarrierObservationCountSaturates(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.mu.Lock()
	r.droppedCarriers = math.MaxUint64
	r.mu.Unlock()
	r.recordCarrierAdmissionLoss()
	if got := r.Snapshot().DroppedCarrierObservationCount; got != math.MaxUint64 {
		t.Fatalf("dropped carrier count wrapped to %d", got)
	}
}

func TestCarrierCounterOverflowIsDirectionalAndTyped(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c := r.NewMuxCarrierObservation()
	f := c.FrameObservation()
	f.Read(math.MaxUint64)
	f.Read(1)
	snapshot := r.Snapshot()
	uplink := carrierObservationForTest(t, snapshot.CarrierRecords[0], DirectionUplink)
	downlink := carrierObservationForTest(t, snapshot.CarrierRecords[0], DirectionDownlink)
	if uplink.State != ByteObservationStateOverflowed || uplink.AccountingFault != AccountingFaultCounterOverflow || uplink.ObservedBytes.Known {
		t.Fatalf("uplink overflow was not typed: %+v", uplink)
	}
	if downlink.State != ByteObservationStateProven || !downlink.ObservedBytes.Known || carrierCoverageForTest(t, snapshot, DirectionDownlink).State != AccountingCoverageComplete {
		t.Fatalf("uplink overflow leaked into downlink: observation=%+v coverage=%+v", downlink, snapshot.CarrierAccountingCoverage)
	}
}

func TestCarrierRetentionEvictsOnlyTerminalDetail(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first := r.NewMuxCarrierObservation()
	firstRef := first.reference
	finishCarrierForTest(first)
	if snapshot := r.Snapshot(); snapshot.CarrierRecords[0].CompletionState != CompletionTerminal {
		t.Fatalf("first carrier did not terminalize: %+v", snapshot.CarrierRecords)
	}
	second := r.NewMuxCarrierObservation()
	snapshot := r.Snapshot()
	if len(snapshot.CarrierRecords) != 1 || snapshot.CarrierRecords[0].CarrierReference == firstRef || snapshot.EvictedCarrierRecordCount != 1 || snapshot.DroppedCarrierObservationCount != 0 {
		t.Fatalf("terminal-only carrier eviction failed: %+v", snapshot)
	}
	foundEviction := false
	for _, event := range r.EventsAfter(0, 64).Events {
		if event.Type == EventCarrierDetailEvicted && event.Carrier != nil && event.Carrier.CarrierReference == firstRef {
			foundEviction = true
		}
	}
	if !foundEviction {
		t.Fatal("missing CARRIER_DETAIL_EVICTED event")
	}
	finishCarrierForTest(second)
}

func BenchmarkServerMuxCarrierFrameObservation(b *testing.B) {
	r, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 8192})
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	frame := r.NewMuxCarrierObservation().FrameObservation()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.Read(1)
		frame.Write(1, nil)
	}
	b.StopTimer()
	_ = r.Snapshot()
}

func carrierObservationForTest(t testing.TB, record CarrierRecord, direction Direction) ByteObservation {
	t.Helper()
	for _, observation := range record.ByteObservations {
		if observation.Direction == direction {
			return observation
		}
	}
	t.Fatalf("missing %s observation in %+v", direction, record.ByteObservations)
	return ByteObservation{}
}

func carrierCoverageForTest(t testing.TB, snapshot Snapshot, direction Direction) CarrierAccountingCoverage {
	t.Helper()
	for _, coverage := range snapshot.CarrierAccountingCoverage {
		if coverage.Key.CarrierKind == CarrierKindServerMuxFrameLink && coverage.Key.Direction == direction {
			return coverage
		}
	}
	t.Fatalf("missing %s carrier coverage in %+v", direction, snapshot.CarrierAccountingCoverage)
	return CarrierAccountingCoverage{}
}

func finishCarrierForTest(c *MuxCarrier) {
	f := c.FrameObservation()
	f.ReaderExited()
	f.UplinkSealed()
	f.MonitorCompleted()
	f.DownlinkSealed()
	c.Close()
}
