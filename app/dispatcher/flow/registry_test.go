package flow

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionOriginIsFailClosedAndValuesAreCopied(t *testing.T) {
	registry := newTestRegistry(t, 8, 8, 32)
	unknown := registry.AdmitTCP(context.Background(), "source", "tcp:example.com:443", "", ByteScopeDispatcherExternalLinkIO)
	coordinate := []byte("router-state-7")
	userContext, err := WithUserAdmission(context.Background(), Admission{Coordinate: coordinate, OpaqueAndroidUID: OptionalUint64{Known: true, Value: 10001}})
	if err != nil {
		t.Fatal(err)
	}
	coordinate[0] = 'X'
	user := registry.AdmitTCP(userContext, "source", "tcp:example.com:443", "tls", ByteScopeDispatcherExternalLinkIO)
	measurementContext, err := WithControlledMeasurementAdmission(context.Background(), Admission{})
	if err != nil {
		t.Fatal(err)
	}
	measurement := registry.AdmitTCP(measurementContext, "", "tcp:example.com:443", "", ByteScopeDispatcherExternalLinkIO)

	selectTestRoot(unknown, "out-a")
	selectTestRoot(user, "out-a")
	selectTestRoot(measurement, "out-a")
	unknown.AddUplink(3)
	user.AddUplink(5)
	measurement.AddUplink(7)
	snapshot := registry.Snapshot()
	if got := snapshot.Records[0]; got.TrafficOrigin != OriginUnknown || got.OriginProof != OriginProofNone || got.AdmissionCoordinate.Known || got.OpaqueAndroidUID.Known {
		t.Fatalf("unmarked traffic was not fail-closed: %+v", got)
	}
	if got := snapshot.Records[1]; got.TrafficOrigin != OriginUser || got.OriginProof != OriginProofTrustedIngressMarker || string(got.AdmissionCoordinate.Value) != "router-state-7" || got.OpaqueAndroidUID != (OptionalUint64{Known: true, Value: 10001}) {
		t.Fatalf("unexpected user admission: %+v", got)
	}
	if got := snapshot.Records[2]; got.TrafficOrigin != OriginControlledMeasurement || got.OriginProof != OriginProofMeasurementAdmission {
		t.Fatalf("unexpected measurement admission: %+v", got)
	}
	bytesByOrigin := make(map[Origin]uint64, len(snapshot.CounterSeries))
	for _, series := range snapshot.CounterSeries {
		if series.Key.Direction != DirectionUplink {
			continue
		}
		if !series.CumulativeBytes.Known {
			t.Fatalf("origin-specific series unexpectedly unknown: %+v", series)
		}
		bytesByOrigin[series.Key.TrafficOrigin] = series.CumulativeBytes.Value
	}
	if bytesByOrigin[OriginUnknown] != 3 || bytesByOrigin[OriginUser] != 5 || bytesByOrigin[OriginControlledMeasurement] != 7 {
		t.Fatalf("traffic origins contaminated one another: %+v", snapshot.CounterSeries)
	}
	if _, err := WithUserAdmission(context.Background(), Admission{Coordinate: make([]byte, MaxAdmissionCoordinateBytes+1)}); err == nil {
		t.Fatal("oversize admission coordinate accepted")
	}
	if _, err := WithControlledMeasurementAdmission(context.Background(), Admission{OpaqueAndroidUID: OptionalUint64{Known: true, Value: 10001}}); err == nil {
		t.Fatal("controlled measurement accepted a trusted-platform UID")
	}
	unknownUIDContext, err := WithUserAdmission(context.Background(), Admission{OpaqueAndroidUID: OptionalUint64{Value: 10001}})
	if err != nil {
		t.Fatal(err)
	}
	if uid := admissionFromContext(unknownUIDContext).admission.OpaqueAndroidUID; uid != (OptionalUint64{}) {
		t.Fatalf("unknown Android UID retained a hidden value: %+v", uid)
	}
	if _, err := WithControlledMeasurementAdmission(userContext, Admission{}); err == nil {
		t.Fatal("immutable admission marker overwritten")
	}
}

func TestUDPAssociationAdmissionUsesSharedIdentityAndOriginModel(t *testing.T) {
	registry := newTestRegistry(t, 3, 6, 32)
	userContext, err := WithUserAdmission(context.Background(), Admission{Coordinate: []byte("route-7")})
	if err != nil {
		t.Fatal(err)
	}
	measurementContext, err := WithControlledMeasurementAdmission(context.Background(), Admission{})
	if err != nil {
		t.Fatal(err)
	}

	unknown := registry.AdmitUDPAssociation(context.Background(), "udp:source:1000", "udp:first.example:53", "")
	user := registry.AdmitUDPAssociation(userContext, "udp:source:1001", "udp:second.example:53", "dns")
	measurement := registry.AdmitUDPAssociation(measurementContext, "", "udp:third.example:53", "dns")
	for _, handle := range []*Handle{unknown, user, measurement} {
		if handle == nil {
			t.Fatal("UDP association admission failed")
		}
		handle.SelectRoot("", "udp-out", "handler", handle.root.record.record.OriginalDestination, handle.root.record.record.Protocol, true, CarrierProofNotApplicable)
		handle.AddUplink(1)
	}

	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 3 {
		t.Fatalf("UDP associations = %d, want 3", len(snapshot.Records))
	}
	wantOrigins := []Origin{OriginUnknown, OriginUser, OriginControlledMeasurement}
	for index, record := range snapshot.Records {
		if record.FlowKind != KindUDPAssociation || record.TrafficOrigin != wantOrigins[index] || len(record.ByteObservations) != 2 {
			t.Fatalf("UDP association %d has wrong shared record model: %+v", index, record)
		}
		for _, observation := range record.ByteObservations {
			if observation.ByteScope != ByteScopeLogicalLinkAccepted {
				t.Fatalf("UDP association exposed non-logical byte scope: %+v", observation)
			}
		}
	}
	if len(snapshot.CounterSeries) != 6 {
		t.Fatalf("origin-separated UDP series = %d, want 6: %+v", len(snapshot.CounterSeries), snapshot.CounterSeries)
	}
}

func TestOversizedSelectedOutboundCannotCollideInCumulativeSeries(t *testing.T) {
	registry := newTestRegistry(t, 3, 3, 32)
	normal := registry.AdmitTCP(context.Background(), "", "tcp:normal:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(normal, "normal")
	normal.AddUplink(7)
	before := registry.Snapshot()
	if len(before.CounterSeries) != 2 {
		t.Fatalf("normal series was not continuous before attribution loss: %+v", before)
	}
	var normalUplinkSeriesID string
	for _, series := range before.CounterSeries {
		if series.State != SeriesStateContinuous || (series.Key.Direction == DirectionUplink && series.CumulativeBytes != (OptionalUint64{Known: true, Value: 7})) {
			t.Fatalf("normal series was not continuous before attribution loss: %+v", before)
		}
		if series.Key.Direction == DirectionUplink {
			normalUplinkSeriesID = series.SeriesID
		}
	}
	first := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	first.SelectRoot("", string(make([]byte, maxTagBytes+1)), "type", "tcp:a:1", "", true, CarrierProofNotApplicable)
	second.SelectRoot("", "x"+string(make([]byte, maxTagBytes)), "type", "tcp:b:1", "", true, CarrierProofNotApplicable)
	first.AddUplink(11)
	second.AddUplink(13)

	snapshot := registry.Snapshot()
	if snapshot.AccountingCoverage.State != AccountingCoverageIndeterminate || snapshot.AccountingCoverage.Reason != DiscontinuityAccountingScopeUnproven || len(snapshot.CounterSeries) != 2 {
		t.Fatalf("oversized outbound attribution remained aggregate-compatible: %+v", snapshot)
	}
	for _, series := range snapshot.CounterSeries {
		if series.Key.SelectedTopLevelOutboundTag != "normal" || series.State != SeriesStateIndeterminate || series.CumulativeBytes.Known {
			t.Fatalf("existing durable series was not retained and invalidated explicitly: %+v", series)
		}
		if series.Key.Direction == DirectionUplink && series.SeriesID != normalUplinkSeriesID {
			t.Fatalf("existing uplink series identity changed across attribution loss: before=%q after=%+v", normalUplinkSeriesID, series)
		}
	}
	for index, record := range snapshot.Records {
		if index == 0 {
			continue
		}
		if record.Route.SelectedTopLevelOutboundTag != "" || !detourRecordHasIssue(record, IssueFieldOversize) || !detourRecordHasIssue(record, IssueSelectedOutboundUnknown) {
			t.Fatalf("oversized outbound was not exposed as unknown: %+v", record)
		}
	}
}

func TestRegistryClosePrioritizesStopOverContinuousDirtySignals(t *testing.T) {
	registry, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 2, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	producerDone := make(chan struct{})
	producerStarted := make(chan struct{})
	stopProducer := make(chan struct{})
	go func() {
		defer close(producerDone)
		first := true
		for {
			select {
			case <-stopProducer:
				return
			default:
				handle.AddUplink(1)
				if first {
					close(producerStarted)
					first = false
				}
			}
		}
	}()
	<-producerStarted
	closeDone := make(chan struct{})
	go func() {
		registry.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		close(stopProducer)
		<-producerDone
		t.Fatal("registry close starved behind continuous dirty signals")
	}
	close(stopProducer)
	<-producerDone
}

func TestCounterSeriesAreIndependentPerOutboundAndDoNotInventIdleMembers(t *testing.T) {
	registry := newTestRegistry(t, 4, 8, 64)
	ctx, err := WithUserAdmission(context.Background(), Admission{Coordinate: []byte("routing-revision")})
	if err != nil {
		t.Fatal(err)
	}
	first := registry.AdmitTCP(ctx, "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	second := registry.AdmitTCP(ctx, "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(first, "active-a")
	selectTestRoot(second, "active-b")
	first.AddUplink(11)
	second.AddUplink(13)

	snapshot := registry.Snapshot()
	seriesByOutbound := make(map[string]CounterSeries)
	for _, series := range snapshot.CounterSeries {
		if series.Key.Direction == DirectionUplink && series.Key.ByteScope == ByteScopeLogicalLinkAccepted {
			seriesByOutbound[series.Key.SelectedTopLevelOutboundTag] = series
		}
	}
	if len(seriesByOutbound) != 2 || seriesByOutbound["active-a"].CumulativeBytes.Value != 11 || seriesByOutbound["active-b"].CumulativeBytes.Value != 13 {
		t.Fatalf("active outbounds did not retain independent series: %+v", snapshot.CounterSeries)
	}
	if _, invented := seriesByOutbound["idle-c"]; invented {
		t.Fatalf("idle outbound was fabricated as a zero-valued series: %+v", snapshot.CounterSeries)
	}
	if seriesByOutbound["active-a"].ActiveFlowCount != (OptionalUint64{Known: true, Value: 1}) || seriesByOutbound["active-b"].ActiveFlowCount != (OptionalUint64{Known: true, Value: 1}) {
		t.Fatalf("per-outbound active flow counts were merged: %+v", snapshot.CounterSeries)
	}

	terminalize(first)
	terminalize(second)
	snapshot = registry.Snapshot()
	for _, series := range snapshot.CounterSeries {
		if series.Key.Direction == DirectionUplink && series.Key.ByteScope == ByteScopeLogicalLinkAccepted && series.ActiveFlowCount != (OptionalUint64{Known: true}) {
			t.Fatalf("terminal flow remained active in series: %+v", series)
		}
	}
}

func TestFlowDetailEvictionDoesNotChangeCounterSeries(t *testing.T) {
	registry := newTestRegistry(t, 1, 4, 64)
	first := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(first, "out")
	first.AddUplink(11)
	first.AddDownlink(13)
	terminalize(first)
	before := testSeries(t, registry.Snapshot().CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted)

	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	if second == nil {
		t.Fatal("terminal detail was not evicted")
	}
	selectTestRoot(second, "out")
	after := registry.Snapshot()
	if after.EvictedRecordCount != 1 || len(after.Records) != 1 || len(after.CounterSeries) != 2 {
		t.Fatalf("unexpected retention state: %+v", after)
	}
	uplink := testSeries(t, after.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted)
	downlink := testSeries(t, after.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted)
	if uplink.SeriesID != before.SeriesID || uplink.State != SeriesStateContinuous || uplink.CumulativeBytes != (OptionalUint64{Known: true, Value: 11}) || downlink.CumulativeBytes != (OptionalUint64{Known: true, Value: 13}) {
		t.Fatalf("detail eviction changed cumulative accounting: before=%+v after=%+v", before, after.CounterSeries)
	}
	foundEviction := false
	for _, event := range registry.EventsAfter(0, 64).Events {
		if event.Type == EventFlowDetailEvicted {
			foundEviction = event.Record != nil && event.Record.FlowID == first.flowID
		}
	}
	if !foundEviction {
		t.Fatal("flow-detail eviction event did not identify the removed flow")
	}
}

func TestOpaqueCounterSeriesKeyCannotCollideOnDelimiters(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	firstContext, err := WithUserAdmission(context.Background(), Admission{Coordinate: []byte("a\x00b")})
	if err != nil {
		t.Fatal(err)
	}
	secondContext, err := WithUserAdmission(context.Background(), Admission{Coordinate: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	first := registry.AdmitTCP(firstContext, "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	first.SelectRoot("", "c", "type", "tcp:a:1", "", true, CarrierProofNotApplicable)
	second := registry.AdmitTCP(secondContext, "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	second.SelectRoot("", "b\x00c", "type", "tcp:b:1", "", true, CarrierProofNotApplicable)
	if series := registry.Snapshot().CounterSeries; len(series) != 4 {
		t.Fatalf("distinct structured keys collided: %+v", series)
	}
}

func TestInactiveSeriesEvictionRecreatesWithNewIdentity(t *testing.T) {
	registry := newTestRegistry(t, 3, 1, 64)
	first := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(first, "out-a")
	first.AddUplink(5)
	terminalize(first)
	firstID := testSeries(t, registry.Snapshot().CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).SeriesID

	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(second, "out-b")
	terminalize(second)
	if registry.Snapshot().EvictedSeriesCount != 2 {
		t.Fatal("inactive series was not evicted")
	}
	third := registry.AdmitTCP(context.Background(), "", "tcp:c:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(third, "out-a")
	series := testSeries(t, registry.Snapshot().CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted)
	if series.SeriesID == firstID || series.CumulativeBytes.Value != 0 || series.StartReason != SeriesStartFirstObserved {
		t.Fatalf("series incarnation was reused: old=%s new=%+v", firstID, series)
	}
}

func TestSeriesCapacityLossIsExplicitAndNeverPublishesUnknownAsZero(t *testing.T) {
	registry := newTestRegistry(t, 3, 1, 64)
	first := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(first, "out-a")
	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(second, "out-b")
	snapshot := registry.Snapshot()
	if snapshot.AccountingCoverage.State != AccountingCoverageIndeterminate || snapshot.AccountingCoverage.Generation != 2 || snapshot.AccountingCoverage.Reason != DiscontinuityAccountingCapacityExceeded {
		t.Fatalf("accounting loss was not explicit: %+v", snapshot.AccountingCoverage)
	}
	if len(snapshot.CounterSeries) != 2 || snapshot.CounterSeries[0].State != SeriesStateIndeterminate || snapshot.CounterSeries[0].CumulativeBytes.Known || snapshot.CounterSeries[0].ActiveFlowCount.Known {
		t.Fatalf("unknown coverage was emitted as numeric state: %+v", snapshot.CounterSeries)
	}
	if testObservation(t, snapshot.Records[1].ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Known {
		t.Fatalf("unaccounted flow retained a fabricated zero: %+v", snapshot.Records[1])
	}
}

func TestUnsupportedRedispatchInvalidatesCoverageBeforeSameKeyReuse(t *testing.T) {
	registry := newTestRegistry(t, 2, 4, 64)
	first := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(first, "out")
	// Attach the first root before its later topology makes only that root's
	// exact observations indeterminate.
	_ = registry.Snapshot()
	first.BeginRedispatch("mux", "mux-type", "", false, CarrierProofUnknown, IssueMuxCarrierF2Required)
	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(second, "out")
	snapshot := registry.Snapshot()
	uplinkSeries := testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted)
	if snapshot.AccountingCoverage.State != AccountingCoverageComplete || len(snapshot.CounterSeries) != 2 || testObservation(t, snapshot.Records[0].ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).State != ByteObservationStateIndeterminate || testObservation(t, snapshot.Records[1].ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).State != ByteObservationStateProven || uplinkSeries.State != SeriesStateIndeterminate || uplinkSeries.ActiveFlowCount != (OptionalUint64{Known: true, Value: 2}) {
		t.Fatalf("unsupported inner topology exposed false continuity: %+v", snapshot)
	}
	for _, issue := range snapshot.Records[1].Issues {
		if issue == IssueAccountingCapacityExceeded {
			t.Fatalf("pre-existing scope loss was mislabeled as capacity exhaustion: %+v", snapshot.Records[1])
		}
	}
}

func TestUnsupportedTopLevelAccountingCannotDisappearFromCompleteCoverage(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "out", "type", "tcp:a:1", "", false, CarrierProofUnknown, IssueDirectSpliceF2Required)
	snapshot := registry.Snapshot()
	if snapshot.AccountingCoverage.State != AccountingCoverageComplete || len(snapshot.CounterSeries) != 2 || testObservation(t, snapshot.Records[0].ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).State != ByteObservationStateIndeterminate || testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).State != SeriesStateIndeterminate {
		t.Fatalf("unsupported selected flow disappeared from complete accounting: %+v", snapshot)
	}
}

func TestCounterOverflowNeverWraps(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddUplink(math.MaxUint64)
	handle.AddUplink(1)
	series := testSeries(t, registry.Snapshot().CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted)
	if series.State != SeriesStateOverflowed || series.CumulativeBytes.Known || series.DiscontinuityReason != DiscontinuityCounterOverflow {
		t.Fatalf("counter overflow wrapped or stayed implicit: %+v", series)
	}
}

func TestMultiScopeSeriesRemainIndependentThroughTerminalAndEviction(t *testing.T) {
	registry := newTestRegistry(t, 1, 3, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddDownlink(9)
	transition := handle.BeginF2RequiredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	transition.Complete(0)
	handle.AddUplink(4)
	terminalize(handle)

	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || len(snapshot.CounterSeries) != 3 {
		t.Fatalf("unexpected multi-scope shape: %+v", snapshot)
	}
	record := snapshot.Records[0]
	if testObservation(t, record.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes != (OptionalUint64{Known: true, Value: 9}) || testObservation(t, record.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted).State != ByteObservationStateF2Required {
		t.Fatalf("terminal record coerced scope provenance: %+v", record.ByteObservations)
	}
	logicalSeries := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted)
	kernelSeries := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if logicalSeries.CumulativeBytes != (OptionalUint64{Known: true, Value: 9}) || logicalSeries.State != SeriesStateContinuous || kernelSeries.CumulativeBytes.Known || kernelSeries.State != SeriesStateF2Required || logicalSeries.ActiveFlowCount.Value != 0 || kernelSeries.ActiveFlowCount.Value != 0 {
		t.Fatalf("multi-scope terminal series were merged or detached incorrectly: %+v", snapshot.CounterSeries)
	}
	foundF2Event := false
	for _, event := range registry.EventsAfter(0, 64).Events {
		if event.Series != nil && event.Series.Key.Direction == DirectionDownlink && event.Series.Key.ByteScope == ByteScopeKernelDirectCopyAccepted {
			foundF2Event = event.Series.State == SeriesStateF2Required && event.Reason == DiscontinuityF2Required && !event.Series.CumulativeBytes.Known
		}
	}
	if !foundF2Event {
		t.Fatal("typed splice transition was absent or numeric in the event surface")
	}

	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	if second == nil {
		t.Fatal("terminal record could not be evicted")
	}
	selectTestRoot(second, "out")
	after := registry.Snapshot()
	if after.EvictedRecordCount != 1 || testSeries(t, after.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted).CumulativeBytes.Value != 9 || testSeries(t, after.CounterSeries, DirectionDownlink, ByteScopeKernelDirectCopyAccepted).State != SeriesStateF2Required {
		t.Fatalf("record eviction rolled back a scope-specific series: %+v", after)
	}
}

func TestProvenDirectCopySeriesUpdatesBeforeOperationCompletion(t *testing.T) {
	registry := newTestRegistry(t, 1, 3, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddDownlink(4)
	operation := handle.BeginDeferredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	operation.Progress(6)
	operation.Progress(7)

	snapshot := registry.Snapshot()
	observation := testObservation(t, snapshot.Records[0].ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if observation.State != ByteObservationStateProven || observation.ObservedBytes != (OptionalUint64{Known: true, Value: 13}) || series.State != SeriesStateContinuous || series.CumulativeBytes != (OptionalUint64{Known: true, Value: 13}) || series.ActiveFlowCount != (OptionalUint64{Known: true, Value: 1}) {
		t.Fatalf("live direct-copy series was not exact and independent: %+v", snapshot)
	}
	operation.Complete(0)
}

func TestDeferredDirectCopyDoesNotPublishIncompleteBeforeRuntimeDecision(t *testing.T) {
	registry := newTestRegistry(t, 1, 3, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	operation := handle.BeginDeferredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)

	pending := registry.Snapshot()
	if pending.AccountingCoverage.State != AccountingCoverageComplete || len(pending.Records) != 1 || len(pending.Records[0].ByteObservations) != 2 {
		t.Fatalf("pending runtime decision leaked a false observation or lost coverage: %+v", pending)
	}

	operation.RequireF2()
	operation.Complete(0)
	decided := registry.Snapshot()
	observation := testObservation(t, decided.Records[0].ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	if observation.State != ByteObservationStateF2Required || decided.AccountingCoverage.State != AccountingCoverageComplete {
		t.Fatalf("deferred fallback was not published as typed incomplete: %+v", decided)
	}
}

func TestBytePathInvalidScopeFailsExistingProofClosed(t *testing.T) {
	tests := []struct {
		name  string
		begin func(*Handle) *ByteOperation
	}{
		{name: "f2-required", begin: func(handle *Handle) *ByteOperation {
			return handle.BeginF2RequiredBytePath(DirectionDownlink, ByteScope("INVALID_SCOPE"))
		}},
		{name: "deferred", begin: func(handle *Handle) *ByteOperation {
			return handle.BeginDeferredBytePath(DirectionDownlink, ByteScope("INVALID_SCOPE"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := newTestRegistry(t, 1, 3, 64)
			handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
			selectTestRoot(handle, "out")
			operation := test.begin(handle)
			operation.Progress(10)
			operation.Complete(10)

			view := handle.LogicalRoot().View()
			if view.AccountingFault != AccountingFaultBoundaryUnproven || len(view.ByteObservations) != 2 {
				t.Fatalf("invalid byte scope was omitted without an explicit fail-closed result: %+v", view)
			}
			for _, observation := range view.ByteObservations {
				if observation.State != ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
					t.Fatalf("invalid byte scope left an accepted scope proven: %+v", view)
				}
			}
		})
	}
}

func TestDirectCopyProgressReachesRegistryWithoutAnotherTrafficOperation(t *testing.T) {
	registry := newTestRegistry(t, 1, 3, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	operation := handle.BeginDeferredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
	operation.Progress(1)
	if got := testObservation(t, registry.Snapshot().Records[0].ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted).ObservedBytes; got != (OptionalUint64{Known: true, Value: 1}) {
		t.Fatalf("initial direct-copy progress was not synchronized: %+v", got)
	}

	operation.Progress(2)
	deadline := time.Now().Add(2 * deferredProgressSyncInterval)
	for {
		registry.mu.Lock()
		record := cloneRecord(registry.records[handle.flowID].record)
		registry.mu.Unlock()
		observation := testObservation(t, record.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		if observation.ObservedBytes == (OptionalUint64{Known: true, Value: 3}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("periodic registry sync left an open quiet flow stale: %+v", record.ByteObservations)
		}
		time.Sleep(10 * time.Millisecond)
	}
	operation.Complete(0)
}

func TestLateProgressRegistryRetirementRaceCannotLeaveContinuousSeries(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		registry := newTestRegistry(t, 1, 3, 64)
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		selectTestRoot(handle, "out")
		operation := handle.BeginDeferredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		operation.Progress(9)
		operation.Complete(0)
		handle.UplinkQuiesced()
		handle.DownlinkQuiesced()
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-start
			handle.LogicalRoot().SealOwner(TerminalClassCompleted, "")
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			operation.Progress(7)
		}()
		close(start)
		waitGroup.Wait()

		view := handle.LogicalRoot().View()
		snapshot := registry.Snapshot()
		rootObservation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		observation := testObservation(t, snapshot.Records[0].ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		if view.Phase == LifecyclePhaseTerminal {
			if observation.State != ByteObservationStateProven || observation.ObservedBytes != (OptionalUint64{Known: true, Value: 9}) || series.State != SeriesStateContinuous {
				t.Fatalf("iteration %d: post-terminal progress changed retained proof: view=%+v snapshot=%+v", iteration, view, snapshot)
			}
		} else if rootObservation.State == ByteObservationStateIndeterminate && (observation.State != ByteObservationStateIndeterminate || series.State == SeriesStateContinuous) {
			t.Fatalf("iteration %d: pre-terminal lost progress survived retirement as continuous: view=%+v snapshot=%+v", iteration, view, snapshot)
		} else if rootObservation.State == ByteObservationStateProven && (view.PostTerminalFaultCount == 0 || observation.State != ByteObservationStateProven || series.State != SeriesStateContinuous) {
			t.Fatalf("iteration %d: frozen retirement boundary was not preserved: view=%+v snapshot=%+v", iteration, view, snapshot)
		}
		registry.Close()
	}
}

func TestLateProgressRegistryThreeWayRetirementRaceCannotLeaveContinuousSeries(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		registry := newTestRegistry(t, 1, 3, 64)
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		selectTestRoot(handle, "out")
		operation := handle.BeginDeferredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		operation.Progress(9)
		operation.Complete(0)
		handle.UplinkQuiesced()
		handle.DownlinkQuiesced()
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(3)
		go func() {
			defer waitGroup.Done()
			<-start
			handle.LogicalRoot().SealOwner(TerminalClassCompleted, "")
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			operation.Progress(7)
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			operation.Complete(0)
		}()
		close(start)
		waitGroup.Wait()

		view := handle.LogicalRoot().View()
		snapshot := registry.Snapshot()
		rootObservation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		observation := testObservation(t, snapshot.Records[0].ByteObservations, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
		if view.Phase == LifecyclePhaseTerminal {
			if observation.State != ByteObservationStateProven || observation.ObservedBytes != (OptionalUint64{Known: true, Value: 9}) || series.State != SeriesStateContinuous {
				t.Fatalf("iteration %d: post-terminal progress changed retained proof: view=%+v snapshot=%+v", iteration, view, snapshot)
			}
		} else if view.ProofState != ProofStateIndeterminate {
			t.Fatalf("iteration %d: lifecycle-fault race did not fail proof closed: view=%+v snapshot=%+v", iteration, view, snapshot)
		} else if rootObservation.State == ByteObservationStateIndeterminate && (observation.State != ByteObservationStateIndeterminate || series.State == SeriesStateContinuous) {
			t.Fatalf("iteration %d: lifecycle-fault race retained an undercounted continuous series: view=%+v snapshot=%+v", iteration, view, snapshot)
		} else if rootObservation.State == ByteObservationStateProven && (view.PostTerminalFaultCount == 0 || observation.State != ByteObservationStateProven || series.State != SeriesStateContinuous) {
			t.Fatalf("iteration %d: frozen retirement boundary was not preserved: view=%+v snapshot=%+v", iteration, view, snapshot)
		}
		registry.Close()
	}
}

func TestByteObservationSnapshotsAndEventsAreImmutable(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddUplink(3)
	snapshot := registry.Snapshot()
	snapshot.Records[0].ByteObservations[0].ObservedBytes.Value = 99
	snapshot.CounterSeries[0].CumulativeBytes.Value = 99
	events := registry.EventsAfter(0, 32)
	for index := range events.Events {
		if events.Events[index].Record != nil && len(events.Events[index].Record.ByteObservations) != 0 {
			events.Events[index].Record.ByteObservations[0].ObservedBytes.Value = 99
		}
	}

	after := registry.Snapshot()
	if testObservation(t, after.Records[0].ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 3 || testSeries(t, after.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).CumulativeBytes.Value != 3 {
		t.Fatalf("consumer mutation changed authoritative byte observations: %+v", after)
	}
}

func TestUnknownByteScopeCannotEscapeFixedObservationBound(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScope("THIRD_PARTY_DYNAMIC_SCOPE"))
	selectTestRoot(handle, "out")
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || len(snapshot.Records[0].ByteObservations) != 0 || len(snapshot.CounterSeries) != 0 || len(handle.LogicalRoot().View().ByteObservations) > MaxByteObservations {
		t.Fatalf("unknown dynamic scope escaped fixed observation representation: %+v", snapshot)
	}
}

func TestMixedTCPUDPScopesTwentyThousandSequentialFlows(t *testing.T) {
	const flowCount = 20_000
	registry := newTestRegistry(t, 64, 3, 64)
	for index := 0; index < flowCount; index++ {
		var handle *Handle
		if index%2 == 0 {
			handle = registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
		} else {
			handle = registry.AdmitUDPAssociation(context.Background(), "", "udp:a:1", "")
		}
		if handle == nil {
			t.Fatalf("flow %d was not admitted", index)
		}
		selectTestRoot(handle, "out")
		handle.AddUplink(1)
		handle.AddDownlink(2)
		if index%2 == 0 {
			transition := handle.BeginF2RequiredBytePath(DirectionDownlink, ByteScopeKernelDirectCopyAccepted)
			transition.Complete(0)
		}
		terminalize(handle)
		if index%32 == 31 {
			_ = registry.Snapshot()
		}
	}
	snapshot := registry.Snapshot()
	if snapshot.DroppedFlowCount != 0 || len(snapshot.Records) > 64 || len(snapshot.CounterSeries) != 3 {
		t.Fatalf("multi-scope stress exceeded bounds: records=%d series=%d dropped=%d", len(snapshot.Records), len(snapshot.CounterSeries), snapshot.DroppedFlowCount)
	}
	if testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).CumulativeBytes != (OptionalUint64{Known: true, Value: flowCount}) || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted).CumulativeBytes != (OptionalUint64{Known: true, Value: flowCount * 2}) || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeKernelDirectCopyAccepted).State != SeriesStateF2Required {
		t.Fatalf("multi-scope stress merged, reset, or fabricated bytes: %+v", snapshot.CounterSeries)
	}
}

func TestIndeterminateRetirementUsesPreRouteLifecycleBarrier(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	if handle == nil {
		t.Fatal("flow admission failed")
	}
	root := handle.LogicalRoot()
	child := root.AcquireParticipant()
	if child == nil {
		t.Fatal("child participant acquisition failed")
	}
	operation := root.Downlink().Reserve()
	root.markLifecycleFault(LifecycleFaultLateParticipantAcquire)
	root.Uplink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().Seal()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")

	registry.mu.Lock()
	barrierView := root.View()
	if barrierView.ProofState != ProofStateIndeterminate || barrierView.LiveParticipantCount != 1 || barrierView.DownlinkQuiescence != nil || registry.applySelectionLocked(handle.root) {
		registry.mu.Unlock()
		t.Fatalf("test did not establish a live proof-faulted barrier: %+v", barrierView)
	}
	handle.SelectRoot("", "out", "type", "tcp:a:1", "", true, CarrierProofNotApplicable)
	handle.RecordDialerProxy("detour", "detour-type")
	operation.Complete(1)
	child.Release(nil)
	accountingView := root.View()
	if accountingView.LiveParticipantCount != 0 || accountingView.DownlinkQuiescence == nil || !root.RetirableIndeterminate() {
		registry.mu.Unlock()
		t.Fatalf("test root did not become freshly retirable: %+v", accountingView)
	}
	registry.syncByteObservationsLocked(handle.root, accountingView)
	registry.applyLifecycleBarrierLocked(handle.flowID, handle.root, barrierView)
	_, stillLiveAfterOldBarrier := registry.roots[handle.flowID]
	if handle.root.retired.Load() || !stillLiveAfterOldBarrier || rootHasAttachedSeries(handle.root) {
		registry.mu.Unlock()
		t.Fatal("fresh retirable state bypassed the older route-publication barrier")
	}

	registry.syncRootLocked(handle.flowID, handle.root)
	retired := handle.root.retired.Load()
	_, stillLive := registry.roots[handle.flowID]
	registry.mu.Unlock()
	if !retired || stillLive {
		t.Fatal("proof-faulted root was not retired after an inclusive barrier")
	}
	snapshot := registry.Snapshot()
	record := snapshot.Records[0]
	series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted)
	if record.CompletionState != CompletionIndeterminate || len(record.Route.KnownHandlerChain) != 2 || testObservation(t, record.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 1 || series.CumulativeBytes.Value != 1 || series.ActiveFlowCount.Value != 0 {
		t.Fatalf("indeterminate retirement lost a late child receipt: record=%+v series=%+v", record, series)
	}
}

func TestEventPaginationAndGapCoordinates(t *testing.T) {
	registry := newTestRegistry(t, 4, 4, 64)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddUplink(1)
	terminalize(handle)
	wantThrough := registry.Snapshot().Watermark
	var after uint64
	var delivered []uint64
	for after < wantThrough {
		batch := registry.EventsAfter(after, 1)
		if len(batch.Events) != 1 || batch.RequestedAfterSequence != after || batch.DeliveredThroughSequence != batch.Events[0].Sequence || batch.AvailableThroughSequence != wantThrough {
			t.Fatalf("invalid one-event page: %+v", batch)
		}
		delivered = append(delivered, batch.Events[0].Sequence)
		after = batch.DeliveredThroughSequence
	}
	for index, sequence := range delivered {
		if sequence != uint64(index+1) {
			t.Fatalf("event sequence lost or duplicated: %v", delivered)
		}
	}

	small := newTestRegistry(t, 2, 2, 3)
	h := small.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(h, "out")
	terminalize(h)
	batch := small.EventsAfter(0, 3)
	if !batch.ResyncRequired || batch.GapReason != EventGapRetentionExceeded || batch.DeliveredThroughSequence != batch.AvailableThroughSequence {
		t.Fatalf("retention gap lacks resync coordinates: %+v", batch)
	}
	if small.Snapshot().CounterSeries[0].State != SeriesStateContinuous {
		t.Fatal("event retention corrupted counter continuity")
	}
}

func TestEventRingRetentionPreservesLogicalOrder(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 3)
	for index := 0; index < 6; index++ {
		registry.mu.Lock()
		registry.appendEventLocked(Event{Type: EventUpdated})
		registry.mu.Unlock()
	}
	batch := registry.EventsAfter(0, 3)
	if !batch.ResyncRequired || batch.GapReason != EventGapRetentionExceeded || len(batch.Events) != 3 {
		t.Fatalf("full event ring did not expose retained gap: %+v", batch)
	}
	for index, event := range batch.Events {
		if event.Sequence != uint64(index+4) {
			t.Fatalf("event ring order corrupted: %+v", batch.Events)
		}
	}
}

func TestSnapshotWatermarkResynchronizesLaterEvents(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	baseline := registry.Snapshot()
	selectTestRoot(handle, "out")
	handle.AddUplink(7)
	batch := registry.EventsAfter(baseline.Watermark, 32)
	if batch.ResyncRequired || len(batch.Events) == 0 {
		t.Fatalf("events after authoritative watermark unavailable: %+v", batch)
	}
	for _, event := range batch.Events {
		if event.Sequence <= baseline.Watermark {
			t.Fatalf("event at or before snapshot watermark redelivered: %+v", event)
		}
	}
	resynchronized := registry.Snapshot()
	if testSeries(t, resynchronized.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).CumulativeBytes != (OptionalUint64{Known: true, Value: 7}) || resynchronized.Watermark != batch.AvailableThroughSequence {
		t.Fatalf("snapshot/event resynchronization coordinates disagree: snapshot=%+v batch=%+v", resynchronized, batch)
	}
}

func TestHandlerReturnIsNotTerminalAndLateBytesAreCounted(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	record := registry.Snapshot().Records[0]
	if record.CompletionState != CompletionIndeterminate || record.IndeterminateReason != IndeterminateHandlerReturnedUnproven {
		t.Fatalf("handler return was treated as terminal: %+v", record)
	}
	handle.AddDownlink(9)
	if got := testObservation(t, registry.Snapshot().Records[0].ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes; got != (OptionalUint64{Known: true, Value: 9}) {
		t.Fatalf("late bytes were lost: %+v", got)
	}
	handle.UplinkQuiesced()
	if registry.Snapshot().Records[0].CompletionState == CompletionTerminal {
		t.Fatal("one-sided close proved terminal")
	}
	handle.DownlinkQuiesced()
	record = registry.Snapshot().Records[0]
	if record.CompletionState != CompletionTerminal || record.CompletionEvidence != CompletionEvidenceRootLogicalLinkQuiesced || record.TerminalClass != TerminalClassCompleted {
		t.Fatalf("root quiescence did not terminalize exactly: %+v", record)
	}
}

func TestCancellationAndRuntimeCloseRemainIndeterminate(t *testing.T) {
	if got, want := IndeterminateRuntimeStopped, IndeterminateReason("RUNTIME_STOPPED_BEFORE_PROOF"); got != want {
		t.Fatalf("runtime-stop reason = %q, want canonical F1 value %q", got, want)
	}
	registry := newTestRegistry(t, 2, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handle.HandlerReturned(ctx, "tcp:a:1")
	if got := registry.Snapshot().Records[0]; got.CompletionState != CompletionIndeterminate || got.IndeterminateReason != IndeterminateCancellationRequested {
		t.Fatalf("cancellation request fabricated completion: %+v", got)
	}
	second := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(second, "out")
	registry.Close()
	for _, record := range registry.Snapshot().Records {
		if record.CompletionState == CompletionTerminal || record.IndeterminateReason != IndeterminateRuntimeStopped {
			t.Fatalf("runtime close fabricated terminal: %+v", record)
		}
	}
}

func TestSnapshotAndEventPreserveExactLifecycleFaultReason(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	baseline := registry.Snapshot()

	handle.LogicalRoot().markLifecycleFault(LifecycleFaultLateParticipantAcquire)
	snapshot := registry.Snapshot()
	want := IndeterminateReason(LifecycleFaultLateParticipantAcquire)
	if got := snapshot.Records[0]; got.CompletionState != CompletionIndeterminate || got.IndeterminateReason != want {
		t.Fatalf("snapshot collapsed exact lifecycle fault: got %+v want reason %q", got, want)
	}

	batch := registry.EventsAfter(baseline.Watermark, 32)
	found := false
	for _, event := range batch.Events {
		if event.Type == EventUpdated && event.Record != nil && event.Record.FlowID == handle.flowID && event.Record.IndeterminateReason == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("events after %d did not preserve lifecycle fault %q: %+v", baseline.Watermark, want, batch)
	}
}

func TestLocalRejectionIsTerminalBeforeInvocation(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	handle.Rejected("MISSING_HANDLER")
	record := registry.Snapshot().Records[0]
	if record.CompletionState != CompletionTerminal || record.CompletionEvidence != CompletionEvidenceLocalRejectionBeforeInvoke || record.TerminalClass != TerminalClassLocalRejection {
		t.Fatalf("local rejection was not proven: %+v", record)
	}
}

func TestOwnedLinkRejectionWaitsForAcceptedCallbacks(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	handle.TrackOwnedRootLink()
	handle.Rejected("MISSING_HANDLER")
	handle.AddUplink(5)
	if record := registry.Snapshot().Records[0]; record.CompletionState == CompletionTerminal || testObservation(t, record.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes != (OptionalUint64{Known: true, Value: 5}) {
		t.Fatalf("rejection raced ahead of accepted bytes: %+v", record)
	}
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	record := registry.Snapshot().Records[0]
	if record.CompletionState != CompletionTerminal || record.CompletionEvidence != CompletionEvidenceLocalRejectionBeforeInvoke || testObservation(t, record.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 5 {
		t.Fatalf("owned-link rejection did not wait for quiescence: %+v", record)
	}
}

func TestHandlerChainIsBoundedAndRootSelectionImmutable(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 128)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("rule", "root", "root-type", "tcp:a:1", "", true, CarrierProofNotApplicable)
	handle.SelectRoot("other", "replacement", "other-type", "tcp:b:1", "", true, CarrierProofNotApplicable)
	handle.BeginRedispatch("next", "next-type", "next-rule", true, CarrierProofUnknown)
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	handle.RecordDialerProxy("root", "cycle")
	handle.BeginRedispatch("later", "later-type", "", true, CarrierProofNotApplicable)
	record := registry.Snapshot().Records[0]
	if record.Route.SelectedTopLevelOutboundTag != "root" || record.Route.MatchedNativeRuleTag != "rule" || len(record.Route.KnownHandlerChain) != 2 || record.Route.KnownHandlerChain[1].EntryKind != HandlerEntryLoopbackRedispatch || record.Route.ChainDisposition != ChainDispositionCycleDetected || record.CarrierProof != CarrierProofUnknown {
		t.Fatalf("root or cycle chain invariant failed: %+v", record.Route)
	}

	depth := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(depth, "hop-0")
	for index := 1; index <= 16; index++ {
		depth.RecordDialerProxy("hop-"+encodeUint64(uint64(index)), "type")
	}
	record = registry.Snapshot().Records[1]
	if len(record.Route.KnownHandlerChain) != maxHandlerHops || record.Route.ChainDisposition != ChainDispositionDepthExceeded {
		t.Fatalf("chain depth was not bounded: %+v", record.Route)
	}
}

func TestConcurrentUpdatesSnapshotsAndTerminalTransition(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 512)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	const workers, iterations = 32, 100
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for index := 0; index < iterations; index++ {
				handle.AddUplink(1)
				handle.AddDownlink(2)
				_ = registry.Snapshot()
				_ = registry.EventsAfter(0, 7)
			}
		}()
	}
	waitGroup.Wait()
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	if registry.Snapshot().Records[0].CompletionState == CompletionTerminal {
		t.Fatal("quiesced directions terminalized while dispatcher invocation was active")
	}
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	handle.DownlinkQuiesced()
	handle.AddUplink(1)
	record := registry.Snapshot().Records[0]
	if testObservation(t, record.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != workers*iterations || testObservation(t, record.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != workers*iterations*2 || record.CompletionState != CompletionTerminal {
		t.Fatalf("concurrent state lost: %+v", record)
	}
	terminalEvents := 0
	for _, event := range registry.EventsAfter(0, 512).Events {
		if event.Type == EventTerminal {
			terminalEvents++
		}
	}
	if terminalEvents != 1 {
		t.Fatalf("got %d terminal events, want 1", terminalEvents)
	}
}

func TestByteHotPathNeverWaitsForRegistryMutex(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	registry.mu.Lock()
	done := make(chan struct{})
	go func() {
		handle.AddUplink(7)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		registry.mu.Unlock()
		t.Fatal("byte update waited for registry mutex")
	}
	registry.mu.Unlock()
	if got := testSeries(t, registry.Snapshot().CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).CumulativeBytes; got != (OptionalUint64{Known: true, Value: 7}) {
		t.Fatalf("non-blocking byte update was not published: %+v", got)
	}
}

func TestAdmissionContentionFailsOpenAndPublishesTypedCoverageLoss(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 32)
	registry.mu.Lock()
	result := make(chan *Handle, 1)
	go func() {
		result <- registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	}()
	select {
	case handle := <-result:
		if handle == nil {
			registry.mu.Unlock()
			t.Fatal("bounded pending queue rejected its first contended admission")
		}
	case <-time.After(time.Second):
		registry.mu.Unlock()
		t.Fatal("contended telemetry admission blocked the stock traffic path")
	}
	if handle := registry.AdmitTCP(context.Background(), "", "tcp:b:1", "", ByteScopeLogicalLinkAccepted); handle != nil {
		registry.mu.Unlock()
		t.Fatal("exhausted pending queue admitted an unbounded root")
	}
	registry.mu.Unlock()

	snapshot := registry.Snapshot()
	if snapshot.DroppedFlowCount != 1 || snapshot.AccountingCoverage.State != AccountingCoverageIndeterminate || snapshot.AccountingCoverage.Reason != DiscontinuityAdmissionContention || len(snapshot.Records) != 1 {
		t.Fatalf("contended admission loss was not published exactly: %+v", snapshot)
	}
	events := registry.EventsAfter(0, 32)
	discontinuities := 0
	for _, event := range events.Events {
		if event.Type == EventCoverageDiscontinuity && event.Reason == DiscontinuityAdmissionContention {
			discontinuities++
		}
	}
	if discontinuities != 1 {
		t.Fatalf("got %d admission-contention discontinuities, want 1: %+v", discontinuities, events)
	}
}

func TestConcurrentAdmissionContentionReceiptIsBoundedAndSaturating(t *testing.T) {
	const attempts = 128
	registry := newTestRegistry(t, 2, 2, 32)
	registry.mu.Lock()
	var wait sync.WaitGroup
	var accepted atomic.Uint64
	wait.Add(attempts)
	for index := 0; index < attempts; index++ {
		go func() {
			defer wait.Done()
			if handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted); handle != nil {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 2 {
		registry.mu.Unlock()
		t.Fatalf("bounded queue accepted %d roots, want 2", accepted.Load())
	}
	if got := registry.pendingAdmissionDrops.Load(); got != attempts-2 {
		registry.mu.Unlock()
		t.Fatalf("pending admission receipt=%d, want %d", got, attempts-2)
	}
	registry.pendingAdmissionDrops.Store(math.MaxUint64)
	registry.applyPendingAdmissionLossLocked()
	if registry.droppedFlows != math.MaxUint64 || registry.pendingAdmissionDrops.Load() != 0 {
		registry.mu.Unlock()
		t.Fatalf("admission loss counters wrapped: dropped=%d pending=%d", registry.droppedFlows, registry.pendingAdmissionDrops.Load())
	}
	registry.mu.Unlock()
}

func TestAdmissionIdentityExhaustionKeepsCapacityReasonExact(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 16)
	registry.nextFlow.Store(math.MaxUint64)
	if handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted); handle != nil {
		t.Fatal("exhausted flow identity admitted a root")
	}
	snapshot := registry.Snapshot()
	if snapshot.DroppedFlowCount != 1 || snapshot.AccountingCoverage.State != AccountingCoverageIndeterminate || snapshot.AccountingCoverage.Reason != DiscontinuityAccountingCapacityExceeded {
		t.Fatalf("identity exhaustion was mislabeled as contention: %+v", snapshot)
	}
}

func TestPendingAdmissionRetainsLifecycleReceiptsBeforeRegistryDrain(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 32)
	registry.mu.Lock()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	if handle == nil {
		registry.mu.Unlock()
		t.Fatal("pending admission failed")
	}
	selectTestRoot(handle, "out")
	handle.AddUplink(3)
	handle.AddDownlink(5)
	terminalize(handle)
	if len(registry.records) != 0 || len(registry.pendingAdmissions) != 1 {
		registry.mu.Unlock()
		t.Fatal("contended admission was not isolated in the bounded pending queue")
	}
	registry.mu.Unlock()

	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].CompletionState != CompletionTerminal || snapshot.DroppedFlowCount != 0 || snapshot.AccountingCoverage.State != AccountingCoverageComplete {
		t.Fatalf("pending admission did not publish exactly after drain: %+v", snapshot)
	}
	if testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).CumulativeBytes.Value != 3 || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted).CumulativeBytes.Value != 5 {
		t.Fatalf("pending admission lost lifecycle bytes: %+v", snapshot.CounterSeries)
	}
}

func TestRegistryCloseDrainsAdmissionThatWonBeforeCloseBarrier(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 32)
	registry.mu.Lock()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	if handle == nil {
		registry.mu.Unlock()
		t.Fatal("pending admission failed")
	}
	closed := make(chan struct{})
	go func() {
		registry.Close()
		close(closed)
	}()
	select {
	case <-closed:
		registry.mu.Unlock()
		t.Fatal("registry close bypassed the held registry publication lock")
	case <-time.After(10 * time.Millisecond):
	}
	registry.mu.Unlock()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("registry close did not drain the pending admission")
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].CompletionState != CompletionIndeterminate || snapshot.Records[0].IndeterminateReason != IndeterminateRuntimeStopped || snapshot.DroppedFlowCount != 0 {
		t.Fatalf("close lost or fabricated the pending admission: %+v", snapshot)
	}
}

func TestSeriesBindingAppliesPreSelectionAndConcurrentBytesExactlyOnce(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	registry.mu.Lock()
	handle.AddUplink(5)
	selectTestRoot(handle, "out")
	handle.AddUplink(7)
	registry.mu.Unlock()
	snapshot := registry.Snapshot()
	if len(snapshot.CounterSeries) != 2 || testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted).CumulativeBytes != (OptionalUint64{Known: true, Value: 12}) {
		t.Fatalf("series cut-over lost or duplicated bytes: %+v", snapshot.CounterSeries)
	}
}

func TestDirtyWorkerPublishesWithoutObserverPolling(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddDownlink(9)
	deadline := time.Now().Add(time.Second)
	for {
		registry.mu.Lock()
		published := testObservation(t, registry.records[handle.flowID].record.ByteObservations, DirectionDownlink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value == 9
		registry.mu.Unlock()
		if published {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dirty worker did not publish root delta")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLateProducerAfterRegistryCloseCannotBlockOrPanic(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	registry.Close()
	handle.AddUplink(3)
	record := registry.Snapshot().Records[0]
	if record.CompletionState == CompletionTerminal || record.IndeterminateReason != IndeterminateRuntimeStopped || testObservation(t, record.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes != (OptionalUint64{Known: true, Value: 3}) {
		t.Fatalf("late producer after close was lost or fabricated terminal: %+v", record)
	}
}

func TestRegistryClosePreservesTerminalProofCompletedBeforeStop(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	registry.mu.Lock()
	// Hold structural publication while the root completes, then execute the
	// same shutdown boundary and sync under that lock deterministically.
	handle.root.logical.dirtySignal = nil
	selectTestRoot(handle, "out")
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseTerminal {
		registry.mu.Unlock()
		t.Fatalf("logical proof did not complete before runtime stop: %+v", view)
	}
	if state := registry.records[handle.flowID].record.CompletionState; state == CompletionTerminal {
		registry.mu.Unlock()
		t.Fatal("test did not retain an unsynchronized terminal receipt")
	}
	registry.stopLifecycleSequence = registry.lifecycleSequence.Add(1)
	registry.closed = true
	registry.syncAllLocked()
	registry.mu.Unlock()

	record := registry.Snapshot().Records[0]
	if record.CompletionState != CompletionTerminal || record.IndeterminateReason != "" {
		t.Fatalf("runtime stop lost earlier terminal proof: %+v", record)
	}
}

func TestRuntimeAndFlowIDsAreUnique(t *testing.T) {
	first := newTestRegistry(t, 1, 1, 8)
	second := newTestRegistry(t, 1, 1, 8)
	firstHandle := first.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	secondHandle := second.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	if first.Snapshot().RuntimeInstanceID == second.Snapshot().RuntimeInstanceID || firstHandle.flowID == secondHandle.flowID || first.Owns(secondHandle) {
		t.Fatal("runtime ownership or identity was reused")
	}
}

func TestSubmittedErrorsAreSanitizedPendingFacts(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.SubmitError(errors.New("secret endpoint and credential"))
	handle.HandlerReturned(context.Background(), "tcp:a:1")
	record := registry.Snapshot().Records[0]
	if record.CompletionState == CompletionTerminal || record.TechnicalErrorCategory != "" {
		t.Fatalf("pending error became terminal fact: %+v", record)
	}
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	record = registry.Snapshot().Records[0]
	if record.TechnicalErrorCategory != "OUTBOUND_ERROR" {
		t.Fatalf("error category was not bounded: %+v", record)
	}
}

func TestLateParticipantErrorOverridesCompletedOwnerOutcome(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 16)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	participant := handle.LogicalRoot().AcquireParticipant()
	if participant == nil {
		t.Fatal("late participant was not acquired before owner seal")
	}

	handle.HandlerReturned(context.Background(), "tcp:a:1")
	if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseOwnerSealed || view.LiveParticipantCount != 1 {
		t.Fatalf("owner seal did not retain late participant: %+v", view)
	}
	SubmitErrorFromContext(ContextWithHandle(context.Background(), handle), errors.New("late outbound failure"))
	participant.Release(nil)
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	record := registry.Snapshot().Records[0]
	if record.CompletionState != CompletionTerminal || record.TerminalClass != TerminalClassLocalError || record.TechnicalErrorCategory != "OUTBOUND_ERROR" {
		t.Fatalf("late participant error did not override completed owner outcome: %+v", record)
	}
}

func newTestRegistry(t *testing.T, maxRecords, maxSeries, maxEvents int) *Registry {
	t.Helper()
	registry, err := NewRegistry(Config{MaxRecords: maxRecords, MaxSeries: maxSeries * 2, MaxEvents: maxEvents})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)
	return registry
}

func selectTestRoot(handle *Handle, outbound string) {
	handle.SelectRoot("", outbound, "type", "tcp:a:1", "", true, CarrierProofNotApplicable)
}

func terminalize(handle *Handle) {
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	handle.HandlerReturned(context.Background(), "tcp:a:1")
}

func testObservation(t testing.TB, observations []ByteObservation, direction Direction, scope ByteScope) ByteObservation {
	t.Helper()
	for _, observation := range observations {
		if observation.Direction == direction && observation.ByteScope == scope {
			return observation
		}
	}
	t.Fatalf("missing byte observation direction=%s scope=%s in %+v", direction, scope, observations)
	return ByteObservation{}
}

func testSeries(t testing.TB, series []CounterSeries, direction Direction, scope ByteScope) CounterSeries {
	t.Helper()
	for _, candidate := range series {
		if candidate.Key.Direction == direction && candidate.Key.ByteScope == scope {
			return candidate
		}
	}
	t.Fatalf("missing counter series direction=%s scope=%s in %+v", direction, scope, series)
	return CounterSeries{}
}

func BenchmarkActiveFlowByteUpdate(b *testing.B) {
	registry, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 2, MaxEvents: 4})
	if err != nil {
		b.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeLogicalLinkAccepted)
	selectTestRoot(handle, "out")
	handle.AddUplink(1)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		handle.AddUplink(1)
	}
}

func BenchmarkUDPAssociationByteUpdate(b *testing.B) {
	registry, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 2, MaxEvents: 4})
	if err != nil {
		b.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitUDPAssociation(context.Background(), "", "udp:a:1", "")
	selectTestRoot(handle, "out")
	handle.AddUplink(1)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		handle.AddUplink(1)
	}
}

func BenchmarkFullEventRetentionAppend(b *testing.B) {
	registry, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: defaultMaxEvents})
	if err != nil {
		b.Fatal(err)
	}
	defer registry.Close()
	registry.mu.Lock()
	for index := 0; index < defaultMaxEvents; index++ {
		registry.appendEventLocked(Event{Type: EventUpdated})
	}
	registry.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		registry.mu.Lock()
		registry.appendEventLocked(Event{Type: EventUpdated})
		registry.mu.Unlock()
	}
}
