package flow

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

type externalTestReader struct {
	mu      sync.Mutex
	payload []byte
	err     error
}

func (r *externalTestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.payload == nil {
		return nil, r.err
	}
	payload := append([]byte(nil), r.payload...)
	r.payload = nil
	return buf.MultiBuffer{buf.FromBytes(payload)}, r.err
}

type externalTestWriter struct {
	started chan struct{}
	release chan struct{}
	err     error
	written uint64
	closed  bool
}

func (w *externalTestWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.started != nil {
		close(w.started)
	}
	if w.release != nil {
		<-w.release
	}
	w.written += uint64(mb.Len())
	buf.ReleaseMulti(mb)
	return w.err
}

func (w *externalTestWriter) Close() error {
	w.closed = true
	return nil
}

func bindExternalTestLink(t *testing.T, reader buf.Reader, writer buf.Writer) (*Registry, *ExternalOwnerScope, *Handle, *transport.Link) {
	t.Helper()
	registry := newTestRegistry(t, 2, 2, 64)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	ctx := ContextWithExternalOwnerScope(context.Background(), scope)
	link := &transport.Link{Reader: reader, Writer: writer}
	handle := registry.AdmitExternalTCP(ctx, "", "tcp:example.com:443", "", scope, link)
	if handle == nil {
		t.Fatal("external admission failed")
	}
	ctx = ContextWithHandle(ctx, handle)
	readLifecycle, bound := BindExternalLinkIO(ctx, link)
	if !bound || !scope.AccountingBound() {
		t.Fatal("external accounting boundary was not bound")
	}
	link.Reader = &buf.TimeoutWrapperReader{Reader: link.Reader, ReadLifecycle: readLifecycle}
	handle.SelectRoot("", "out", "type", "tcp:example.com:443", "", true, CarrierProofNotApplicable)
	return registry, scope, handle, link
}

func TestExternalLinkIOCountsReturnedReadAndSuccessfulWrite(t *testing.T) {
	reader := &externalTestReader{payload: []byte("uplink"), err: io.EOF}
	writer := new(externalTestWriter)
	registry, scope, handle, link := bindExternalTestLink(t, reader, writer)

	mb, err := link.Reader.ReadMultiBuffer()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got read error %v, want EOF", err)
	}
	buf.ReleaseMulti(mb)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("downlink"))}); err != nil {
		t.Fatal(err)
	}
	if err := link.Writer.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	scope.AfterOwnerClose(nil, nil)

	view := handle.LogicalRoot().View()
	if testObservation(t, view.ByteObservations, DirectionUplink, ByteScopeDispatcherExternalLinkIO).ObservedBytes.Value != uint64(len("uplink")) || testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).ObservedBytes.Value != uint64(len("downlink")) || view.Phase != LifecyclePhaseTerminal {
		t.Fatalf("unexpected external I/O view: %+v", view)
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || len(snapshot.CounterSeries) != 2 || testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeDispatcherExternalLinkIO).CumulativeBytes.Value != uint64(len("uplink")) || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).CumulativeBytes.Value != uint64(len("downlink")) {
		t.Fatalf("unexpected external I/O snapshot: %+v", snapshot)
	}
}

func TestExternalLinkWriteErrorMakesPartialAcceptanceUnknown(t *testing.T) {
	wantErr := errors.New("write failed")
	writer := &externalTestWriter{err: wantErr}
	registry, _, handle, link := bindExternalTestLink(t, &externalTestReader{}, writer)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("possibly partial"))}); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
	view := handle.LogicalRoot().View()
	if testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).ObservedBytes.Known || view.AccountingFault != AccountingFaultBoundaryUnproven {
		t.Fatalf("partial write error remained known: %+v", view)
	}
	snapshot := registry.Snapshot()
	if snapshot.AccountingCoverage.State != AccountingCoverageComplete || testObservation(t, snapshot.Records[0].ByteObservations, DirectionUplink, ByteScopeDispatcherExternalLinkIO).State != ByteObservationStateProven || testObservation(t, snapshot.Records[0].ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).State != ByteObservationStateIndeterminate || testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeDispatcherExternalLinkIO).State != SeriesStateContinuous || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).State != SeriesStateIndeterminate {
		t.Fatalf("partial write loss was not isolated to downlink coverage: %+v", snapshot)
	}
}

func TestExternalLinkOperationReservedBeforeOwnerSeal(t *testing.T) {
	writer := &externalTestWriter{started: make(chan struct{}), release: make(chan struct{})}
	_, scope, handle, link := bindExternalTestLink(t, &externalTestReader{}, writer)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("late"))})
	}()
	<-writer.started
	scope.AfterOwnerClose(nil, nil)
	if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseOwnerSealed || testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).ObservedBytes.Value != 0 {
		t.Fatalf("owner seal overtook reserved write or counted before success: %+v", view)
	}
	close(writer.release)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	view := handle.LogicalRoot().View()
	if view.Phase != LifecyclePhaseTerminal || testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).ObservedBytes.Value != uint64(len("late")) || view.LifecycleFault != "" {
		t.Fatalf("reserved write did not complete before terminal: %+v", view)
	}
}

func TestExternalLinkAccountingBindsExactLinkOnce(t *testing.T) {
	_, scope, _, link := bindExternalTestLink(t, &externalTestReader{}, new(externalTestWriter))
	ctx := ContextWithExternalOwnerScope(context.Background(), scope)
	ctx = ContextWithHandle(ctx, scope.Handle())
	if _, bound := BindExternalLinkIO(ctx, link); bound {
		t.Fatal("exact link received a second accounting wrapper")
	}
	foreign := &transport.Link{Reader: &externalTestReader{}, Writer: new(externalTestWriter)}
	if _, bound := BindExternalLinkIO(ctx, foreign); bound {
		t.Fatal("foreign link received external accounting")
	}
}

func TestByteTransactionMarksDirtyAfterCounterAndSequence(t *testing.T) {
	root := newTestRoot(t)
	root.addAcceptedBytes(DirectionUplink, byteScopeSlotLogicalLinkAccepted, 1)
	if root.ConsumeDirty() {
		t.Fatal("counter update published before byte sequence")
	}
	root.advanceByteSequence()
	if root.ConsumeDirty() {
		t.Fatal("sequence update published before byte transaction completion")
	}
	root.markDirty()
	if !root.ConsumeDirty() {
		t.Fatal("completed byte transaction was not published")
	}
	view := root.View()
	if testObservation(t, view.ByteObservations, DirectionUplink, ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 1 || view.LastByteSequence != 1 {
		t.Fatalf("incomplete byte transaction: %+v", view)
	}
}

func TestTerminalSyncAppliesRouteReceiptsAndBytesBeforeRetirement(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 64)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	ctx := ContextWithExternalOwnerScope(context.Background(), scope)
	link := &transport.Link{Reader: &externalTestReader{}, Writer: new(externalTestWriter)}
	handle := registry.AdmitExternalTCP(ctx, "", "tcp:example.com:443", "", scope, link)
	if handle == nil {
		t.Fatal("external admission failed")
	}

	registry.mu.Lock()
	ctx = ContextWithHandle(ctx, handle)
	readLifecycle, bound := BindExternalLinkIO(ctx, link)
	if !bound {
		registry.mu.Unlock()
		t.Fatal("external accounting boundary was not bound")
	}
	link.Reader = &buf.TimeoutWrapperReader{Reader: link.Reader, ReadLifecycle: readLifecycle}
	handle.SelectRoot("", "out", "type", "tcp:example.com:443", "", true, CarrierProofNotApplicable)
	handle.RecordDialerProxy("detour", "detour-type")
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte{'x'})}); err != nil {
		registry.mu.Unlock()
		t.Fatal(err)
	}
	scope.AfterOwnerClose(nil, nil)
	root := handle.root
	if root.selectionApplied || rootHasAttachedSeries(root) {
		registry.mu.Unlock()
		t.Fatalf("worker applied route facts before deterministic sync: selection=%t bindings=%+v", root.selectionApplied, root.observationBindings)
	}
	registry.syncRootLocked(handle.flowID, root)
	retired := root.retired.Load()
	_, stillLive := registry.roots[handle.flowID]
	registry.mu.Unlock()

	snapshot := registry.Snapshot()
	if !retired || stillLive || len(snapshot.Records) != 1 || len(snapshot.CounterSeries) != 2 {
		t.Fatalf("terminal root was not durably synchronized before retirement: %+v", snapshot)
	}
	record := snapshot.Records[0]
	series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO)
	if record.CompletionState != CompletionTerminal || testObservation(t, record.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).ObservedBytes != (OptionalUint64{Known: true, Value: 1}) || len(record.Route.KnownHandlerChain) != 2 {
		t.Fatalf("terminal route or byte receipt was lost: %+v", record)
	}
	if series.CumulativeBytes != (OptionalUint64{Known: true, Value: 1}) || series.ActiveFlowCount != (OptionalUint64{Known: true}) {
		t.Fatalf("terminal byte was not retained in the cumulative series: %+v", series)
	}
}

func TestOpenLifecycleBarrierCannotRetireNewlyTerminalRootWithoutRouteBinding(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 64)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	ctx := ContextWithExternalOwnerScope(context.Background(), scope)
	link := &transport.Link{Reader: &externalTestReader{}, Writer: new(externalTestWriter)}
	handle := registry.AdmitExternalTCP(ctx, "", "tcp:example.com:443", "", scope, link)
	if handle == nil {
		t.Fatal("external admission failed")
	}

	registry.mu.Lock()
	ctx = ContextWithHandle(ctx, handle)
	if _, bound := BindExternalLinkIO(ctx, link); !bound {
		registry.mu.Unlock()
		t.Fatal("external accounting boundary was not bound")
	}
	root := handle.root
	barrierView := root.logical.View()
	if barrierView.Phase != LifecyclePhaseOpen || registry.applySelectionLocked(root) {
		registry.mu.Unlock()
		t.Fatal("test did not establish the pre-receipt lifecycle barrier")
	}

	handle.SelectRoot("", "out", "type", "tcp:example.com:443", "", true, CarrierProofNotApplicable)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte{'x'})}); err != nil {
		registry.mu.Unlock()
		t.Fatal(err)
	}
	scope.AfterOwnerClose(nil, nil)
	accountingView := root.logical.View()
	if accountingView.Phase != LifecyclePhaseTerminal {
		registry.mu.Unlock()
		t.Fatalf("test root did not become terminal: %+v", accountingView)
	}
	registry.syncByteObservationsLocked(root, accountingView)
	registry.applyLifecycleBarrierLocked(handle.flowID, root, barrierView)
	_, stillLiveAfterOldBarrier := registry.roots[handle.flowID]
	if root.retired.Load() || !stillLiveAfterOldBarrier || rootHasAttachedSeries(root) {
		registry.mu.Unlock()
		t.Fatal("newer terminal state bypassed the older route-publication barrier")
	}

	registry.syncRootLocked(handle.flowID, root)
	retired := root.retired.Load()
	_, stillLive := registry.roots[handle.flowID]
	registry.mu.Unlock()
	if !retired || stillLive {
		t.Fatal("terminal root was not retired after a barrier that included its route receipt")
	}
	snapshot := registry.Snapshot()
	series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO)
	if series.CumulativeBytes != (OptionalUint64{Known: true, Value: 1}) || series.ActiveFlowCount != (OptionalUint64{Known: true}) {
		t.Fatalf("terminal byte was not retained after ordered route publication: %+v", series)
	}
}

func TestExternalLinkAccountingTwentyThousandSequentialFlows(t *testing.T) {
	const flowCount = 20_000
	registry := newTestRegistry(t, 64, 4, 64)
	for index := 0; index < flowCount; index++ {
		scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
		ctx := ContextWithExternalOwnerScope(context.Background(), scope)
		link := &transport.Link{Reader: &externalTestReader{}, Writer: new(externalTestWriter)}
		handle := registry.AdmitExternalTCP(ctx, "", "tcp:example.com:443", "", scope, link)
		if handle == nil {
			t.Fatalf("flow %d was not admitted", index)
		}
		ctx = ContextWithHandle(ctx, handle)
		readLifecycle, bound := BindExternalLinkIO(ctx, link)
		if !bound {
			t.Fatalf("flow %d accounting boundary was not bound", index)
		}
		link.Reader = &buf.TimeoutWrapperReader{Reader: link.Reader, ReadLifecycle: readLifecycle}
		handle.SelectRoot("", "out", "type", "tcp:example.com:443", "", true, CarrierProofNotApplicable)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte{'x'})}); err != nil {
			t.Fatalf("flow %d write failed: %v", index, err)
		}
		scope.AfterOwnerClose(nil, nil)
		if view := handle.LogicalRoot().View(); view.Phase != LifecyclePhaseTerminal || view.LifecycleFault != "" {
			t.Fatalf("flow %d did not terminalize cleanly: %+v", index, view)
		}
		if index%32 == 31 {
			snapshot := registry.Snapshot()
			if len(snapshot.CounterSeries) != 2 || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).CumulativeBytes != (OptionalUint64{Known: true, Value: uint64(index + 1)}) {
				t.Fatalf("flow %d lost cumulative accounting: %+v", index, snapshot.CounterSeries)
			}
		}
	}

	snapshot := registry.Snapshot()
	if snapshot.DroppedFlowCount != 0 || len(snapshot.Records) > 64 || len(snapshot.CounterSeries) != 2 {
		t.Fatalf("unexpected retention after stress: records=%d series=%d dropped=%d", len(snapshot.Records), len(snapshot.CounterSeries), snapshot.DroppedFlowCount)
	}
	series := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO)
	uplinkSeries := testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeDispatcherExternalLinkIO)
	if series.CumulativeBytes != (OptionalUint64{Known: true, Value: flowCount}) || uplinkSeries.CumulativeBytes != (OptionalUint64{Known: true}) || series.ActiveFlowCount != (OptionalUint64{Known: true}) {
		t.Fatalf("cumulative accounting changed across record eviction: %+v", series)
	}
}

func TestPendingExternalAdmissionBindsAndTerminalizesBeforeRegistryDrain(t *testing.T) {
	registry := newTestRegistry(t, 1, 2, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	ctx := ContextWithExternalOwnerScope(context.Background(), scope)
	link := &transport.Link{Reader: &externalTestReader{}, Writer: new(externalTestWriter)}
	registry.mu.Lock()
	handle := registry.AdmitExternalTCP(ctx, "", "tcp:example.com:443", "", scope, link)
	if handle == nil || scope.Handle() != handle || scope.Link() != link {
		registry.mu.Unlock()
		t.Fatal("pending external admission was not atomically claimed and bound")
	}
	ctx = ContextWithHandle(ctx, handle)
	if _, bound := BindExternalLinkIO(ctx, link); !bound {
		registry.mu.Unlock()
		t.Fatal("pending external admission did not bind exact-link accounting")
	}
	handle.SelectRoot("", "out", "type", "tcp:example.com:443", "", true, CarrierProofNotApplicable)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte{'x'})}); err != nil {
		registry.mu.Unlock()
		t.Fatal(err)
	}
	scope.AfterOwnerClose(nil, nil)
	if len(registry.records) != 0 || len(registry.pendingAdmissions) != 1 {
		registry.mu.Unlock()
		t.Fatal("external admission escaped pending isolation before registry drain")
	}
	registry.mu.Unlock()

	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].CompletionState != CompletionTerminal || testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeDispatcherExternalLinkIO).CumulativeBytes.Value != 1 || snapshot.DroppedFlowCount != 0 {
		t.Fatalf("pending external lifecycle was not published exactly: %+v", snapshot)
	}
}

func rootHasAttachedSeries(root *rootState) bool {
	for _, binding := range root.observationBindings {
		if binding.seriesID != "" {
			return true
		}
	}
	return false
}
