package flow

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestClientCarrierReferenceExhaustionIsKindLocal(t *testing.T) {
	r := newTestRegistry(t, 2, 2, 32)
	if handle := r.AdmitTCP(context.Background(), "", "tcp:client-exhaust.example:443", "", ByteScopeLogicalLinkAccepted); handle == nil {
		t.Fatal("missing logical flow before client carrier exhaustion")
	}
	r.nextCarrier.Store(math.MaxUint64)
	if capability := r.NewMuxClientCarrierObservation(); capability != nil {
		t.Fatalf("client carrier reference exhaustion admitted capability: %T", capability)
	}
	snapshot := r.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.DroppedFlowCount != 0 || snapshot.AccountingCoverage.State != AccountingCoverageComplete || snapshot.DroppedCarrierObservationCount != 1 {
		t.Fatalf("client carrier exhaustion crossed flow accounting: %+v", snapshot)
	}
	for _, coverage := range snapshot.CarrierAccountingCoverage {
		wantIndeterminate := coverage.Key.CarrierKind == CarrierKindClientMuxFrameLink
		if (coverage.State == AccountingCoverageIndeterminate) != wantIndeterminate {
			t.Fatalf("client carrier exhaustion crossed kind: %+v", snapshot.CarrierAccountingCoverage)
		}
	}
}

func TestClientMuxCarrierProvisionalCommitAndExactDirections(t *testing.T) {
	r := newTestRegistry(t, 4, 4, 64)
	capability := r.NewMuxClientCarrierObservation().(*MuxClientCarrier)
	frame := capability.ClientFrameObservation()
	frame.Read(13)
	frame.Write(17, nil)
	if snapshot := r.Snapshot(); len(snapshot.CarrierRecords) != 0 {
		t.Fatalf("provisional callbacks published carrier detail: %+v", snapshot.CarrierRecords)
	}

	frame.Commit()
	frame.Read(13)
	frame.Write(17, nil)
	snapshot := r.Snapshot()
	if len(snapshot.CarrierRecords) != 1 || snapshot.CarrierRecords[0].CarrierKind != CarrierKindClientMuxFrameLink {
		t.Fatalf("client carrier was not committed exactly once: %+v", snapshot.CarrierRecords)
	}
	record := snapshot.CarrierRecords[0]
	if got := carrierObservationForTest(t, record, DirectionUplink); !got.ObservedBytes.Known || got.ObservedBytes.Value != 17 {
		t.Fatalf("client uplink boundary mismatch: %+v", got)
	}
	if got := carrierObservationForTest(t, record, DirectionDownlink); !got.ObservedBytes.Known || got.ObservedBytes.Value != 13 {
		t.Fatalf("client downlink boundary mismatch: %+v", got)
	}
	if len(snapshot.CarrierAccountingCoverage) != 4 || len(snapshot.CarrierCounterSeries) != 2 {
		t.Fatalf("carrier domain was not keyed as four coverage cells with lazy client series: %+v", snapshot)
	}
	frame.WorkerQuiesced()
	if terminal := r.Snapshot().CarrierRecords[0]; terminal.CompletionState != CompletionTerminal || terminal.TerminalClass != "" {
		t.Fatalf("full worker receipt did not terminalize client sidecar: %+v", terminal)
	}
}

func TestClientMuxCarrierAbortPublishesNoFictitiousRecord(t *testing.T) {
	r := newTestRegistry(t, 2, 2, 32)
	capability := r.NewMuxClientCarrierObservation().(*MuxClientCarrier)
	frame := capability.ClientFrameObservation()
	frame.Abort()
	frame.Commit()
	frame.Read(9)
	frame.Write(11, nil)
	frame.WorkerQuiesced()
	snapshot := r.Snapshot()
	if len(snapshot.CarrierRecords) != 0 || snapshot.DroppedCarrierObservationCount != 0 {
		t.Fatalf("aborted provisional sidecar fabricated accounting: %+v", snapshot)
	}
}

func TestClientMuxCarrierWriteErrorInvalidatesOnlyClientUplink(t *testing.T) {
	r := newTestRegistry(t, 2, 2, 32)
	frame := r.NewMuxClientCarrierObservation().(*MuxClientCarrier).ClientFrameObservation()
	frame.Commit()
	frame.Read(7)
	frame.Write(19, errors.New("unknown prefix"))
	snapshot := r.Snapshot()
	record := snapshot.CarrierRecords[0]
	uplink := carrierObservationForTest(t, record, DirectionUplink)
	downlink := carrierObservationForTest(t, record, DirectionDownlink)
	if uplink.State != ByteObservationStateIndeterminate || uplink.ObservedBytes.Known || uplink.AccountingFault != AccountingFaultBoundaryUnproven {
		t.Fatalf("client uplink error was not fail-closed: %+v", uplink)
	}
	if downlink.State != ByteObservationStateProven || !downlink.ObservedBytes.Known || downlink.ObservedBytes.Value != 7 {
		t.Fatalf("client downlink was contaminated by uplink error: %+v", downlink)
	}
	for _, coverage := range snapshot.CarrierAccountingCoverage {
		wantIndeterminate := coverage.Key.CarrierKind == CarrierKindClientMuxFrameLink && coverage.Key.Direction == DirectionUplink
		if (coverage.State == AccountingCoverageIndeterminate) != wantIndeterminate {
			t.Fatalf("coverage loss crossed exact key: %+v", snapshot.CarrierAccountingCoverage)
		}
	}
}

func TestClientQueueFullLossIsKindLocalAndKeepsSingleReference(t *testing.T) {
	r := newTestRegistry(t, 1, 2, 64)
	handle := r.AdmitTCP(context.Background(), "", "tcp:client.example:443", "", ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "mux-out", "handler", "tcp:client.example:443", "", true, CarrierProofUnknown, IssueMuxCarrierF2Required)
	ctx := ContextWithHandle(context.Background(), handle)
	scope := session.MuxClientSessionObservationFromContext(ContextWithMuxClientSessionObservation(ctx, "mux-out"))
	if scope == nil {
		t.Fatal("selected outbound scope missing")
	}
	capability := r.NewMuxClientCarrierObservation().(*MuxClientCarrier)

	r.mu.Lock()
	r.pendingCarriers <- &carrierSidecar{r: r, ref: "queued-server", kind: CarrierKindServerMuxFrameLink, state: carrierCommitted}
	capability.ClientFrameObservation().Commit()
	r.mu.Unlock()
	capability.AttachTo(scope)

	snapshot := r.Snapshot()
	if snapshot.DroppedCarrierObservationCount != 1 {
		t.Fatalf("queue-full client loss counted %d times", snapshot.DroppedCarrierObservationCount)
	}
	for _, coverage := range snapshot.CarrierAccountingCoverage {
		wantIndeterminate := coverage.Key.CarrierKind == CarrierKindClientMuxFrameLink
		if (coverage.State == AccountingCoverageIndeterminate) != wantIndeterminate {
			t.Fatalf("queue-full loss crossed carrier kind: %+v", snapshot.CarrierAccountingCoverage)
		}
	}
	record := muxRecordByID(t, snapshot, handle.flowID)
	if record.SelectedOutboundCarrierReference != capability.reference || len(snapshot.CarrierRecords) != 1 || snapshot.CarrierRecords[0].CarrierKind != CarrierKindServerMuxFrameLink {
		t.Fatalf("omission reminted correlation or changed shared detail: record=%+v carriers=%+v", record, snapshot.CarrierRecords)
	}
}
