package dispatcher

import (
	goerrors "errors"
	"sync"
	"testing"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features"
)

func TestDispatcherStagesClientCarrierReceiptBeforeObservationFinalization(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &DefaultDispatcher{flows: registry}
	shutdown, err := dispatcher.AdoptObservationShutdown()
	if err != nil {
		t.Fatal(err)
	}
	frame := session.MuxClientCarrierFrameObservationFromCarrier(registry.NewMuxClientCarrierObservation())
	if frame == nil {
		t.Fatal("client carrier has no frame observation")
	}
	frame.Commit()
	frame.Read(13)
	frame.Write(17, nil)

	if err := shutdown.JoinShutdown(); err != nil {
		t.Fatal(err)
	}
	if record := registry.Snapshot().CarrierRecords[0]; record.CompletionState != flow_observation.CompletionOpen {
		t.Fatalf("dispatcher join finalized observation early: %+v", record)
	}
	if err := dispatcher.Close(); !goerrors.Is(err, ErrObservationShutdownOwned) {
		t.Fatalf("managed direct Close error = %v, want owner-required", err)
	}
	if record := registry.Snapshot().CarrierRecords[0]; record.CompletionState != flow_observation.CompletionOpen {
		t.Fatalf("managed direct Close finalized observation: %+v", record)
	}
	frame.WorkerQuiesced()
	if err := shutdown.FinalizeObservation(); err != nil {
		t.Fatal(err)
	}
	record := registry.Snapshot().CarrierRecords[0]
	if record.CompletionState != flow_observation.CompletionTerminal || record.IndeterminateReason != "" {
		t.Fatalf("owner receipt was lost before observation finalization: %+v", record)
	}
	if err := dispatcher.Close(); err != nil {
		t.Fatalf("managed direct Close after final receipt = %v", err)
	}
}

func TestDispatcherStandaloneCloseWinsBeforeInstanceAdoption(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 8})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &DefaultDispatcher{flows: registry}
	frame := session.MuxClientCarrierFrameObservationFromCarrier(registry.NewMuxClientCarrierObservation())
	frame.Commit()
	if err := dispatcher.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatcher.AdoptObservationShutdown(); err == nil {
		t.Fatal("Instance adoption succeeded after standalone Close won")
	}
	if record := registry.Snapshot().CarrierRecords[0]; record.CompletionState != flow_observation.CompletionIndeterminate || record.IndeterminateReason != flow_observation.IndeterminateRuntimeStopped {
		t.Fatalf("standalone Close did not preserve fail-closed registry semantics: %+v", record)
	}
}

func TestDispatcherAdoptionAndStandaloneCloseHaveOneFinalizationOwner(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		dispatcher := new(DefaultDispatcher)
		start := make(chan struct{})
		var shutdown features.ObservationShutdown
		var adoptErr, closeErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			shutdown, adoptErr = dispatcher.AdoptObservationShutdown()
		}()
		go func() {
			defer wait.Done()
			<-start
			closeErr = dispatcher.Close()
		}()
		close(start)
		wait.Wait()

		switch {
		case adoptErr == nil:
			if !goerrors.Is(closeErr, ErrObservationShutdownOwned) {
				t.Fatalf("iteration %d: adopted Close error = %v", iteration, closeErr)
			}
			if err := shutdown.FinalizeObservation(); err != nil {
				t.Fatalf("iteration %d: finalization = %v", iteration, err)
			}
		case closeErr == nil:
			if adoptErr == nil {
				t.Fatalf("iteration %d: standalone Close and adoption both won", iteration)
			}
		default:
			t.Fatalf("iteration %d: neither owner completed: adopt=%v close=%v", iteration, adoptErr, closeErr)
		}
	}
}
