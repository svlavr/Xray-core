package dns

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
)

type queryTracker struct {
	acquired atomic.Int32
	released atomic.Int32
}

func (t *queryTracker) AcquireParticipant() task.ParticipantLease {
	t.acquired.Add(1)
	return &queryLease{tracker: t}
}

type queryLease struct {
	tracker *queryTracker
}

func (l *queryLease) AcquireParticipant() task.ParticipantLease {
	return l.tracker.AcquireParticipant()
}

func (l *queryLease) Release(error) {
	l.tracker.released.Add(1)
}

func TestIPQueryWorkerReleasesFlowParticipantAfterActualReturn(t *testing.T) {
	tracker := new(queryTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	started := make(chan struct{})
	finish := make(chan struct{})
	new(Handler).startIPQueryWorker(ctx, func() {
		close(started)
		<-finish
	})

	<-started
	if tracker.acquired.Load() != 1 || tracker.released.Load() != 0 {
		t.Fatalf("got acquired=%d released=%d before query return, want 1/0", tracker.acquired.Load(), tracker.released.Load())
	}
	close(finish)
	deadline := time.After(time.Second)
	for tracker.released.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("query participant was not released after actual return")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestIPQueryWorkerWithoutFlowTrackerPreservesStockExecution(t *testing.T) {
	done := make(chan struct{})
	new(Handler).startIPQueryWorker(context.Background(), func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("untracked query did not preserve stock worker execution")
	}
}

func TestUDPIPQueryWorkerPreventsTerminalUntilActualReturn(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 2, MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitUDPAssociation(context.Background(), "", "udp:dns.example:53", "dns")
	if handle == nil {
		t.Fatal("UDP association admission failed")
	}
	ctx := flow_observation.ContextWithHandle(context.Background(), handle)
	started := make(chan struct{})
	finish := make(chan struct{})
	new(Handler).startIPQueryWorker(ctx, func() {
		close(started)
		<-finish
	})
	<-started

	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	handle.HandlerReturned(context.Background(), "udp:dns.example:53")
	view := handle.LogicalRoot().View()
	if view.Phase != flow_observation.LifecyclePhaseOwnerSealed || view.LiveParticipantCount != 1 || view.Terminal != nil {
		t.Fatalf("UDP association terminal overtook DNS query worker: %+v", view)
	}

	close(finish)
	deadline := time.Now().Add(time.Second)
	for {
		view = handle.LogicalRoot().View()
		if view.Phase == flow_observation.LifecyclePhaseTerminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP association did not terminalize after DNS worker exit: %+v", view)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestIPQueryWorkersConcurrentRelease(t *testing.T) {
	const workers = 1000
	tracker := new(queryTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	finish := make(chan struct{})
	var completed sync.WaitGroup
	completed.Add(workers)
	for range workers {
		new(Handler).startIPQueryWorker(ctx, func() {
			defer completed.Done()
			<-finish
		})
	}
	if tracker.acquired.Load() != workers || tracker.released.Load() != 0 {
		t.Fatalf("got acquired=%d released=%d before release, want %d/0", tracker.acquired.Load(), tracker.released.Load(), workers)
	}
	close(finish)
	completed.Wait()
	deadline := time.After(time.Second)
	for tracker.released.Load() != workers {
		select {
		case <-deadline:
			t.Fatalf("got %d releases, want %d", tracker.released.Load(), workers)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestIPQueryWorkerRetainsAndObservesExactGeneration(t *testing.T) {
	ledger := core.NewRetirementLedgerForValidation(1)
	generation, err := ledger.Register(new(int), "dns-out")
	if err != nil {
		t.Fatal(err)
	}
	root, ok := generation.AcquireRoot()
	if !ok {
		t.Fatal("failed to acquire generation root")
	}
	ctx := core.ContextWithRetirementRight(context.Background(), root)
	started := make(chan struct{})
	finished := make(chan struct{})
	new(Handler).startIPQueryWorkerContext(ctx, func(workerCtx context.Context) {
		if right := core.RetirementRightFromContext(workerCtx); right == nil || right.Generation() != generation {
			t.Errorf("worker lost exact handler generation: %v", right)
		}
		close(started)
		<-workerCtx.Done()
		close(finished)
	})
	<-started
	if err := ledger.ReserveRetirement(generation); err != nil {
		t.Fatal(err)
	}
	generation.Retire()
	root.Release()
	generation.ForceSeal()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("generation seal did not cancel DNS query continuation")
	}
	select {
	case <-generation.Drained():
	case <-time.After(time.Second):
		t.Fatal("DNS query continuation did not release generation hold")
	}
}
