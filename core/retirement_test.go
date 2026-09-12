package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func mustRegisterRetirementGeneration(t testing.TB, ledger *RetirementLedger, tag string) *RetirementGeneration {
	t.Helper()
	generation, err := ledger.Register(new(struct{}), tag)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func TestRelease1RetirementCapacityDefault(t *testing.T) {
	ledger := newInstanceRetirementLedger()
	if ledger.capacity != 50 {
		t.Fatalf("Release-1 retirement capacity = %d, want source-validated upstream concurrency envelope 50", ledger.capacity)
	}
}

func TestRetirementLedgerReservationAndRelease(t *testing.T) {
	ledger := newRetirementLedger(1)
	first := mustRegisterRetirementGeneration(t, ledger, "first")
	second := mustRegisterRetirementGeneration(t, ledger, "second")
	if err := ledger.ReserveRetirement(first); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ReserveRetirement(second); err == nil {
		t.Fatal("second retirement unexpectedly admitted")
	} else {
		var exhausted *RetirementCapacityExhaustedError
		if !errors.As(err, &exhausted) || !exhausted.Temporary() {
			t.Fatalf("error = %T %[1]v, want retryable typed exhaustion", err)
		}
	}
	if second.Phase() != RetirementActive || ledger.RetainedCount() != 1 {
		t.Fatalf("failed reservation mutated second phase=%v used=%d", second.Phase(), ledger.RetainedCount())
	}
	first.Retire()
	<-first.Drained()
	first.Release()
	if ledger.RetainedCount() != 0 {
		t.Fatalf("released first still counted: %d", ledger.RetainedCount())
	}
	if err := ledger.ReserveRetirement(second); err != nil {
		t.Fatalf("retry after release: %v", err)
	}
	second.Retire()
	<-second.Drained()
	second.Release()
}

func TestRetirementContinuationRequiresLiveSourceRight(t *testing.T) {
	ledger := newRetirementLedger(1)
	generation := mustRegisterRetirementGeneration(t, ledger, "same")
	root, ok := generation.AcquireRoot()
	if !ok {
		t.Fatal("root not admitted")
	}
	if err := ledger.ReserveRetirement(generation); err != nil {
		t.Fatal(err)
	}
	continuation, ok := root.AcquireContinuation()
	if !ok {
		t.Fatal("continuation not admitted from live root")
	}
	root.Release()
	if _, ok := root.AcquireContinuation(); ok {
		t.Fatal("released root minted a continuation")
	}
	child, ok := continuation.AcquireContinuation()
	if !ok {
		t.Fatal("live continuation did not mint a flat child hold")
	}
	continuation.Release()
	if generation.Phase() != RetirementRetiring {
		t.Fatalf("phase with live child = %v, want RETIRING", generation.Phase())
	}
	child.Release()
	if generation.Phase() != RetirementDraining {
		t.Fatalf("phase after last child = %v, want DRAINING", generation.Phase())
	}
}

func TestRetirementEnterCrossGenerationAndSameGeneration(t *testing.T) {
	ledger := newRetirementLedger(2)
	source := mustRegisterRetirementGeneration(t, ledger, "source")
	target := mustRegisterRetirementGeneration(t, ledger, "target")
	sourceRoot, ok := source.AcquireRoot()
	if !ok {
		t.Fatal("source root not admitted")
	}
	sourceCtx := ContextWithRetirementRight(context.Background(), sourceRoot)
	enteredCtx, entered, err := EnterRetirement(sourceCtx, target)
	if err != nil {
		t.Fatal(err)
	}
	if got := RetirementRightFromContext(enteredCtx); got == nil || got.Generation() != target {
		t.Fatal("entered context did not carry exact target right")
	}
	sameCtx, same, err := EnterRetirement(enteredCtx, target)
	if err != nil {
		t.Fatal(err)
	}
	if got := RetirementRightFromContext(sameCtx); got == nil || got.Generation() != target {
		t.Fatal("same-generation Enter did not carry continuation")
	}
	if err := ledger.ReserveRetirement(target); err != nil {
		t.Fatal(err)
	}
	same.Release()
	entered.Release()
	sourceRoot.Release()
	if target.Phase() != RetirementDraining {
		t.Fatalf("target phase = %v, want DRAINING", target.Phase())
	}
	target.Release()
	if err := ledger.ReserveRetirement(source); err != nil {
		t.Fatal(err)
	}
	source.Retire()
	<-source.Drained()
	source.Release()
}

func TestRetirementEnterLinearizesWithSeal(t *testing.T) {
	for range 1000 {
		ledger := newRetirementLedger(1)
		target := mustRegisterRetirementGeneration(t, ledger, "target")
		start := make(chan struct{})
		var wg sync.WaitGroup
		var task *RetirementTask
		var enterErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, task, enterErr = EnterRetirement(context.Background(), target)
		}()
		go func() {
			defer wg.Done()
			<-start
			ledger.SealAndSnapshot()
		}()
		close(start)
		wg.Wait()
		if enterErr == nil {
			task.Release()
		}
		<-target.Drained()
		target.Release()
		ledger.Wait()
	}
}

func TestRetirementEnterLinearizesWithSourceRelease(t *testing.T) {
	for range 1000 {
		ledger := newRetirementLedger(2)
		source := mustRegisterRetirementGeneration(t, ledger, "source")
		target := mustRegisterRetirementGeneration(t, ledger, "target")
		sourceRoot, ok := source.AcquireRoot()
		if !ok {
			t.Fatal("source root not admitted")
		}
		ctx := ContextWithRetirementRight(context.Background(), sourceRoot)
		start := make(chan struct{})
		result := make(chan *RetirementTask, 1)
		go func() {
			<-start
			_, task, _ := EnterRetirement(ctx, target)
			result <- task
		}()
		go func() {
			<-start
			sourceRoot.Release()
		}()
		close(start)
		if task := <-result; task != nil {
			task.Release()
		}
		if err := ledger.ReserveRetirement(source); err != nil {
			t.Fatal(err)
		}
		if err := ledger.ReserveRetirement(target); err != nil {
			t.Fatal(err)
		}
		source.Retire()
		target.Retire()
		<-source.Drained()
		<-target.Drained()
		source.Release()
		target.Release()
	}
}

func TestRetirementOppositeCrossGenerationEnterHasNoLockCycle(t *testing.T) {
	ledger := newRetirementLedger(2)
	left := mustRegisterRetirementGeneration(t, ledger, "left")
	right := mustRegisterRetirementGeneration(t, ledger, "right")
	leftRoot, ok := left.AcquireRoot()
	if !ok {
		t.Fatal("left root not admitted")
	}
	rightRoot, ok := right.AcquireRoot()
	if !ok {
		t.Fatal("right root not admitted")
	}
	start := make(chan struct{})
	results := make(chan *RetirementTask, 2)
	for _, input := range []struct {
		ctx    context.Context
		target *RetirementGeneration
	}{
		{ContextWithRetirementRight(context.Background(), leftRoot), right},
		{ContextWithRetirementRight(context.Background(), rightRoot), left},
	} {
		go func() {
			<-start
			_, task, err := EnterRetirement(input.ctx, input.target)
			if err != nil {
				results <- nil
				return
			}
			results <- task
		}()
	}
	close(start)
	for range 2 {
		select {
		case task := <-results:
			if task == nil {
				t.Fatal("opposite Enter unexpectedly failed")
			}
			task.Release()
		case <-time.After(5 * time.Second):
			t.Fatal("opposite Enter lock cycle")
		}
	}
	leftRoot.Release()
	rightRoot.Release()
	if err := ledger.ReserveRetirement(left); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ReserveRetirement(right); err != nil {
		t.Fatal(err)
	}
	left.Retire()
	right.Retire()
	<-left.Drained()
	<-right.Drained()
	left.Release()
	right.Release()
}

func TestRetirementEnterRejectsForeignInstance(t *testing.T) {
	leftLedger := newRetirementLedger(1)
	rightLedger := newRetirementLedger(1)
	source := mustRegisterRetirementGeneration(t, leftLedger, "source")
	target := mustRegisterRetirementGeneration(t, rightLedger, "target")
	right, ok := source.AcquireRoot()
	if !ok {
		t.Fatal("source root not admitted")
	}
	ctx := ContextWithRetirementRight(context.Background(), right)
	if _, task, err := EnterRetirement(ctx, target); err == nil || task != nil {
		t.Fatal("foreign Instance Enter succeeded")
	}
	right.Release()
	leftLedger.SealAndSnapshot()
	rightLedger.SealAndSnapshot()
	<-source.Drained()
	<-target.Drained()
	source.Release()
	target.Release()
}

func TestRetirementSealIncludesActiveAndRetiringWithoutQuotaCharge(t *testing.T) {
	ledger := newRetirementLedger(1)
	retiring := mustRegisterRetirementGeneration(t, ledger, "retiring")
	active := mustRegisterRetirementGeneration(t, ledger, "active")
	right, ok := retiring.AcquireRoot()
	if !ok {
		t.Fatal("retiring root not admitted")
	}
	if err := ledger.ReserveRetirement(retiring); err != nil {
		t.Fatal(err)
	}
	snapshot := ledger.SealAndSnapshot()
	if len(snapshot) != 2 {
		t.Fatalf("shutdown snapshot size = %d, want 2", len(snapshot))
	}
	if got := ledger.RetainedCount(); got != 1 {
		t.Fatalf("shutdown charged count = %d, want only ordinary retiring generation", got)
	}
	if _, ok := active.AcquireRoot(); ok {
		t.Fatal("sealed ACTIVE generation admitted a root")
	}
	right.Release()
	<-retiring.Drained()
	<-active.Drained()
	retiring.Release()
	active.Release()
	ledger.Wait()
}

type retirementContextTestKey string

func TestContextWithoutRequestCancellationRetainsGenerationAuthority(t *testing.T) {
	ledger := NewRetirementLedgerForValidation(1)
	generation := mustRegisterRetirementGeneration(t, ledger, "timeout-only")
	right, ok := generation.AcquireRoot()
	if !ok {
		t.Fatal("failed to acquire generation root")
	}
	requestCtx, cancelRequest := context.WithCancel(context.WithValue(context.Background(), retirementContextTestKey("value"), "kept"))
	requestCtx = ContextWithRetirementRight(requestCtx, right)
	detached, cleanup := ContextWithoutRequestCancellation(requestCtx)
	defer cleanup()
	cancelRequest()
	if err := detached.Err(); err != nil {
		t.Fatalf("request cancellation escaped TimeoutOnly detachment: %v", err)
	}
	if got := detached.Value(retirementContextTestKey("value")); got != "kept" {
		t.Fatalf("detached context value = %v, want kept", got)
	}
	generation.ForceSeal()
	select {
	case <-detached.Done():
	case <-time.After(time.Second):
		t.Fatal("generation seal did not cancel detached context")
	}
	right.Release()
}

func TestRetirementEntryFootprint(t *testing.T) {
	ledger := newRetirementLedger(1)
	allocs := testing.AllocsPerRun(1000, func() {
		generation, err := ledger.Register(new(struct{}), "footprint")
		if err != nil {
			panic(err)
		}
		if err := ledger.ReserveRetirement(generation); err != nil {
			panic(err)
		}
		generation.Retire()
		generation.Release()
	})
	if allocs > 8 {
		t.Fatalf("retirement entry allocations = %.2f, want <= 8", allocs)
	}
	t.Logf("retirement entry allocations/run = %.2f", allocs)
}

func BenchmarkRetirementReservationRelease(b *testing.B) {
	ledger := newRetirementLedger(1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		generation, err := ledger.Register(new(struct{}), "bench")
		if err != nil {
			b.Fatal(err)
		}
		if err := ledger.ReserveRetirement(generation); err != nil {
			b.Fatal(err)
		}
		generation.Retire()
		generation.Release()
	}
}
