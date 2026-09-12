package outbound

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	feature "github.com/xtls/xray-core/features/outbound"
)

func retirementManager(t *testing.T, capacity int) *Manager {
	t.Helper()
	m, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.retirement = core.NewRetirementLedgerForValidation(capacity)
	return m
}

func requireRetirementCounts(t *testing.T, m *Manager, current, peak int) {
	t.Helper()
	if got := m.retirement.RetainedCount(); got != current {
		t.Fatalf("current retained = %d, want %d", got, current)
	}
	if got := m.retirement.PeakRetainedCount(); got != peak {
		t.Fatalf("peak retained = %d, want %d", got, peak)
	}
}

func waitRetirementEntry(t *testing.T, entry *handlerGenerationEntry) {
	t.Helper()
	select {
	case <-entry.done:
	case <-time.After(5 * time.Second):
		t.Fatal("retirement cleanup did not complete")
	}
}

func retirementEntryForHandler(m *Manager, handler feature.Handler) *handlerGenerationEntry {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.entries[m.generations[handler]]
}

func TestRetirementReservationBeforeMutationAndRetry(t *testing.T) {
	m := retirementManager(t, 1)
	old := &lifecycleHandler{tag: "old"}
	blocked := &lifecycleHandler{tag: "blocked"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), blocked); err != nil {
		t.Fatal(err)
	}
	oldGeneration := m.generations[old]
	oldEntry := m.entries[oldGeneration]
	right, ok := oldGeneration.AcquireRoot()
	if !ok {
		t.Fatal("old root not admitted")
	}
	if err := m.RemoveHandler(context.Background(), "old"); err != nil {
		t.Fatal(err)
	}
	err := m.RemoveHandler(context.Background(), "blocked")
	var exhausted *core.RetirementCapacityExhaustedError
	if !errors.As(err, &exhausted) {
		t.Fatalf("remove error = %v, want typed exhaustion", err)
	}
	if got := m.GetHandler("blocked"); got != blocked {
		t.Fatal("exhaustion changed tagged handler")
	}
	if got := m.GetDefaultHandler(); got != nil {
		t.Fatalf("exhaustion changed default: %v", got)
	}
	if m.generations[blocked].Phase() != core.RetirementActive {
		t.Fatal("exhaustion changed generation phase")
	}
	right.Release()
	waitRetirementEntry(t, oldEntry)
	blockedEntry := m.entries[m.generations[blocked]]
	if err := m.RemoveHandler(context.Background(), "blocked"); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	waitRetirementEntry(t, blockedEntry)
	requireRetirementCounts(t, m, 0, 1)
}

func TestRetirementIdleSameTagTenThousand(t *testing.T) {
	m := retirementManager(t, 1)
	for i := 0; i < 10000; i++ {
		h := &lifecycleHandler{tag: "same"}
		if err := m.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		entry := m.entries[m.generations[h]]
		if err := m.RemoveHandler(context.Background(), "same"); err != nil {
			t.Fatal(err)
		}
		waitRetirementEntry(t, entry)
		if h.closeCall.Load() != 1 {
			t.Fatalf("iteration %d close calls = %d", i, h.closeCall.Load())
		}
	}
	requireRetirementCounts(t, m, 0, 1)
}

func TestRetirementDynamicAddRemoveSelectWorkers(t *testing.T) {
	m := retirementManager(t, 50)
	const groups, iterations = 50, 20
	var wg sync.WaitGroup
	errs := make(chan error, groups)
	for group := 0; group < groups; group++ {
		wg.Add(1)
		go func(group int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tag := fmt.Sprintf("g-%d-%d", group, i)
				if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: tag}); err != nil {
					errs <- err
					return
				}
				_ = m.Select([]string{"g-"})
				handler := m.GetHandler(tag)
				entry := retirementEntryForHandler(m, handler)
				if err := m.RemoveHandler(context.Background(), tag); err != nil {
					errs <- err
					return
				}
				select {
				case <-entry.done:
				case <-time.After(5 * time.Second):
					errs <- fmt.Errorf("retirement cleanup timeout")
					return
				}
			}
		}(group)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if current := m.retirement.RetainedCount(); current != 0 {
		t.Fatalf("current retained = %d, want 0", current)
	}
	if peak := m.retirement.PeakRetainedCount(); peak < 1 || peak > 50 {
		t.Fatalf("peak retained = %d, want within [1,50]", peak)
	}
}

func TestRetirementUpstreamFiftyConcurrentRemovalsCapacityMatrix(t *testing.T) {
	const removers = 50
	for _, capacity := range []int{1, 2, 4, 8, 16, 32, 50} {
		t.Run(fmt.Sprintf("capacity-%d", capacity), func(t *testing.T) {
			m := retirementManager(t, capacity)
			entered := make(chan struct{}, removers)
			releaseClose := make(chan struct{})
			results := make(chan error, removers)
			for index := 0; index < removers; index++ {
				tag := fmt.Sprintf("held-close-%d", index)
				handler := &lifecycleHandler{tag: tag, closeFn: func() error {
					entered <- struct{}{}
					<-releaseClose
					return nil
				}}
				if err := m.AddHandler(context.Background(), handler); err != nil {
					t.Fatal(err)
				}
				go func(tag string) { results <- m.RemoveHandler(context.Background(), tag) }(tag)
			}

			admitted, rejected := 0, 0
			for index := 0; index < removers; index++ {
				err := <-results
				if err == nil {
					admitted++
					continue
				}
				var exhausted *core.RetirementCapacityExhaustedError
				if !errors.As(err, &exhausted) {
					t.Fatalf("unexpected remove result: %v", err)
				}
				rejected++
			}
			if admitted != capacity || rejected != removers-capacity {
				t.Fatalf("admitted=%d rejected=%d, want %d/%d", admitted, rejected, capacity, removers-capacity)
			}
			if peak := m.retirement.PeakRetainedCount(); peak != capacity {
				t.Fatalf("peak=%d, want capacity %d", peak, capacity)
			}
			for index := 0; index < admitted; index++ {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("admitted closer did not start")
				}
			}
			close(releaseClose)
			deadline := time.Now().Add(5 * time.Second)
			for m.retirement.RetainedCount() != 0 {
				if time.Now().After(deadline) {
					t.Fatalf("current retained=%d after receipts", m.retirement.RetainedCount())
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestRetirementConcurrentRemoveTwoAdds(t *testing.T) {
	m := retirementManager(t, 1)
	old := &lifecycleHandler{tag: "old"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	oldEntry := m.entries[m.generations[old]]
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, fn := range []func(){
		func() { <-start; _ = m.RemoveHandler(context.Background(), "old") },
		func() { <-start; _ = m.AddHandler(context.Background(), &lifecycleHandler{tag: "new-a"}) },
		func() { <-start; _ = m.AddHandler(context.Background(), &lifecycleHandler{tag: "new-b"}) },
		func() {
			<-start
			for i := 0; i < 100; i++ {
				_ = m.Select([]string{"new", "old"})
			}
		},
	} {
		wg.Add(1)
		go func(f func()) { defer wg.Done(); f() }(fn)
	}
	close(start)
	wg.Wait()
	waitRetirementEntry(t, oldEntry)
	requireRetirementCounts(t, m, 0, 1)
}

func TestRetirementHeldContinuationSameTagReplacement(t *testing.T) {
	m := retirementManager(t, 1)
	old := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	oldGeneration := m.generations[old]
	oldEntry := m.entries[oldGeneration]
	root, ok := oldGeneration.AcquireRoot()
	if !ok {
		t.Fatal("old root not admitted")
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	continuation, ok := root.AcquireContinuation()
	if !ok {
		t.Fatal("retiring continuation not admitted for live root")
	}
	root.Release()
	replacement := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	requireRetirementCounts(t, m, 1, 1)
	continuation.Release()
	waitRetirementEntry(t, oldEntry)
	if old.closeCall.Load() != 1 {
		t.Fatalf("old close calls = %d", old.closeCall.Load())
	}
	if got := m.GetHandler("same"); got != replacement {
		t.Fatal("old release affected replacement")
	}
	requireRetirementCounts(t, m, 0, 1)
}

func TestRetirementCapacityAndRapidSecondRetirement(t *testing.T) {
	m := retirementManager(t, 1)
	first := &lifecycleHandler{tag: "first"}
	second := &lifecycleHandler{tag: "second"}
	if err := m.AddHandler(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	firstGeneration := m.generations[first]
	firstEntry := m.entries[firstGeneration]
	right, ok := firstGeneration.AcquireRoot()
	if !ok {
		t.Fatal("first root")
	}
	if err := m.RemoveHandler(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	err := m.RemoveHandler(context.Background(), "second")
	var exhausted *core.RetirementCapacityExhaustedError
	if !errors.As(err, &exhausted) {
		t.Fatalf("distinct-tag capacity error = %v", err)
	}
	right.Release()
	waitRetirementEntry(t, firstEntry)
	secondEntry := m.entries[m.generations[second]]
	if err := m.RemoveHandler(context.Background(), "second"); err != nil {
		t.Fatal(err)
	}
	waitRetirementEntry(t, secondEntry)

	old := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	oldGeneration := m.generations[old]
	oldEntry := m.entries[oldGeneration]
	oldRight, ok := oldGeneration.AcquireRoot()
	if !ok {
		t.Fatal("old root")
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	newer := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	newRight, ok := m.generations[newer].AcquireRoot()
	if !ok {
		t.Fatal("new root")
	}
	err = m.RemoveHandler(context.Background(), "same")
	if !errors.As(err, &exhausted) {
		t.Fatalf("C=1 rapid same-tag second retirement error = %v", err)
	}
	if got := m.GetHandler("same"); got != newer {
		t.Fatal("failed second retirement changed replacement")
	}
	oldRight.Release()
	waitRetirementEntry(t, oldEntry)
	newRight.Release()
	requireRetirementCounts(t, m, 0, 1)
}

func TestRetirementSequentialHeldSameTagCapacityReleaseAndRetry(t *testing.T) {
	const capacity = 50
	m := retirementManager(t, capacity)
	rights := make([]*core.RetirementRight, 0, capacity+1)
	entries := make([]*handlerGenerationEntry, 0, capacity+1)
	for index := 0; index < capacity; index++ {
		handler := &lifecycleHandler{tag: "same"}
		if err := m.AddHandler(context.Background(), handler); err != nil {
			t.Fatal(err)
		}
		right, ok := m.generations[handler].AcquireRoot()
		if !ok {
			t.Fatalf("generation %d root not admitted", index)
		}
		rights = append(rights, right)
		entries = append(entries, m.entries[m.generations[handler]])
		if err := m.RemoveHandler(context.Background(), "same"); err != nil {
			t.Fatalf("generation %d retirement: %v", index, err)
		}
	}
	requireRetirementCounts(t, m, capacity, capacity)
	if got := len(m.retained); got != capacity {
		t.Fatalf("manager retained entries = %d, want %d", got, capacity)
	}

	newest := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), newest); err != nil {
		t.Fatal(err)
	}
	newestGeneration := m.generations[newest]
	newestRight, ok := newestGeneration.AcquireRoot()
	if !ok {
		t.Fatal("newest root not admitted")
	}
	rights = append(rights, newestRight)
	entries = append(entries, m.entries[newestGeneration])
	err := m.RemoveHandler(context.Background(), "same")
	var exhausted *core.RetirementCapacityExhaustedError
	if !errors.As(err, &exhausted) {
		t.Fatalf("capacity+1 error = %v, want typed exhaustion", err)
	}
	if got := m.GetHandler("same"); got != newest {
		t.Fatal("capacity rejection mutated the active same-tag generation")
	}
	if newestGeneration.Phase() != core.RetirementActive {
		t.Fatalf("capacity rejection phase = %v, want ACTIVE", newestGeneration.Phase())
	}
	requireRetirementCounts(t, m, capacity, capacity)
	if got := len(m.retained); got != capacity {
		t.Fatalf("manager retained entries after rejection = %d, want %d", got, capacity)
	}

	rights[0].Release()
	waitRetirementEntry(t, entries[0])
	if got := len(m.retained); got != capacity-1 {
		t.Fatalf("manager retained entries after one release = %d, want %d", got, capacity-1)
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatalf("retry after one release: %v", err)
	}
	requireRetirementCounts(t, m, capacity, capacity)
	if got := len(m.retained); got != capacity {
		t.Fatalf("manager retained entries after retry = %d, want %d", got, capacity)
	}

	for _, right := range rights[1:] {
		right.Release()
	}
	for _, entry := range entries[1:] {
		waitRetirementEntry(t, entry)
	}
	requireRetirementCounts(t, m, 0, capacity)
	if got := len(m.retained); got != 0 {
		t.Fatalf("manager retained entries after drain = %d, want 0", got)
	}
}

func TestRetirementRejectsSameHandlerInstanceReactivation(t *testing.T) {
	m := retirementManager(t, 2)
	handler := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), handler); err != nil {
		t.Fatal(err)
	}
	generation := m.generations[handler]
	entry := m.entries[generation]
	right, ok := generation.AcquireRoot()
	if !ok {
		t.Fatal("root not admitted")
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), handler); err == nil {
		t.Fatal("same live handler instance was reactivated as another generation")
	}
	if got := m.GetHandler("same"); got != nil {
		t.Fatalf("rejected handler was published: %v", got)
	}
	if got := m.generations[handler]; got != generation {
		t.Fatal("rejected reactivation replaced the retiring generation identity")
	}
	requireRetirementCounts(t, m, 1, 1)
	right.Release()
	waitRetirementEntry(t, entry)
	if _, found := m.generations[handler]; found {
		t.Fatal("released exact generation remained manager-reachable")
	}
	requireRetirementCounts(t, m, 0, 1)
}

func BenchmarkRetirementManagerEntry(b *testing.B) {
	m, err := New(context.Background(), nil)
	if err != nil {
		b.Fatal(err)
	}
	m.retirement = core.NewRetirementLedgerForValidation(1)
	handler := &lifecycleHandler{tag: "bench"}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := m.AddHandler(context.Background(), handler); err != nil {
			b.Fatal(err)
		}
		entry := m.entries[m.generations[handler]]
		if err := m.RemoveHandler(context.Background(), "bench"); err != nil {
			b.Fatal(err)
		}
		<-entry.done
	}
}

func BenchmarkRetirementManagerCapacity50(b *testing.B) {
	const capacity = 50
	handlers := make([]*lifecycleHandler, capacity)
	for index := range handlers {
		handlers[index] = &lifecycleHandler{tag: fmt.Sprintf("held-%d", index)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		m, err := New(context.Background(), nil)
		if err != nil {
			b.Fatal(err)
		}
		m.retirement = core.NewRetirementLedgerForValidation(capacity)
		rights := make([]*core.RetirementRight, 0, capacity)
		entries := make([]*handlerGenerationEntry, 0, capacity)
		for _, handler := range handlers {
			if err := m.AddHandler(context.Background(), handler); err != nil {
				b.Fatal(err)
			}
			right, ok := m.generations[handler].AcquireRoot()
			if !ok {
				b.Fatal("root not admitted")
			}
			rights = append(rights, right)
			entries = append(entries, m.entries[m.generations[handler]])
			if err := m.RemoveHandler(context.Background(), handler.tag); err != nil {
				b.Fatal(err)
			}
		}
		for _, right := range rights {
			right.Release()
		}
		for _, entry := range entries {
			<-entry.done
		}
	}
}
