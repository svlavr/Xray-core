package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/transport/internet"
)

// retainedHandlerGenerationCapacity is the Release-1 Instance default. Fifty
// is the smallest capacity that admits the official upstream #2943 control-
// plane stress envelope of fifty concurrently unfinished handler removals.
// Deterministic blocked-close and sequential held-generation tests prove the
// same bound, C+1 refusal without mutation, and release-then-retry. Work beyond
// that measured envelope receives the typed retryable exhaustion result.
const retainedHandlerGenerationCapacity = 50

var nextRetirementInstanceID atomic.Uint64

// RetirementCapacityExhaustedError is a retryable refusal made before a
// handler-generation is removed from lookup.
type RetirementCapacityExhaustedError struct {
	Capacity int
}

func (e *RetirementCapacityExhaustedError) Error() string {
	return fmt.Sprintf("RETIREMENT_CAPACITY_EXHAUSTED: capacity=%d", e.Capacity)
}

func (*RetirementCapacityExhaustedError) Temporary() bool { return true }

// RetirementPhase is the exact handler generation lifecycle used by the
// validation ledger.
type RetirementPhase uint8

const (
	RetirementActive RetirementPhase = iota
	RetirementRetiring
	RetirementDraining
	RetirementDrained
	RetirementReleased
)

// RetirementLedger is owned by one Instance. Its exported surface exists only
// for in-tree feature integration and validation; it is not a product API.
type RetirementLedger struct {
	mu          sync.Mutex
	instanceID  uint64
	capacity    int
	next        uint64
	used        int // reservations plus exact non-RELEASED retired generations
	peak        int
	sealed      bool
	generations map[*RetirementGeneration]struct{}
	wg          sync.WaitGroup
}

// RetirementGeneration has one monotonic identity and flat root/continuation
// holds. It deliberately has no descendant lease tree.
type RetirementGeneration struct {
	ledger   *RetirementLedger
	instance uint64
	ordinal  uint64
	handler  any
	tag      string

	mu            sync.Mutex
	phase         RetirementPhase
	holds         int
	sealed        bool
	quotaReserved bool
	ctx           context.Context
	cancel        context.CancelFunc
	drained       chan struct{}
	drainClosed   bool
}

// RetirementRight is one live root or continuation hold. A continuation can
// be derived only while its exact source right remains live; the generation
// itself never manufactures post-retirement work from a saved pointer.
type RetirementRight struct {
	generation *RetirementGeneration
	mu         sync.Mutex
	released   bool
}

// RetirementTask is one single-use Enter receipt. Cross-generation work owns
// one flat hold on each side; same-generation work owns one continuation hold.
type RetirementTask struct {
	ctx     context.Context
	cancel  context.CancelFunc
	stop    []func() bool
	source  *RetirementRight
	target  *RetirementRight
	release sync.Once
}

type retirementRightKey struct{}

func newRetirementLedger(capacity int) *RetirementLedger {
	if capacity <= 0 {
		panic("retirement capacity must be positive")
	}
	return &RetirementLedger{
		instanceID:  nextRetirementInstanceID.Add(1),
		capacity:    capacity,
		generations: make(map[*RetirementGeneration]struct{}),
	}
}

func newInstanceRetirementLedger() *RetirementLedger {
	return newRetirementLedger(retainedHandlerGenerationCapacity)
}

// NewRetirementLedgerForValidation permits deterministic in-tree capacity
// tests without selecting a production capacity.
func NewRetirementLedgerForValidation(capacity int) *RetirementLedger {
	return newRetirementLedger(capacity)
}

// RetirementLedgerFromContext returns the owning Instance ledger, if this is a
// real core construction context. Standalone feature tests intentionally get nil.
func RetirementLedgerFromContext(ctx interface{ Value(any) any }) *RetirementLedger {
	if instance, ok := ctx.Value(xrayKey).(*Instance); ok && instance != nil {
		return instance.retirementLedger
	}
	return nil
}

func (l *RetirementLedger) Register(handler any, tag string) (*RetirementGeneration, error) {
	if l == nil {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed {
		return nil, fmt.Errorf("retirement ledger is sealed")
	}
	l.next++
	ctx, cancel := context.WithCancel(context.Background())
	g := &RetirementGeneration{
		ledger:   l,
		instance: l.instanceID,
		ordinal:  l.next,
		handler:  handler,
		tag:      tag,
		phase:    RetirementActive,
		ctx:      ctx,
		cancel:   cancel,
		drained:  make(chan struct{}),
	}
	l.generations[g] = struct{}{}
	l.wg.Add(1)
	return g, nil
}

// ReserveRetirement performs the quota admission before the manager mutates a
// map, default handler, binding, or generation phase.
func (l *RetirementLedger) ReserveRetirement(g *RetirementGeneration) error {
	if l == nil || g == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed {
		return fmt.Errorf("retirement ledger is sealed")
	}
	if g.ledger != l {
		return fmt.Errorf("foreign retirement generation")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.phase != RetirementActive {
		return fmt.Errorf("generation is not ACTIVE")
	}
	if l.used >= l.capacity {
		return &RetirementCapacityExhaustedError{Capacity: l.capacity}
	}
	l.used++
	if l.used > l.peak {
		l.peak = l.used
	}
	g.phase = RetirementRetiring
	g.quotaReserved = true
	return nil
}

// Retire seals new roots. Existing live work may take continuations until a
// forced seal, while its exact root hold remains live.
func (g *RetirementGeneration) Retire() {
	if g == nil || g.ledger == nil {
		return
	}
	l := g.ledger
	l.mu.Lock()
	g.mu.Lock()
	g.transitionToDrainingLocked()
	g.mu.Unlock()
	l.mu.Unlock()
}

func (g *RetirementGeneration) AcquireRoot() (*RetirementRight, bool) {
	if g == nil || g.ledger == nil {
		return nil, false
	}
	l := g.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed {
		return nil, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed || g.phase != RetirementActive {
		return nil, false
	}
	return g.acquireLocked(), true
}

func (r *RetirementRight) AcquireContinuation() (*RetirementRight, bool) {
	if r == nil || r.generation == nil {
		return nil, false
	}
	l := r.generation.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil, false
	}
	g := r.generation
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed || (g.phase != RetirementActive && g.phase != RetirementRetiring) {
		return nil, false
	}
	return g.acquireLocked(), true
}

func (g *RetirementGeneration) acquireLocked() *RetirementRight {
	g.holds++
	return &RetirementRight{generation: g}
}

// Release returns this exact flat hold once. It does not release any child
// continuation previously derived from the right.
func (r *RetirementRight) Release() {
	if r == nil || r.generation == nil {
		return
	}
	l := r.generation.ledger
	l.mu.Lock()
	r.mu.Lock()
	if r.released {
		r.mu.Unlock()
		l.mu.Unlock()
		return
	}
	r.released = true
	generation := r.generation
	r.mu.Unlock()
	generation.mu.Lock()
	generation.releaseHoldLocked()
	generation.mu.Unlock()
	l.mu.Unlock()
}

// ForceSeal rejects all later continuations as well as roots.
func (g *RetirementGeneration) ForceSeal() {
	if g == nil || g.ledger == nil {
		return
	}
	l := g.ledger
	l.mu.Lock()
	g.mu.Lock()
	g.sealed = true
	cancel := g.cancel
	g.mu.Unlock()
	l.mu.Unlock()
	cancel()
}

func (g *RetirementGeneration) releaseHoldLocked() {
	g.holds--
	if g.holds < 0 {
		panic("retirement hold underflow")
	}
	g.transitionToDrainingLocked()
}

func (g *RetirementGeneration) transitionToDrainingLocked() {
	if g.phase == RetirementRetiring && g.holds == 0 {
		g.phase = RetirementDraining
		if !g.drainClosed {
			close(g.drained)
			g.drainClosed = true
		}
	}
}

// Drained is closed only after retirement/shutdown has begun and every exact
// root or continuation hold has returned.
func (g *RetirementGeneration) Drained() <-chan struct{} {
	if g == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return g.drained
}

// Release marks this exact retired generation terminal and returns exactly one
// Instance slot. The handler close receipt must precede this call.
func (g *RetirementGeneration) Release() {
	if g == nil || g.ledger == nil {
		return
	}
	l := g.ledger
	l.mu.Lock()
	g.mu.Lock()
	if g.phase == RetirementReleased || (g.phase != RetirementDraining && g.phase != RetirementDrained) {
		g.mu.Unlock()
		l.mu.Unlock()
		return
	}
	g.phase = RetirementDrained
	g.phase = RetirementReleased
	quotaReserved := g.quotaReserved
	g.quotaReserved = false
	delete(l.generations, g)
	g.mu.Unlock()
	if quotaReserved {
		l.used--
		if l.used < 0 {
			l.mu.Unlock()
			panic("retirement capacity underflow")
		}
	}
	l.mu.Unlock()
	l.wg.Done()
}

// Abandon releases an unpublished ACTIVE generation after construction or
// binding rollback. It cannot retire or close a published handler.
func (g *RetirementGeneration) Abandon() bool {
	if g == nil || g.ledger == nil {
		return true
	}
	l := g.ledger
	l.mu.Lock()
	g.mu.Lock()
	if g.phase != RetirementActive || g.holds != 0 {
		g.mu.Unlock()
		l.mu.Unlock()
		return false
	}
	g.sealed = true
	g.phase = RetirementReleased
	delete(l.generations, g)
	cancel := g.cancel
	g.mu.Unlock()
	l.mu.Unlock()
	cancel()
	l.wg.Done()
	return true
}

// SealAndSnapshot is the Instance shutdown linearization point. ACTIVE
// generations enter uncharged retirement; already RETIRING generations retain
// their ordinary quota slot until their exact cleanup receipt releases it.
func (l *RetirementLedger) SealAndSnapshot() []*RetirementGeneration {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	l.sealed = true
	snapshot := make([]*RetirementGeneration, 0, len(l.generations))
	cancels := make([]context.CancelFunc, 0, len(l.generations))
	for generation := range l.generations {
		generation.mu.Lock()
		if generation.phase != RetirementReleased {
			generation.sealed = true
			if generation.phase == RetirementActive {
				generation.phase = RetirementRetiring
			}
			generation.transitionToDrainingLocked()
			snapshot = append(snapshot, generation)
			cancels = append(cancels, generation.cancel)
		}
		generation.mu.Unlock()
	}
	l.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return snapshot
}

func (l *RetirementLedger) Wait() {
	if l != nil {
		l.wg.Wait()
	}
}

// EnterRetirement registers one exact target task and, for a cross-generation
// edge, one source continuation in a single ledger transaction.
func EnterRetirement(ctx context.Context, target *RetirementGeneration) (context.Context, *RetirementTask, error) {
	if target == nil || target.ledger == nil {
		return ctx, nil, fmt.Errorf("target generation is unavailable")
	}
	l := target.ledger
	source := RetirementRightFromContext(ctx)
	l.mu.Lock()
	if l.sealed {
		l.mu.Unlock()
		return ctx, nil, fmt.Errorf("retirement ledger is sealed")
	}
	var sourceHold, targetHold *RetirementRight
	if source != nil {
		if source.generation == nil || source.generation.ledger != l {
			l.mu.Unlock()
			return ctx, nil, fmt.Errorf("foreign source generation")
		}
		source.mu.Lock()
		if source.released {
			source.mu.Unlock()
			l.mu.Unlock()
			return ctx, nil, fmt.Errorf("source generation right is released")
		}
		sourceGeneration := source.generation
		sourceGeneration.mu.Lock()
		if sourceGeneration.sealed || (sourceGeneration.phase != RetirementActive && sourceGeneration.phase != RetirementRetiring) {
			sourceGeneration.mu.Unlock()
			source.mu.Unlock()
			l.mu.Unlock()
			return ctx, nil, fmt.Errorf("source generation is not admitting continuations")
		}
		if sourceGeneration == target {
			targetHold = sourceGeneration.acquireLocked()
			sourceGeneration.mu.Unlock()
			source.mu.Unlock()
			l.mu.Unlock()
			return newRetirementTaskContext(ctx, nil, targetHold)
		}
		sourceHold = sourceGeneration.acquireLocked()
		sourceGeneration.mu.Unlock()
		source.mu.Unlock()
	}
	target.mu.Lock()
	if target.sealed || target.phase != RetirementActive {
		target.mu.Unlock()
		if sourceHold != nil {
			sourceHold.mu.Lock()
			sourceHold.released = true
			sourceHold.mu.Unlock()
			sourceHold.generation.mu.Lock()
			sourceHold.generation.releaseHoldLocked()
			sourceHold.generation.mu.Unlock()
		}
		l.mu.Unlock()
		return ctx, nil, fmt.Errorf("target generation is not ACTIVE")
	}
	targetHold = target.acquireLocked()
	target.mu.Unlock()
	l.mu.Unlock()
	return newRetirementTaskContext(ctx, sourceHold, targetHold)
}

func newRetirementTaskContext(ctx context.Context, source, target *RetirementRight) (context.Context, *RetirementTask, error) {
	// Detach the cancel tree itself, then forward cancellation through removable
	// callbacks. Releasing an invocation receipt must not cancel resources whose
	// stock ownership legitimately outlives the synchronous Handler return.
	taskCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	task := &RetirementTask{cancel: cancel, source: source, target: target}
	task.stop = append(task.stop, context.AfterFunc(ctx, cancel))
	if source != nil {
		task.stop = append(task.stop, context.AfterFunc(source.generation.ctx, cancel))
	}
	task.stop = append(task.stop, context.AfterFunc(target.generation.ctx, cancel))
	task.ctx = context.WithValue(taskCtx, retirementRightKey{}, target)
	return task.ctx, task, nil
}

func (t *RetirementTask) Context() context.Context {
	if t == nil {
		return nil
	}
	return t.ctx
}

func (t *RetirementTask) Release() {
	if t == nil {
		return
	}
	t.release.Do(func() {
		for _, stop := range t.stop {
			stop()
		}
		if t.target != nil {
			t.target.Release()
		}
		if t.source != nil {
			t.source.Release()
		}
	})
}

func ContextWithRetirementRight(ctx context.Context, right *RetirementRight) context.Context {
	if right == nil {
		return ctx
	}
	return context.WithValue(ctx, retirementRightKey{}, right)
}

// ContextWithoutRequestCancellation preserves context values and TimeoutOnly
// request-detachment semantics while retaining exact generation cancellation.
func ContextWithoutRequestCancellation(ctx context.Context) (context.Context, context.CancelFunc) {
	detached, cancel := context.WithCancel(context.WithoutCancel(ctx))
	var stops []func() bool
	if right := RetirementRightFromContext(ctx); right != nil {
		stops = append(stops, context.AfterFunc(right.GenerationContext(), cancel))
	}
	if resources := internet.ResourceLifecycleFromContext(ctx); resources != nil {
		stops = append(stops, context.AfterFunc(resources.Context(), cancel))
	}
	if operationCtx := internet.DialOperationContext(ctx); operationCtx != nil {
		stops = append(stops, context.AfterFunc(operationCtx, cancel))
	}
	return detached, func() {
		for _, stop := range stops {
			stop()
		}
		cancel()
	}
}

func RetirementRightFromContext(ctx context.Context) *RetirementRight {
	right, _ := ctx.Value(retirementRightKey{}).(*RetirementRight)
	return right
}

func (r *RetirementRight) Generation() *RetirementGeneration {
	if r == nil {
		return nil
	}
	return r.generation
}

func (r *RetirementRight) LiveFor(generation *RetirementGeneration) bool {
	if r == nil || generation == nil || r.generation != generation {
		return false
	}
	r.mu.Lock()
	live := !r.released
	r.mu.Unlock()
	return live
}

func (r *RetirementRight) GenerationContext() context.Context {
	if r == nil || r.generation == nil {
		return context.Background()
	}
	return r.generation.ctx
}

func (l *RetirementLedger) RetainedCount() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used
}

func (l *RetirementLedger) PeakRetainedCount() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peak
}

func (g *RetirementGeneration) Phase() RetirementPhase {
	if g == nil {
		return RetirementReleased
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.phase
}
