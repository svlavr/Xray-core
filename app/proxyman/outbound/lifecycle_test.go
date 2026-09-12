package outbound

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	feature "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type lifecycleHandler struct {
	tag       string
	startFn   func() error
	closeFn   func() error
	closeCall atomic.Int32
}

func (h *lifecycleHandler) Start() error {
	if h.startFn != nil {
		return h.startFn()
	}
	return nil
}

func (h *lifecycleHandler) Close() error {
	h.closeCall.Add(1)
	if h.closeFn != nil {
		return h.closeFn()
	}
	return nil
}
func (h *lifecycleHandler) Tag() string                               { return h.tag }
func (h *lifecycleHandler) Dispatch(context.Context, *transport.Link) {}
func (h *lifecycleHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (h *lifecycleHandler) ProxySettings() *serial.TypedMessage       { return nil }

var _ feature.Handler = (*lifecycleHandler)(nil)

func TestManagerCloseInvokesHandlerOutsideManagerLock(t *testing.T) {
	m, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &lifecycleHandler{tag: "a"}
	h.closeFn = func() error {
		if got := m.GetHandler("a"); got != nil {
			t.Fatalf("handler remained published during Close callback")
		}
		return nil
	}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVLESSReverseRegistrationSharesExactHandlerAndLastReleaseDetaches(t *testing.T) {
	m, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	var created atomic.Int32
	factory := func(context.Context) (feature.Handler, error) {
		created.Add(1)
		return &lifecycleHandler{tag: "reverse"}, nil
	}
	first, err := m.RegisterVLESSReverse(context.Background(), "reverse", factory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.RegisterVLESSReverse(context.Background(), "reverse", factory)
	if err != nil {
		t.Fatal(err)
	}
	if created.Load() != 1 || first.Handler() != second.Handler() {
		t.Fatal("reverse registrations did not share one exact handler")
	}
	entered, err := first.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.GetHandler("reverse") == nil {
		t.Fatal("non-last release detached reverse")
	}
	if err := second.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.GetHandler("reverse") != nil {
		t.Fatal("last release retained reverse")
	}
	entered.Release()
}

func TestVLESSReverseLastReleaseCapacityRefusalIsRetryable(t *testing.T) {
	m := retirementManager(t, 1)
	if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	registration, err := m.RegisterVLESSReverse(context.Background(), "reverse", func(context.Context) (feature.Handler, error) {
		return &lifecycleHandler{tag: "reverse"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	blocker := &lifecycleHandler{tag: "blocker"}
	if err := m.AddHandler(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	blockerUse, err := m.EnterHandler(context.Background(), blocker.tag)
	if err != nil {
		t.Fatal(err)
	}
	blockerGeneration := m.generations[blocker]
	blockerEntry := m.entries[blockerGeneration]
	if err := m.RemoveHandler(context.Background(), blocker.tag); err != nil {
		t.Fatal(err)
	}
	if err := registration.Release(context.Background()); err == nil {
		t.Fatal("last registration release ignored retirement capacity")
	} else {
		var exhausted *core.RetirementCapacityExhaustedError
		if !errors.As(err, &exhausted) {
			t.Fatalf("release error = %T %v, want capacity exhaustion", err, err)
		}
	}
	if got := m.GetHandler("reverse"); got != registration.Handler() {
		t.Fatal("capacity refusal changed the exact shared generation")
	}
	use, err := registration.Enter(context.Background())
	if err != nil {
		t.Fatalf("capacity refusal invalidated the registration: %v", err)
	}
	use.Release()
	blockerUse.Release()
	waitRetirementEntry(t, blockerEntry)
	if err := registration.Release(context.Background()); err != nil {
		t.Fatalf("explicit release retry = %v", err)
	}
	if m.GetHandler("reverse") != nil {
		t.Fatal("successful retry retained shared generation")
	}
}

func TestVLESSReverseStaleTokenCannotAffectReplacement(t *testing.T) {
	m, _ := New(context.Background(), nil)
	if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	old, err := m.RegisterVLESSReverse(context.Background(), "reverse", func(context.Context) (feature.Handler, error) {
		return &lifecycleHandler{tag: "reverse"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandler(context.Background(), "reverse"); err != nil {
		t.Fatal(err)
	}
	replacement := &lifecycleHandler{tag: "reverse"}
	if err := m.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Enter(context.Background()); err == nil {
		t.Fatal("stale registration entered a replacement generation")
	}
	if err := old.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := m.GetHandler("reverse"); got != replacement {
		t.Fatal("stale token release changed replacement")
	}
	if got := old.Handler().(*lifecycleHandler).closeCall.Load(); got != 1 {
		t.Fatalf("externally removed standalone Reverse close calls = %d, want 1", got)
	}
}

func TestStandaloneVLESSReverseLastReleaseJoinsWithManagerClose(t *testing.T) {
	m, _ := New(context.Background(), nil)
	if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	registration, err := m.RegisterVLESSReverse(context.Background(), "reverse", func(context.Context) (feature.Handler, error) {
		return &lifecycleHandler{tag: "reverse", closeFn: func() error {
			close(closeEntered)
			<-closeRelease
			return nil
		}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseDone := make(chan error, 1)
	go func() { releaseDone <- registration.Release(context.Background()) }()
	<-closeEntered
	managerDone := make(chan error, 1)
	go func() { managerDone <- m.Close() }()
	select {
	case err := <-managerDone:
		t.Fatalf("Manager.Close returned before standalone shared close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(closeRelease)
	if err := <-releaseDone; err != nil {
		t.Fatal(err)
	}
	if err := <-managerDone; err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneRemovalOwnsCandidateDuringSharedPublicationWindow(t *testing.T) {
	m, _ := New(context.Background(), nil)
	if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	candidate := &lifecycleHandler{tag: "reverse"}
	creating := &sharedHandlerCreation{done: make(chan struct{}), cancel: func() {}, handler: candidate}
	m.access.Lock()
	m.sharedCreating[candidate.tag] = creating
	m.access.Unlock()
	if err := m.AddHandler(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandler(context.Background(), candidate.tag); err != nil {
		t.Fatal(err)
	}
	if got := candidate.closeCall.Load(); got != 1 {
		t.Fatalf("publication-window candidate close calls = %d, want 1", got)
	}
	m.access.Lock()
	delete(m.sharedCreating, candidate.tag)
	close(creating.done)
	m.access.Unlock()
}

func TestVLESSReverseCreationIsCancelledAndJoinedByManagerClose(t *testing.T) {
	m, _ := New(context.Background(), nil)
	if err := m.AddHandler(context.Background(), &lifecycleHandler{tag: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	factoryEntered := make(chan struct{})
	candidateCloseEntered := make(chan struct{})
	candidateCloseRelease := make(chan struct{})
	candidate := &lifecycleHandler{tag: "reverse", closeFn: func() error {
		close(candidateCloseEntered)
		<-candidateCloseRelease
		return nil
	}}
	registerDone := make(chan error, 1)
	go func() {
		_, err := m.RegisterVLESSReverse(context.Background(), "reverse", func(ctx context.Context) (feature.Handler, error) {
			close(factoryEntered)
			<-ctx.Done()
			return candidate, nil
		})
		registerDone <- err
	}()
	<-factoryEntered
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	<-candidateCloseEntered
	select {
	case err := <-closeDone:
		t.Fatalf("Manager.Close returned before provisional candidate join: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(candidateCloseRelease)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-registerDone; err == nil {
		t.Fatal("cancelled shared creation reported success")
	}
	if got := candidate.closeCall.Load(); got != 1 {
		t.Fatalf("provisional candidate close calls = %d, want 1", got)
	}
}

func TestRemoveHandlerInstanceDoesNotRemoveSameTagReplacement(t *testing.T) {
	m, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oldHandler := &lifecycleHandler{tag: "same"}
	replacement := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), oldHandler); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandlerInstance(context.Background(), oldHandler); err != nil {
		t.Fatal(err)
	}
	if got := m.GetHandler("same"); got != replacement {
		t.Fatalf("stale exact removal changed replacement: got %T %p, want %p", got, got, replacement)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandlerInstance(context.Background(), replacement); err != nil {
		t.Fatalf("late exact cleanup after manager Close = %v", err)
	}
}

func TestRemoveHandlerInstanceAfterGlobalSealIsIdempotent(t *testing.T) {
	m := retirementManager(t, 1)
	handler := &lifecycleHandler{tag: "sealed"}
	if err := m.AddHandler(context.Background(), handler); err != nil {
		t.Fatal(err)
	}
	m.SignalStop()
	if err := m.RemoveHandlerInstance(context.Background(), handler); err != nil {
		t.Fatal(err)
	}
	if got := m.GetHandler("sealed"); got != handler {
		t.Fatal("exact cleanup mutated a globally sealed manager before its shutdown snapshot")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveHandlerInstanceRacesGlobalSeal(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		m := retirementManager(t, 1)
		handler := &lifecycleHandler{tag: "race"}
		if err := m.AddHandler(context.Background(), handler); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		removeDone := make(chan error, 1)
		sealDone := make(chan struct{})
		go func() {
			<-start
			removeDone <- m.RemoveHandlerInstance(context.Background(), handler)
		}()
		go func() {
			<-start
			m.retirement.SealAndSnapshot()
			close(sealDone)
		}()
		close(start)
		if err := <-removeDone; err != nil {
			t.Fatalf("iteration %d: exact removal vs global seal = %v", iteration, err)
		}
		<-sealDone
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestManagerRepeatedCloseWaitsAndReturnsSavedError(t *testing.T) {
	m, _ := New(context.Background(), nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	want := errors.New("close failed")
	var once sync.Once
	h := &lifecycleHandler{tag: "a", closeFn: func() error {
		once.Do(func() { close(entered) })
		<-release
		return want
	}}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- m.Close() }()
	<-entered
	go func() { second <- m.Close() }()
	select {
	case <-second:
		t.Fatal("repeated Close returned before original completion")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-first; err == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("first Close error = %v", err)
	}
	if err := <-second; err == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("repeated Close error = %v", err)
	}
}

func TestRemoveHandlerDetachesWithoutClosingAcceptedGeneration(t *testing.T) {
	m, _ := New(context.Background(), nil)
	old := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	if old.closeCall.Load() != 0 {
		t.Fatal("RemoveHandler destructively closed the detached generation")
	}
	replacement := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if got := m.GetHandler("same"); got != replacement {
		t.Fatal("replacement generation was not selected")
	}
}

func TestEnteredHandlerPinsExactGenerationAcrossReplacement(t *testing.T) {
	m := retirementManager(t, 1)
	old := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	entry, err := m.EnterHandler(context.Background(), "same")
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration := m.generations[old]
	oldRecord := m.entries[oldGeneration]
	if entry.Handler() != old {
		t.Fatal("entry did not retain exact old handler")
	}
	if err := m.RemoveHandler(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	replacement := &lifecycleHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if old.closeCall.Load() != 0 {
		t.Fatal("old generation closed while its entered task remained live")
	}
	entry.Release()
	waitRetirementEntry(t, oldRecord)
	if old.closeCall.Load() != 1 {
		t.Fatalf("old close calls = %d, want 1", old.closeCall.Load())
	}
	if got := m.GetHandler("same"); got != replacement {
		t.Fatal("old cleanup changed same-tag replacement")
	}
}

func TestManagerCloseSnapshotsActiveAndRetiringBeforeWaiting(t *testing.T) {
	m := retirementManager(t, 1)
	closeEntered := make(chan string, 2)
	releaseClose := make(chan struct{})
	newHandler := func(tag string) *lifecycleHandler {
		return &lifecycleHandler{tag: tag, closeFn: func() error {
			closeEntered <- tag
			<-releaseClose
			return nil
		}}
	}
	retiring := newHandler("retiring")
	active := newHandler("active")
	if err := m.AddHandler(context.Background(), retiring); err != nil {
		t.Fatal(err)
	}
	right, ok := m.generations[retiring].AcquireRoot()
	if !ok {
		t.Fatal("retiring root not admitted")
	}
	if err := m.RemoveHandler(context.Background(), "retiring"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	seen := map[string]bool{}
	for len(seen) != 2 {
		select {
		case tag := <-closeEntered:
			seen[tag] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("not all handlers received close before wait: %v", seen)
		}
	}
	close(releaseClose)
	select {
	case err := <-closed:
		t.Fatalf("manager closed before retiring task receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	right.Release()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not join ACTIVE+RETIRING snapshot")
	}
	if retiring.closeCall.Load() != 1 || active.closeCall.Load() != 1 {
		t.Fatalf("close calls retiring=%d active=%d, want exactly once", retiring.closeCall.Load(), active.closeCall.Load())
	}
	requireRetirementCounts(t, m, 0, 1)
}

func TestAddHandlerStartFailureRacingSealRetainsCleanupOwnership(t *testing.T) {
	m := retirementManager(t, 1)
	m.running = true
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	startFailure := errors.New("start failed")
	closeFailure := errors.New("cleanup failed")
	handler := &lifecycleHandler{
		tag: "pending",
		startFn: func() error {
			close(startEntered)
			<-releaseStart
			return startFailure
		},
		closeFn: func() error { return closeFailure },
	}
	addResult := make(chan error, 1)
	go func() { addResult <- m.AddHandler(context.Background(), handler) }()
	<-startEntered
	signaled := make(chan struct{})
	go func() { m.SignalStop(); close(signaled) }()
	close(releaseStart)
	err := <-addResult
	if err == nil || !strings.Contains(err.Error(), startFailure.Error()) || !strings.Contains(err.Error(), closeFailure.Error()) {
		t.Fatalf("AddHandler error = %v, want start and cleanup failures", err)
	}
	select {
	case <-signaled:
	case <-time.After(5 * time.Second):
		t.Fatal("manager signal did not finish after Start rollback")
	}
	m.retirement.Wait()
	if got := len(m.retirement.SealAndSnapshot()); got != 0 {
		t.Fatalf("rollback left %d orphan generations", got)
	}
	if handler.closeCall.Load() != 1 {
		t.Fatalf("cleanup close calls = %d, want 1", handler.closeCall.Load())
	}
}

type blockingDispatchHandler struct {
	lifecycleHandler
	started chan struct{}
}

func (h *blockingDispatchHandler) Dispatch(_ context.Context, link *transport.Link) {
	close(h.started)
	_, _ = link.Reader.ReadMultiBuffer()
}

func TestDialerProxyEntryPinsOldGenerationUntilDispatchReceipt(t *testing.T) {
	m := retirementManager(t, 1)
	old := &blockingDispatchHandler{lifecycleHandler: lifecycleHandler{tag: "detour"}, started: make(chan struct{})}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	oldGeneration := m.generations[old]
	oldRecord := m.entries[oldGeneration]
	lifecycle := internet.NewDialLifecycle()
	if err := lifecycle.Configure(nil, m); err != nil {
		t.Fatal(err)
	}
	ctx := internet.ContextWithDialLifecycle(context.Background(), lifecycle)
	connection, err := internet.DialSystem(ctx, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443), &internet.SocketConfig{DialerProxy: "detour"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.started:
	case <-time.After(time.Second):
		t.Fatal("dialerProxy Dispatch was not published")
	}
	if err := m.RemoveHandler(context.Background(), "detour"); err != nil {
		t.Fatal(err)
	}
	replacement := &lifecycleHandler{tag: "detour"}
	if err := m.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if old.closeCall.Load() != 0 {
		t.Fatal("old dialerProxy generation closed before dispatch receipt")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitRetirementEntry(t, oldRecord)
	if old.closeCall.Load() != 1 {
		t.Fatalf("old close calls = %d, want 1", old.closeCall.Load())
	}
	if got := m.GetHandler("detour"); got != replacement {
		t.Fatal("old dialerProxy cleanup affected replacement")
	}
}
