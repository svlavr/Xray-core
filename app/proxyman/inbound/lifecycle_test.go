package inbound

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	feature "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type lifecycleInboundHandler struct {
	tag        string
	closeCalls atomic.Int32
	closeFn    func() error
}

func (*lifecycleInboundHandler) Start() error                           { return nil }
func (h *lifecycleInboundHandler) Tag() string                          { return h.tag }
func (*lifecycleInboundHandler) ReceiverSettings() *serial.TypedMessage { return nil }
func (*lifecycleInboundHandler) ProxySettings() *serial.TypedMessage    { return nil }
func (h *lifecycleInboundHandler) Close() error {
	h.closeCalls.Add(1)
	if h.closeFn != nil {
		return h.closeFn()
	}
	return nil
}

var _ feature.Handler = (*lifecycleInboundHandler)(nil)

func TestRemoveHandlerRetainsFailedExactOwnerForExplicitRetry(t *testing.T) {
	m, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := stderrors.New("retirement refused")
	var fail atomic.Bool
	fail.Store(true)
	h := &lifecycleInboundHandler{tag: "retry", closeFn: func() error {
		if fail.Load() {
			return want
		}
		return nil
	}}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandler(context.Background(), h.tag); !stderrors.Is(err, want) {
		t.Fatalf("first removal error = %v, want %v", err, want)
	}
	if got, err := m.GetHandler(context.Background(), h.tag); err != nil || got != h {
		t.Fatalf("failed removal lost exact owner: got=%p err=%v", got, err)
	}
	fail.Store(false)
	if err := m.RemoveHandler(context.Background(), h.tag); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetHandler(context.Background(), h.tag); err == nil {
		t.Fatal("successful retry retained handler")
	}
	if got := h.closeCalls.Load(); got != 2 {
		t.Fatalf("close attempts = %d, want 2", got)
	}
}

func TestConcurrentRemoveAndManagerCloseShareExactAttempt(t *testing.T) {
	m, _ := New(context.Background(), nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	h := &lifecycleInboundHandler{tag: "shared", closeFn: func() error {
		close(entered)
		<-release
		return nil
	}}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	removeDone := make(chan error, 1)
	closeDone := make(chan error, 1)
	go func() { removeDone <- m.RemoveHandler(context.Background(), h.tag) }()
	<-entered
	go func() { closeDone <- m.Close() }()
	close(release)
	if err := <-removeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if got := h.closeCalls.Load(); got != 1 {
		t.Fatalf("concurrent close calls = %d, want 1", got)
	}
}

func TestSuccessfulRemoveReleasesReceiptForSameObjectRepublish(t *testing.T) {
	m, _ := New(context.Background(), nil)
	h := &lifecycleInboundHandler{tag: "republish"}
	for iteration := 0; iteration < 2; iteration++ {
		if err := m.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if err := m.RemoveHandler(context.Background(), h.tag); err != nil {
			t.Fatal(err)
		}
		if len(m.closeAttempts) != 0 {
			t.Fatal("successful dynamic removal retained its close receipt")
		}
	}
	if got := h.closeCalls.Load(); got != 2 {
		t.Fatalf("republished handler close calls = %d, want 2", got)
	}
}

func TestShutdownSnapshotKeepsExactReceiptAfterDynamicRemovalCleanup(t *testing.T) {
	m, _ := New(context.Background(), nil)
	h := &lifecycleInboundHandler{tag: "snapshot"}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	m.access.Lock()
	removeTarget := m.closeTargetLocked(h)
	shutdownTarget := m.closeTargetLocked(h)
	m.access.Unlock()
	if err := m.runCloseTarget(removeTarget); err != nil {
		t.Fatal(err)
	}
	m.access.Lock()
	delete(m.taggedHandlers, h.tag)
	delete(m.closeAttempts, h)
	m.access.Unlock()
	if err := m.runCloseTarget(shutdownTarget); err != nil {
		t.Fatal(err)
	}
	if got := h.closeCalls.Load(); got != 1 {
		t.Fatalf("snapshot receipt issued %d Close calls, want 1", got)
	}
}

func TestStaleConcurrentRemovalCannotDeleteSameObjectRepublish(t *testing.T) {
	m, _ := New(context.Background(), nil)
	h := &lifecycleInboundHandler{tag: "same-object"}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	m.access.Lock()
	oldEpoch := m.tagEpoch[h.tag]
	first := m.closeTargetLocked(h)
	stale := m.closeTargetLocked(h)
	m.access.Unlock()
	if err := m.runCloseTarget(first); err != nil {
		t.Fatal(err)
	}
	m.commitTaggedRemoval(h.tag, h, oldEpoch, first.attempt)
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	newEpoch := m.tagEpoch[h.tag]
	if newEpoch == oldEpoch {
		t.Fatal("same-object republish reused publication epoch")
	}
	if err := m.runCloseTarget(stale); err != nil {
		t.Fatal(err)
	}
	m.commitTaggedRemoval(h.tag, h, oldEpoch, stale.attempt)
	if got, err := m.GetHandler(context.Background(), h.tag); err != nil || got != h {
		t.Fatalf("stale remover deleted republished handler: got=%p err=%v", got, err)
	}
	if err := m.RemoveHandler(context.Background(), h.tag); err != nil {
		t.Fatal(err)
	}
	if got := h.closeCalls.Load(); got != 2 {
		t.Fatalf("same-object lifecycle close calls = %d, want 2", got)
	}
}

type preparingInbound struct {
	prepareErr  error
	prepared    atomic.Int32
	closed      atomic.Int32
	closeSignal chan struct{}
	closeOnce   sync.Once
}

func (*preparingInbound) Network() []net.Network { return []net.Network{net.Network_TCP} }
func (*preparingInbound) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	return nil
}

func (p *preparingInbound) PrepareClose() error {
	p.prepared.Add(1)
	return p.prepareErr
}

func (p *preparingInbound) Close() error {
	p.closed.Add(1)
	if p.closeSignal != nil {
		p.closeOnce.Do(func() { close(p.closeSignal) })
	}
	return nil
}

type lifecycleWorker struct {
	proxy      proxy.Inbound
	closeCalls atomic.Int32
}

func (*lifecycleWorker) Start() error           { return nil }
func (*lifecycleWorker) Seal()                  {}
func (w *lifecycleWorker) Stop() error          { return w.Close() }
func (*lifecycleWorker) Wait() error            { return nil }
func (w *lifecycleWorker) Close() error         { w.closeCalls.Add(1); return nil }
func (*lifecycleWorker) Port() net.Port         { return 0 }
func (w *lifecycleWorker) Proxy() proxy.Inbound { return w.proxy }

func TestAlwaysOnPrepareCloseRefusalPrecedesWorkerDestruction(t *testing.T) {
	p := &preparingInbound{prepareErr: stderrors.New("capacity")}
	w := &lifecycleWorker{proxy: p}
	h := &AlwaysOnInboundHandler{proxy: p, workers: []worker{w}}
	if err := h.Close(); !stderrors.Is(err, p.prepareErr) {
		t.Fatalf("Close error = %v, want %v", err, p.prepareErr)
	}
	if w.closeCalls.Load() != 0 || p.closed.Load() != 0 {
		t.Fatal("pre-close refusal destroyed inbound resources")
	}
	p.prepareErr = nil
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if w.closeCalls.Load() != 1 || p.closed.Load() != 1 {
		t.Fatal("successful retry did not close the owned graph exactly once")
	}
}
