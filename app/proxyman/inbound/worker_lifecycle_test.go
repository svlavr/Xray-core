package inbound

import (
	stderrors "errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/pipe"
)

type phasedWorker struct {
	proxy          proxy.Inbound
	all            []*phasedWorker
	stops          *atomic.Int32
	phaseViolation *atomic.Bool
	startErr       error
	startCalls     *atomic.Int32
	sealed         atomic.Bool
}

func (w *phasedWorker) Start() error {
	if w.startCalls != nil {
		w.startCalls.Add(1)
	}
	return w.startErr
}
func (w *phasedWorker) Seal() { w.sealed.Store(true) }
func (w *phasedWorker) Stop() error {
	for _, peer := range w.all {
		if !peer.sealed.Load() {
			w.phaseViolation.Store(true)
		}
	}
	w.stops.Add(1)
	return nil
}

func (w *phasedWorker) Wait() error {
	if got, want := w.stops.Load(), int32(len(w.all)); got != want {
		w.phaseViolation.Store(true)
	}
	if owner, ok := w.proxy.(*preparingInbound); ok && owner.closed.Load() == 0 {
		w.phaseViolation.Store(true)
	}
	if owner, ok := w.proxy.(*preparingInbound); ok && owner.closeSignal != nil {
		<-owner.closeSignal
	}
	return nil
}
func (w *phasedWorker) Close() error         { w.Seal(); _ = w.Stop(); return w.Wait() }
func (*phasedWorker) Port() net.Port         { return 0 }
func (w *phasedWorker) Proxy() proxy.Inbound { return w.proxy }

func TestAlwaysOnCloseStopsAllWorkersBeforeWaitAndClosesProxyOnce(t *testing.T) {
	p := &preparingInbound{}
	var stops atomic.Int32
	var violation atomic.Bool
	first := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation}
	second := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation}
	workers := []*phasedWorker{first, second}
	first.all, second.all = workers, workers
	h := &AlwaysOnInboundHandler{proxy: p, workers: []worker{first, second}, started: []worker{first, second}}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if violation.Load() {
		t.Fatal("worker shutdown did not preserve seal-all, stop-all, wait-all order")
	}
	if got := p.closed.Load(); got != 1 {
		t.Fatalf("shared proxy close calls = %d, want 1", got)
	}
}

func TestAlwaysOnCloseSignalsProxyBeforeWorkerReceiptJoin(t *testing.T) {
	p := &preparingInbound{closeSignal: make(chan struct{})}
	var stops atomic.Int32
	var violation atomic.Bool
	first := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation}
	second := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation}
	workers := []*phasedWorker{first, second}
	first.all, second.all = workers, workers
	h := &AlwaysOnInboundHandler{proxy: p, workers: []worker{first, second}, started: []worker{first, second}}
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler deadlocked waiting for receipts before proxy stop")
	}
	if violation.Load() || stops.Load() != 2 || p.closed.Load() != 1 {
		t.Fatal("proxy stop did not follow seal-all, stop-all and precede worker waits")
	}
}

func TestAlwaysOnStartFailureRollsBackStartedAndFailedWorkers(t *testing.T) {
	p := &preparingInbound{}
	var stops atomic.Int32
	var violation atomic.Bool
	want := stderrors.New("second worker start failed")
	first := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation}
	second := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation, startErr: want}
	workers := []*phasedWorker{first, second}
	first.all, second.all = workers, workers
	h := &AlwaysOnInboundHandler{proxy: p, workers: []worker{first, second}}
	if err := h.Start(); err == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("Start error = %v, want %v", err, want)
	}
	if violation.Load() || stops.Load() != 2 {
		t.Fatal("partial Start did not stop and join both adopted workers")
	}
	if got := p.closed.Load(); got != 1 {
		t.Fatalf("rollback proxy close calls = %d, want 1", got)
	}
}

func TestAlwaysOnStartFailureWithPrepareRefusalForbidsRestartButAllowsCloseRetry(t *testing.T) {
	wantStart := stderrors.New("second worker start failed")
	wantPrepare := stderrors.New("retirement capacity unavailable")
	p := &preparingInbound{prepareErr: wantPrepare}
	var starts atomic.Int32
	var stops atomic.Int32
	var violation atomic.Bool
	first := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation, startCalls: &starts}
	second := &phasedWorker{proxy: p, stops: &stops, phaseViolation: &violation, startErr: wantStart, startCalls: &starts}
	workers := []*phasedWorker{first, second}
	first.all, second.all = workers, workers
	h := &AlwaysOnInboundHandler{proxy: p, workers: []worker{first, second}}
	if err := h.Start(); err == nil || !strings.Contains(err.Error(), wantStart.Error()) || !strings.Contains(err.Error(), wantPrepare.Error()) {
		t.Fatalf("Start error = %v, want both start and PrepareClose failures", err)
	}
	if got := starts.Load(); got != 2 {
		t.Fatalf("initial worker Start calls = %d, want 2", got)
	}
	if err := h.Start(); err == nil {
		t.Fatal("failed partial graph admitted a second Start")
	}
	if got := starts.Load(); got != 2 {
		t.Fatalf("restart reached workers: Start calls = %d", got)
	}
	if stops.Load() != 0 || p.closed.Load() != 0 {
		t.Fatal("PrepareClose refusal destroyed the retained partial graph")
	}
	p.prepareErr = nil
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if violation.Load() || stops.Load() != 2 || p.closed.Load() != 1 {
		t.Fatal("Close retry did not stop and release the retained partial graph")
	}
}

func TestUDPWorkerCloseWaitsForAssociationReceipt(t *testing.T) {
	reader, writer := pipe.New(pipe.DiscardOverflow())
	conn := &udpConn{reader: reader, writer: writer, done: done.New()}
	w := &udpWorker{activeConn: map[connID]*udpConn{{}: conn}, joinDirect: true}
	if !w.lifecycle.Acquire() {
		t.Fatal("association receipt was rejected")
	}
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case <-conn.done.Wait():
	case <-time.After(time.Second):
		t.Fatal("UDP worker did not close the active association")
	}
	select {
	case err := <-closed:
		t.Fatalf("UDP worker Close returned before association receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	w.lifecycle.Release()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP worker did not join the association receipt")
	}
}

func TestUDPWorkerSealedCheckerCannotRestart(t *testing.T) {
	w := &udpWorker{joinDirect: true}
	w.Seal()
	if err := w.startChecker(); err == nil {
		t.Fatal("sealed UDP worker restarted its periodic checker")
	}
}

func TestJoinedIngressScopeIncludesAcceptedTransportsAndExcludesOtherOwners(t *testing.T) {
	for _, protocol := range []string{"tcp", "httpupgrade", "websocket", "grpc"} {
		if !streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: protocol}) {
			t.Fatalf("%s was excluded from its accepted ingress join", protocol)
		}
	}
	if !tcpStreamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "hysteria"}) {
		t.Fatal("Hysteria was excluded from its accepted TCP-worker ingress join")
	}
	if !tcpStreamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "mkcp"}) {
		t.Fatal("mKCP was excluded from its accepted TCP-worker ingress join")
	}
	if streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "hysteria"}) {
		t.Fatal("Hysteria was admitted to the UNIX-worker ingress join")
	}
	if tcpStreamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "hysteria", UdpmaskManager: &finalmask.UdpmaskManager{}}) {
		t.Fatal("UDP mask work was admitted to the Hysteria claim")
	}
	if tcpStreamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "mkcp", UdpmaskManager: &finalmask.UdpmaskManager{}}) {
		t.Fatal("UDP mask work was admitted to the mKCP claim")
	}
	if !streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "splithttp"}) {
		t.Fatal("mask-free, non-REALITY SplitHTTP was excluded from its joined inbound scope")
	}
	if streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "splithttp", UdpmaskManager: &finalmask.UdpmaskManager{}}) {
		t.Fatal("UDP mask work was admitted to the SplitHTTP claim")
	}
	if streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "splithttp", SecurityType: "reality"}) {
		t.Fatal("REALITY work was admitted to the SplitHTTP claim")
	}
	if streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "grpc", SecurityType: "reality"}) {
		t.Fatal("REALITY background work was admitted to the gRPC claim")
	}
	if streamJoinSupported(&internet.MemoryStreamConfig{ProtocolName: "websocket", TcpmaskManager: &finalmask.TcpmaskManager{}}) {
		t.Fatal("TCP mask work was admitted to the WebSocket claim")
	}
	if directUDPJoinSupported(&internet.MemoryStreamConfig{UdpmaskManager: &finalmask.UdpmaskManager{}}) {
		t.Fatal("UDP mask work was admitted to the direct UDP claim")
	}
}
