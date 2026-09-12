package mux

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type lifecycleTestCarrier struct{ attaches atomic.Int32 }

func (c *lifecycleTestCarrier) AttachTo(session.MuxClientSessionObservation) { c.attaches.Add(1) }

type lifecycleTestAuthority struct {
	created atomic.Int32
	carrier *lifecycleTestCarrier
}

type lifecycleAccountingCarrier struct {
	lifecycleTestCarrier
	commits  atomic.Int32
	aborts   atomic.Int32
	quiesced atomic.Int32
}

func (*lifecycleAccountingCarrier) Read(uint64)         {}
func (*lifecycleAccountingCarrier) Write(uint64, error) {}
func (c *lifecycleAccountingCarrier) Commit()           { c.commits.Add(1) }
func (c *lifecycleAccountingCarrier) Abort()            { c.aborts.Add(1) }
func (c *lifecycleAccountingCarrier) WorkerQuiesced()   { c.quiesced.Add(1) }
func (c *lifecycleAccountingCarrier) ClientFrameObservation() session.MuxClientCarrierFrameObservation {
	return c
}

type lifecycleAccountingAuthority struct{ carrier *lifecycleAccountingCarrier }

func (a *lifecycleAccountingAuthority) NewMuxClientCarrierObservation() session.MuxClientCarrierObservation {
	return a.carrier
}

func (a *lifecycleTestAuthority) NewMuxClientCarrierObservation() session.MuxClientCarrierObservation {
	a.created.Add(1)
	return a.carrier
}

type lifecycleBlockingProxy struct {
	started chan struct{}
	done    chan struct{}
}

func (p *lifecycleBlockingProxy) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) error {
	close(p.started)
	<-ctx.Done()
	close(p.done)
	return ctx.Err()
}

type closeBeforeGateCarrier struct {
	attached chan struct{}
	release  chan struct{}
}

func (c *closeBeforeGateCarrier) AttachTo(session.MuxClientSessionObservation) {
	close(c.attached)
	<-c.release
}

type closeBeforeGateScope struct{}

func (*closeBeforeGateScope) NewCarrier() session.MuxClientCarrierObservation {
	panic("worker authority must not be reminted")
}

type closeBeforeGateWriter struct{ writes atomic.Int32 }

func (w *closeBeforeGateWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	w.writes.Add(1)
	return nil
}

type closeBeforeGateReader struct{ reads atomic.Int32 }

func (r *closeBeforeGateReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.reads.Add(1)
	return nil, context.Canceled
}

func TestClientWorkerCloseBeforeSessionGateCleansWithoutInputStart(t *testing.T) {
	carrier := &closeBeforeGateCarrier{attached: make(chan struct{}), release: make(chan struct{})}
	encodedWriter := new(closeBeforeGateWriter)
	worker, err := newClientWorkerPrepared(transport.Link{Writer: encodedWriter}, ClientStrategy{}, carrier, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.timer.Stop()

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("d4.example"), 443),
	}})
	ctx = session.ContextWithMuxClientSessionObservation(ctx, new(closeBeforeGateScope))
	dispatched := make(chan bool, 1)
	go func() {
		dispatched <- worker.Dispatch(ctx, &transport.Link{
			Reader: buf.NewReader(strings.NewReader("payload")),
			Writer: buf.Discard,
		})
	}()

	select {
	case <-carrier.attached:
		// Dispatch has committed the gated session but cannot resolve its gate.
	case <-time.After(time.Second):
		t.Fatal("Dispatch did not reach the post-commit AttachTo gate")
	}

	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	if !worker.sessionManager.Closed() {
		t.Fatal("worker Close returned before the session allocation barrier closed")
	}
	close(carrier.release)
	select {
	case ok := <-dispatched:
		if !ok {
			t.Fatal("post-commit Dispatch retried after cleanup-only gate resolution")
		}
	case <-time.After(time.Second):
		t.Fatal("Dispatch did not resolve after cleanup-only gate release")
	}
	worker.Wait()
	if got := encodedWriter.writes.Load(); got != 0 {
		t.Fatalf("encoded input performed %d writes after worker Close won the gate", got)
	}
}

func TestClientWorkerCloseBeforeDownlinkGateDoesNotDrainPayload(t *testing.T) {
	worker, err := newClientWorkerPrepared(transport.Link{}, ClientStrategy{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.timer.Stop()

	s := worker.sessionManager.Allocate(&worker.strategy)
	if s == nil {
		t.Fatal("failed to reproduce committed gated session")
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	reader := new(closeBeforeGateReader)
	err = worker.handleStatusKeepSession(s, &FrameMetadata{}, &buf.BufferedReader{Reader: reader})
	if err != errClientSessionGateClosed {
		t.Fatalf("cleanup-only downlink result = %v, want %v", err, errClientSessionGateClosed)
	}
	if got := reader.reads.Load(); got != 0 {
		t.Fatalf("cleanup-only downlink drained %d payload buffers", got)
	}
}

func TestClientWorkerClosedManagerDoesNotEmitMissingSessionEnd(t *testing.T) {
	encodedWriter := new(closeBeforeGateWriter)
	worker, err := newClientWorkerPrepared(transport.Link{Writer: encodedWriter}, ClientStrategy{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.timer.Stop()
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}

	reader := new(closeBeforeGateReader)
	err = worker.handleStatusKeep(
		&FrameMetadata{SessionID: 1, SessionStatus: SessionStatusKeep, Option: OptionData},
		&buf.BufferedReader{Reader: reader},
	)
	if err != errClientSessionGateClosed {
		t.Fatalf("closed-manager Keep result = %v, want %v", err, errClientSessionGateClosed)
	}
	if got := encodedWriter.writes.Load(); got != 0 {
		t.Fatalf("closed manager emitted %d missing-session END frames", got)
	}
	if got := reader.reads.Load(); got != 0 {
		t.Fatalf("closed manager drained %d payload buffers", got)
	}
}

func TestFactoryCreatesEarlyAuthorityBeforeProcessPublication(t *testing.T) {
	authority := &lifecycleTestAuthority{carrier: new(lifecycleTestCarrier)}
	proxy := &lifecycleBlockingProxy{started: make(chan struct{}), done: make(chan struct{})}
	factory := &DialingWorkerFactory{Proxy: proxy}
	worker, err := factory.CreateWithMuxClientCarrierAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("proxy Process was not published")
	}
	if got := authority.created.Load(); got != 1 || worker.flowCarrier.Load() == nil {
		t.Fatalf("early authority not installed before publication: created=%d", got)
	}
	common.Must(worker.Close())
	worker.Wait()
	select {
	case <-proxy.done:
	default:
		t.Fatal("worker receipt preceded factory Process return")
	}
}

func TestFactoryCommitsClientAccountingBeforePublicationAndQuiescesAfterProcess(t *testing.T) {
	carrier := new(lifecycleAccountingCarrier)
	proxy := &lifecycleBlockingProxy{started: make(chan struct{}), done: make(chan struct{})}
	worker, err := (&DialingWorkerFactory{Proxy: proxy}).CreateWithMuxClientCarrierAuthority(&lifecycleAccountingAuthority{carrier: carrier})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-proxy.started:
	case <-time.After(time.Second):
		t.Fatal("proxy Process was not published")
	}
	if carrier.commits.Load() != 1 || carrier.aborts.Load() != 0 {
		t.Fatalf("client accounting was not committed exactly once before Process: commit=%d abort=%d", carrier.commits.Load(), carrier.aborts.Load())
	}
	if carrier.quiesced.Load() != 0 {
		t.Fatal("client carrier terminal receipt preceded worker close")
	}
	common.Must(worker.Close())
	worker.Wait()
	select {
	case <-proxy.done:
	default:
		t.Fatal("client carrier quiescence preceded factory Process return")
	}
	if carrier.quiesced.Load() != 1 {
		t.Fatalf("client carrier quiescence receipts = %d, want 1", carrier.quiesced.Load())
	}
	worker.Wait()
	if carrier.quiesced.Load() != 1 {
		t.Fatalf("worker forwarded the terminal receipt more than once: %d", carrier.quiesced.Load())
	}
}

type lifecycleBlockingFactory struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *lifecycleBlockingFactory) Create() (*ClientWorker, error) {
	f.calls.Add(1)
	f.once.Do(func() { close(f.entered) })
	<-f.release
	r, w := pipe.New(pipe.WithoutSizeLimit())
	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	worker, err := NewClientWorker(transport.Link{Reader: r, Writer: w2}, ClientStrategy{})
	if err == nil {
		go func() {
			<-worker.done.Wait()
			common.Close(w)
			common.Interrupt(r2)
		}()
	}
	return worker, err
}

func TestPickerSingleflightCreationAndCloseReceipt(t *testing.T) {
	factory := &lifecycleBlockingFactory{entered: make(chan struct{}), release: make(chan struct{})}
	picker := &IncrementalWorkerPicker{Factory: factory}
	const callers = 16
	results := make(chan error, callers)
	for range callers {
		go func() {
			_, err := picker.PickAvailable()
			results <- err
		}()
	}
	<-factory.entered
	closeDone := make(chan struct{})
	go func() {
		picker.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("picker close did not wait for in-flight creation")
	case <-time.After(20 * time.Millisecond):
	}
	close(factory.release)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("picker close did not finish after creation receipt")
	}
	for range callers {
		<-results
	}
	if got := factory.calls.Load(); got != 1 {
		t.Fatalf("factory called %d times, want 1", got)
	}
}

func TestPickerSignalStopDoesNotWaitForInFlightCreation(t *testing.T) {
	factory := &lifecycleBlockingFactory{entered: make(chan struct{}), release: make(chan struct{})}
	picker := &IncrementalWorkerPicker{Factory: factory}
	picked := make(chan error, 1)
	go func() {
		_, err := picker.PickAvailable()
		picked <- err
	}()
	<-factory.entered
	signaled := make(chan struct{})
	go func() {
		picker.SignalStop()
		close(signaled)
	}()
	select {
	case <-signaled:
	case <-time.After(time.Second):
		t.Fatal("SignalStop waited for in-flight creation")
	}
	close(factory.release)
	if err := <-picked; err == nil {
		t.Fatal("sealed picker published the late worker")
	}
	picker.Wait()
}

func TestMuxFactoryContinuationDrainsOnlyAfterWorkerReceipt(t *testing.T) {
	ledger := core.NewRetirementLedgerForValidation(1)
	generation, err := ledger.Register(new(struct{}), "mux")
	if err != nil {
		t.Fatal(err)
	}
	root, ok := generation.AcquireRoot()
	if !ok {
		t.Fatal("root not admitted")
	}
	ctx := core.ContextWithRetirementRight(context.Background(), root)
	proxy := &lifecycleBlockingProxy{started: make(chan struct{}), done: make(chan struct{})}
	picker := &IncrementalWorkerPicker{Factory: &DialingWorkerFactory{Proxy: proxy}}
	worker, err := picker.PickAvailableContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	<-proxy.started
	if err := ledger.ReserveRetirement(generation); err != nil {
		t.Fatal(err)
	}
	picker.Retire()
	generation.Retire()
	root.Release()
	select {
	case <-generation.Drained():
		t.Fatal("generation drained before worker continuation receipt")
	default:
	}
	ledger.SealAndSnapshot()
	picker.SignalStop()
	picker.Wait()
	worker.Wait()
	select {
	case <-proxy.done:
	default:
		t.Fatal("worker receipt preceded factory Process return")
	}
	select {
	case <-generation.Drained():
	case <-time.After(time.Second):
		t.Fatal("worker continuation did not release generation")
	}
	generation.Release()
	ledger.Wait()
}

func TestMuxPickerAllowsAlreadyEnteredInvocationAfterRetirement(t *testing.T) {
	ledger := core.NewRetirementLedgerForValidation(1)
	generation, err := ledger.Register(new(struct{}), "mux")
	if err != nil {
		t.Fatal(err)
	}
	root, ok := generation.AcquireRoot()
	if !ok {
		t.Fatal("root not admitted")
	}
	ctx := core.ContextWithRetirementRight(context.Background(), root)
	proxy := &lifecycleBlockingProxy{started: make(chan struct{}), done: make(chan struct{})}
	picker := &IncrementalWorkerPicker{Factory: &DialingWorkerFactory{Proxy: proxy}}
	if err := ledger.ReserveRetirement(generation); err != nil {
		t.Fatal(err)
	}
	generation.Retire()
	picker.Retire()
	worker, err := picker.PickAvailableContext(ctx)
	if err != nil {
		t.Fatalf("already-entered picker invocation rejected: %v", err)
	}
	<-proxy.started
	root.Release()
	ledger.SealAndSnapshot()
	picker.SignalStop()
	picker.Wait()
	worker.Wait()
	<-generation.Drained()
	generation.Release()
}

func TestPickerCleanupReleasesWorkerOnlyAfterReceipt(t *testing.T) {
	fromReader, fromWriter := pipe.New(pipe.WithoutSizeLimit())
	toReader, toWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := NewClientWorker(transport.Link{Reader: fromReader, Writer: toWriter}, ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	picker := &IncrementalWorkerPicker{workers: []*ClientWorker{worker}}
	common.Must(worker.Close())
	common.Close(fromWriter)
	common.Interrupt(toReader)
	if err := picker.cleanupFunc(); err != nil {
		t.Fatal(err)
	}
	worker.Wait()
	_ = picker.cleanupFunc()
	picker.access.Lock()
	defer picker.access.Unlock()
	if len(picker.workers) != 0 || len(picker.retired) != 0 {
		t.Fatalf("completed worker retained: active=%d retired=%d", len(picker.workers), len(picker.retired))
	}
}

type lifecycleAlreadyClosedFactory struct {
	release chan struct{}
}

func (f *lifecycleAlreadyClosedFactory) Create() (*ClientWorker, error) {
	fromReader, fromWriter := pipe.New(pipe.WithoutSizeLimit())
	toReader, toWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := NewClientWorker(transport.Link{Reader: fromReader, Writer: toWriter}, ClientStrategy{})
	if err != nil {
		return nil, err
	}
	if !worker.lifecycle.Acquire() {
		panic("worker lifecycle sealed during construction")
	}
	common.Must(worker.Close())
	common.Close(fromWriter)
	common.Interrupt(toReader)
	go func() {
		<-f.release
		worker.lifecycle.Release()
	}()
	return worker, nil
}

func TestPickerInitialCleanupDoesNotJoinRetiredWorker(t *testing.T) {
	factory := &lifecycleAlreadyClosedFactory{release: make(chan struct{})}
	picker := &IncrementalWorkerPicker{Factory: factory}
	picked := make(chan error, 1)
	go func() {
		_, err := picker.PickAvailable()
		picked <- err
	}()
	select {
	case err := <-picked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial cleanup joined a retired worker before owner stop")
	}
	closed := make(chan struct{})
	go func() {
		picker.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("owner Wait completed before retired worker receipt")
	case <-time.After(20 * time.Millisecond):
	}
	close(factory.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("owner Wait did not complete after retired worker receipt")
	}
}
