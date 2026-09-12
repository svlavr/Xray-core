package reverse

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	proxymanoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	xbuf "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

type reverseTestDispatcher struct {
	mu          sync.Mutex
	links       []*transport.Link
	contextSeen chan context.Context
}

type reverseCapacityHandler struct{ tag string }

func (h *reverseCapacityHandler) Tag() string                             { return h.tag }
func (*reverseCapacityHandler) Start() error                              { return nil }
func (*reverseCapacityHandler) Close() error                              { return nil }
func (*reverseCapacityHandler) Dispatch(context.Context, *transport.Link) {}
func (*reverseCapacityHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (*reverseCapacityHandler) ProxySettings() *serial.TypedMessage       { return nil }

type reverseControlReader struct {
	buffers []xbuf.MultiBuffer
	index   int
}

func (r *reverseControlReader) ReadMultiBuffer() (xbuf.MultiBuffer, error) {
	if r.index == len(r.buffers) {
		return nil, io.EOF
	}
	mb := r.buffers[r.index]
	r.index++
	return mb, nil
}

func (d *reverseTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *reverseTestDispatcher) Start() error      { return nil }
func (d *reverseTestDispatcher) Close() error      { return nil }
func (d *reverseTestDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	d.mu.Lock()
	d.links = append(d.links, link)
	d.mu.Unlock()
	if d.contextSeen != nil {
		d.contextSeen <- ctx
	}
	return link, nil
}

func (d *reverseTestDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

type reverseTestOutboundManager struct {
	mu            sync.Mutex
	handlers      map[string]outbound.Handler
	addStarted    chan struct{}
	unblockAdd    <-chan struct{}
	closeOnRemove bool
	removeErr     error
}

func (m *reverseTestOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (m *reverseTestOutboundManager) Start() error      { return nil }
func (m *reverseTestOutboundManager) Close() error {
	m.mu.Lock()
	handlers := make([]outbound.Handler, 0, len(m.handlers))
	for _, handler := range m.handlers {
		handlers = append(handlers, handler)
	}
	m.handlers = nil
	m.mu.Unlock()
	for _, handler := range handlers {
		if err := handler.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (m *reverseTestOutboundManager) GetHandler(tag string) outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handlers[tag]
}
func (m *reverseTestOutboundManager) GetDefaultHandler() outbound.Handler { return nil }
func (m *reverseTestOutboundManager) AddHandler(_ context.Context, h outbound.Handler) error {
	m.mu.Lock()
	if m.handlers == nil {
		m.handlers = make(map[string]outbound.Handler)
	}
	m.handlers[h.Tag()] = h
	started := m.addStarted
	unblock := m.unblockAdd
	m.mu.Unlock()
	if started != nil {
		close(started)
	}
	if unblock != nil {
		<-unblock
	}
	return nil
}

func (m *reverseTestOutboundManager) RemoveHandler(_ context.Context, tag string) error {
	m.mu.Lock()
	delete(m.handlers, tag)
	m.mu.Unlock()
	return nil
}

func (m *reverseTestOutboundManager) RemoveHandlerInstance(_ context.Context, handler outbound.Handler) error {
	m.mu.Lock()
	if m.removeErr != nil {
		err := m.removeErr
		m.mu.Unlock()
		return err
	}
	current := m.handlers[handler.Tag()]
	if current != handler {
		m.mu.Unlock()
		return nil
	}
	delete(m.handlers, handler.Tag())
	closeHandler := m.closeOnRemove
	m.mu.Unlock()
	if closeHandler {
		return handler.Close()
	}
	return nil
}
func (m *reverseTestOutboundManager) ListHandlers(context.Context) []outbound.Handler { return nil }

func waitReverse(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reverse lifecycle did not finish")
	}
}

func TestBridgeWorkerCloseUnblocksInternalControl(t *testing.T) {
	dispatcher := new(reverseTestDispatcher)
	worker, err := NewBridgeWorker("bridge.test", "bridge", dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	link, err := worker.Dispatch(context.Background(), net.TCPDestination(net.DomainAddress(internalDomain), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	done := make(chan struct{})
	go func() { _ = worker.Close(); close(done) }()
	waitReverse(t, done)
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReverseBridgeRetainsInstanceDialLifecycle(t *testing.T) {
	dialLifecycle := internet.NewDialLifecycle()
	ctx := internet.ContextWithDialLifecycle(context.Background(), dialLifecycle)
	dispatcher := &reverseTestDispatcher{contextSeen: make(chan context.Context, 1)}
	reverseFeature := new(Reverse)
	if err := reverseFeature.init(ctx, &Config{BridgeConfig: []*BridgeConfig{{
		Tag: "bridge", Domain: "bridge.test",
	}}}, dispatcher, new(reverseTestOutboundManager)); err != nil {
		t.Fatal(err)
	}
	if err := reverseFeature.Start(); err != nil {
		t.Fatal(err)
	}
	dispatchCtx := <-dispatcher.contextSeen
	if got := internet.DialLifecycleFromContext(dispatchCtx); got != dialLifecycle {
		t.Fatal("Bridge dispatcher path lost the Reverse Instance dial lifecycle")
	}
	if err := reverseFeature.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeControlFramesReleaseAllBuffers(t *testing.T) {
	validData, err := proto.Marshal(&Control{State: Control_ACTIVE})
	if err != nil {
		t.Fatal(err)
	}
	valid1 := xbuf.New()
	valid1.Write(validData)
	valid2 := xbuf.New()
	valid2.Write(validData)
	validWorker := &BridgeWorker{}
	validWorker.handleInternalConn(&transport.Link{Reader: &reverseControlReader{
		buffers: []xbuf.MultiBuffer{{valid1, valid2}},
	}})
	if !valid1.IsEmpty() || !valid2.IsEmpty() {
		t.Fatal("valid multi-frame control buffers were not released")
	}
	if validWorker.State != Control_ACTIVE {
		t.Fatal("valid control frames did not preserve state semantics")
	}

	malformed := xbuf.New()
	malformed.Write([]byte{0xff})
	unreadTail := xbuf.New()
	unreadTail.Write(validData)
	malformedWorker := &BridgeWorker{}
	malformedWorker.handleInternalConn(&transport.Link{Reader: &reverseControlReader{
		buffers: []xbuf.MultiBuffer{{malformed, unreadTail}},
	}})
	if !malformed.IsEmpty() || !unreadTail.IsEmpty() {
		t.Fatal("malformed control path did not release the complete MultiBuffer")
	}
}

func TestBridgeWorkerCloseUnblocksDispatchLink(t *testing.T) {
	// VLESS reverse constructs this shared wrapper as a literal and attaches
	// ServerWorker afterward, so Close must initialize its own receipt lazily.
	worker := &BridgeWorker{}
	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- worker.DispatchLink(context.Background(), net.TCPDestination(net.DomainAddress(internalDomain), 0), link)
	}()
	for {
		worker.access.Lock()
		registered := len(worker.controls) == 1
		worker.access.Unlock()
		if registered {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("BridgeWorker.Close returned before DispatchLink receipt")
	}
}

func TestBridgeDispatchKeepsAsyncContextUntilOwnerClose(t *testing.T) {
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	dispatcher := &reverseTestDispatcher{contextSeen: make(chan context.Context, 1)}
	worker := &BridgeWorker{
		Dispatcher: dispatcher,
		ctx:        ownerCtx,
		cancel:     cancelOwner,
		closeDone:  make(chan struct{}),
	}
	link, err := worker.Dispatch(ownerCtx, net.TCPDestination(net.DomainAddress("target.test"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	dispatchCtx := <-dispatcher.contextSeen
	select {
	case <-dispatchCtx.Done():
		t.Fatal("Dispatch canceled the asynchronous dataplane context on return")
	default:
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatchCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("BridgeWorker.Close did not cancel the owned dataplane context")
	}
}

func TestBridgeCloseJoinsMonitorAndWorkers(t *testing.T) {
	dispatcher := new(reverseTestDispatcher)
	bridge, err := NewBridge(&BridgeConfig{Tag: "bridge", Domain: "bridge.test"}, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	bridge.access.Lock()
	workers := append([]*BridgeWorker(nil), bridge.workers...)
	bridge.access.Unlock()
	for _, worker := range workers {
		if !worker.Closed() {
			t.Fatal("bridge retained a live worker after Close")
		}
	}
}

func TestPortalWorkerCloseJoinsControlAndClient(t *testing.T) {
	reader, writer := pipe.New()
	client, err := muxClientForReverseTest(reader, writer)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewPortalWorker(client)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = worker.Close(); close(done) }()
	waitReverse(t, done)
	if !client.Closed() {
		t.Fatal("portal close did not close client worker")
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
}

func muxClientForReverseTest(reader *pipe.Reader, writer *pipe.Writer) (*mux.ClientWorker, error) {
	return mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
}

func TestPickerSealsLatePublicationAndClosesWorkers(t *testing.T) {
	picker, err := NewStaticMuxPicker()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := pipe.New()
	client, err := muxClientForReverseTest(reader, writer)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewPortalWorker(client)
	if err != nil {
		t.Fatal(err)
	}
	if !picker.AddWorker(worker) {
		t.Fatal("initial worker was rejected")
	}
	if err := picker.Close(); err != nil {
		t.Fatal(err)
	}
	if picker.AddWorker(worker) {
		t.Fatal("closed picker accepted a late worker")
	}
	if !worker.Closed() {
		t.Fatal("picker close did not close worker")
	}
}

func TestPortalOutboundAndReverseCloseAreIdempotent(t *testing.T) {
	manager := new(reverseTestOutboundManager)
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	handler := manager.GetHandler("portal")
	if handler == nil {
		t.Fatal("portal handler not registered")
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := portal.Close(); err != nil {
		t.Fatal(err)
	}

	bridge, err := NewBridge(&BridgeConfig{Tag: "bridge", Domain: "bridge.test"}, new(reverseTestDispatcher))
	if err != nil {
		t.Fatal(err)
	}
	reverse := &Reverse{bridges: []*Bridge{bridge}, portals: []*Portal{portal}}
	if err := reverse.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reverse.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReverseCloseRemovesLivePortalBeforeStopping(t *testing.T) {
	manager := new(reverseTestOutboundManager)
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	reverse := &Reverse{portals: []*Portal{portal}}
	if err := reverse.Close(); err != nil {
		t.Fatal(err)
	}
	if handler := manager.GetHandler("portal"); handler != nil {
		t.Fatal("Reverse.Close left a live synthetic handler published")
	}
	if !portal.lifecycle.Sealed() {
		t.Fatal("Reverse.Close did not stop the portal after exact removal")
	}
}

func TestReverseCloseCapacityFailureIsRetryable(t *testing.T) {
	manager := &reverseTestOutboundManager{removeErr: &core.RetirementCapacityExhaustedError{Capacity: 50}}
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	reverse := &Reverse{portals: []*Portal{portal}}
	if err := reverse.Close(); err == nil {
		t.Fatal("capacity exhaustion did not fail Reverse.Close")
	}
	reverse.access.Lock()
	stopped := reverse.stopped
	reverse.access.Unlock()
	if stopped || portal.lifecycle.Sealed() {
		t.Fatal("capacity failure stopped the still-active reverse graph")
	}
	manager.mu.Lock()
	manager.removeErr = nil
	manager.mu.Unlock()
	if err := reverse.Close(); err != nil {
		t.Fatal(err)
	}
	if handler := manager.GetHandler("portal"); handler != nil {
		t.Fatal("retry did not remove the synthetic handler")
	}
}

func TestReversePartialCapacityFailureThenInstanceShutdown(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	manager, err := proxymanoutbound.New(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.AddFeature(manager); err != nil {
		t.Fatal(err)
	}

	const release1RetirementCapacity = 50
	holds := make([]outbound.HandlerEntry, 0, release1RetirementCapacity-1)
	for i := 0; i < release1RetirementCapacity-1; i++ {
		tag := fmt.Sprintf("held-%d", i)
		handler := &reverseCapacityHandler{tag: tag}
		if err := manager.AddHandler(ctx, handler); err != nil {
			t.Fatal(err)
		}
		entry, err := manager.EnterHandler(ctx, tag)
		if err != nil {
			t.Fatal(err)
		}
		holds = append(holds, entry)
		if err := manager.RemoveHandler(ctx, tag); err != nil {
			t.Fatal(err)
		}
	}

	portal1, err := NewPortal(&PortalConfig{Tag: "portal-1", Domain: "portal-1.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	portal2, err := NewPortal(&PortalConfig{Tag: "portal-2", Domain: "portal-2.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal1.Start(); err != nil {
		t.Fatal(err)
	}
	if err := portal2.Start(); err != nil {
		t.Fatal(err)
	}
	portal1Hold, err := manager.EnterHandler(ctx, "portal-1")
	if err != nil {
		t.Fatal(err)
	}
	reverseFeature := &Reverse{portals: []*Portal{portal1, portal2}}
	if err := instance.AddFeature(reverseFeature); err != nil {
		t.Fatal(err)
	}

	err = reverseFeature.Close()
	var exhausted *core.RetirementCapacityExhaustedError
	if !stderrors.As(err, &exhausted) {
		t.Fatalf("Reverse.Close error = %v, want retirement capacity exhaustion", err)
	}
	if manager.GetHandler("portal-1") != nil {
		t.Fatal("first portal was not committed to retirement")
	}
	if manager.GetHandler("portal-2") == nil {
		t.Fatal("second portal did not remain ACTIVE after its failed reservation")
	}
	if reverseFeature.stopped || portal2.lifecycle.Sealed() {
		t.Fatal("partial retirement failure falsely completed the reverse graph")
	}

	portal1Hold.Release()
	for _, hold := range holds {
		hold.Release()
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler("portal-2") != nil {
		t.Fatal("Instance shutdown left the active portal registered")
	}
}

func TestPortalCloseSupportsSynchronousExactHandlerClose(t *testing.T) {
	manager := &reverseTestOutboundManager{closeOnRemove: true}
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- portal.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Portal.Close deadlocked with synchronous handler Close")
	}
}

func TestPortalRetirementCapacityFailureLeavesActiveAndRetryable(t *testing.T) {
	manager := &reverseTestOutboundManager{removeErr: &core.RetirementCapacityExhaustedError{Capacity: 50}}
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	handler := manager.GetHandler("portal")
	if err := portal.Close(); err == nil {
		t.Fatal("capacity exhaustion did not fail Portal.Close")
	}
	if portal.lifecycle.Sealed() {
		t.Fatal("capacity failure sealed portal admission")
	}
	portal.picker.access.Lock()
	pickerSealed := portal.picker.sealed
	portal.picker.access.Unlock()
	if pickerSealed {
		t.Fatal("capacity failure stopped the active portal picker")
	}
	if got := manager.GetHandler("portal"); got != handler {
		t.Fatal("capacity failure changed the active handler")
	}
	manager.mu.Lock()
	manager.removeErr = nil
	manager.mu.Unlock()
	if err := portal.Close(); err != nil {
		t.Fatal(err)
	}
	if got := manager.GetHandler("portal"); got != nil {
		t.Fatal("retry did not remove the exact portal handler")
	}
}

func TestLatePortalHandlerCloseCannotRemoveReplacement(t *testing.T) {
	manager := new(reverseTestOutboundManager)
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	oldHandler := manager.GetHandler("portal")
	if oldHandler == nil {
		t.Fatal("portal handler not registered")
	}
	if err := manager.RemoveHandlerInstance(context.Background(), oldHandler); err != nil {
		t.Fatal(err)
	}
	replacement := &Outbound{tag: "portal"}
	if err := manager.AddHandler(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := oldHandler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := portal.Close(); err != nil {
		t.Fatal(err)
	}
	if got := manager.GetHandler("portal"); got != replacement {
		t.Fatal("late old handler cleanup removed same-tag replacement")
	}
}

func TestManagerDrivenPortalCloseDoesNotReRemoveHandler(t *testing.T) {
	manager := new(reverseTestOutboundManager)
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(); err != nil {
		t.Fatal(err)
	}
	portal.SignalStop()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := portal.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeStartAndCloseDoNotRestartMonitor(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		bridge, err := NewBridge(&BridgeConfig{Tag: "bridge", Domain: "bridge.test"}, new(reverseTestDispatcher))
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		startDone := make(chan error, 1)
		closeDone := make(chan error, 1)
		go func() { <-start; startDone <- bridge.Start() }()
		go func() { <-start; closeDone <- bridge.Close() }()
		close(start)
		<-startDone
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
		if err := bridge.Start(); err == nil {
			t.Fatalf("iteration %d: closed bridge restarted monitor", iteration)
		}
	}
}

func TestPickerConcurrentStopAndSelection(t *testing.T) {
	picker, err := NewStaticMuxPicker()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := pipe.New()
	client, err := muxClientForReverseTest(reader, writer)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewPortalWorker(client)
	if err != nil {
		t.Fatal(err)
	}
	if !picker.AddWorker(worker) {
		t.Fatal("worker rejected")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := picker.PickAvailable(); err != nil {
				return
			}
		}
	}()
	if err := picker.Close(); err != nil {
		t.Fatal(err)
	}
	waitReverse(t, done)
}

func TestPortalStartAndCloseDoNotLeaveLateHandler(t *testing.T) {
	unblock := make(chan struct{})
	manager := &reverseTestOutboundManager{addStarted: make(chan struct{}), unblockAdd: unblock}
	portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	startDone := make(chan error, 1)
	go func() { startDone <- portal.Start() }()
	waitReverse(t, manager.addStarted)
	closeDone := make(chan error, 1)
	go func() { closeDone <- portal.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before the admitted Start completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(unblock)
	_ = <-startDone
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if handler := manager.GetHandler("portal"); handler != nil {
		t.Fatal("close left a handler published after concurrent Start")
	}
}

func TestPortalStartClosePrepublicationRaceDoesNotLeakHandler(t *testing.T) {
	for iteration := 0; iteration < 500; iteration++ {
		manager := new(reverseTestOutboundManager)
		portal, err := NewPortal(&PortalConfig{Tag: "portal", Domain: "portal.test"}, manager)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		startDone := make(chan error, 1)
		closeDone := make(chan error, 1)
		go func() { <-start; startDone <- portal.Start() }()
		go func() { <-start; closeDone <- portal.Close() }()
		close(start)
		<-startDone
		if err := <-closeDone; err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		if handler := manager.GetHandler("portal"); handler != nil {
			t.Fatalf("iteration %d: concurrent Start published a handler after Close", iteration)
		}
	}
}
