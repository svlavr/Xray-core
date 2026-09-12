package mux

import (
	"context"
	"sync"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type xudpExperimentDispatcher struct {
	mu         sync.Mutex
	dispatches int
	links      []*transport.Link
	dispatched chan struct{}
	registry   *flow_observation.Registry
}

func (d *xudpExperimentDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if d.registry != nil {
		scope := flow_observation.XUDPObservationFromContext(ctx)
		if scope == nil || d.registry.AdmitXUDP(scope, destination) == nil {
			return nil, context.Canceled
		}
	}
	owner, downstream := xudpExperimentLinkPair()
	d.mu.Lock()
	d.dispatches++
	d.links = append(d.links, owner)
	d.mu.Unlock()
	d.dispatched <- struct{}{}
	return downstream, nil
}

func (d *xudpExperimentDispatcher) NewXUDPObservation(destination net.Destination, source string) session.XUDPEpochObservation {
	if d == nil || d.registry == nil {
		return nil
	}
	return d.registry.NewXUDPObservation(destination, source)
}

func (*xudpExperimentDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (*xudpExperimentDispatcher) Start() error      { return nil }
func (*xudpExperimentDispatcher) Close() error      { return nil }
func (*xudpExperimentDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *xudpExperimentDispatcher) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dispatches
}

func (d *xudpExperimentDispatcher) link(t testing.TB, index int) *transport.Link {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if index >= len(d.links) {
		t.Fatalf("missing downstream link %d", index)
	}
	return d.links[index]
}

func xudpExperimentLinkPair() (*transport.Link, *transport.Link) {
	opt := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(opt)
	downlinkReader, downlinkWriter := pipe.New(opt)
	return &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
}

func xudpExperimentReset(t testing.TB) {
	t.Helper()
	XUDPManager.Lock()
	XUDPManager.Map = make(map[[8]byte]*XUDP)
	XUDPManager.Unlock()
	t.Cleanup(func() {
		XUDPManager.Lock()
		XUDPManager.Map = make(map[[8]byte]*XUDP)
		XUDPManager.Unlock()
	})
}

func xudpExperimentWorker(t testing.TB, dispatcher *xudpExperimentDispatcher) (*ServerWorker, *transport.Link) {
	t.Helper()
	serverLink, peerLink := xudpExperimentLinkPair()
	worker, err := NewServerWorker(context.Background(), dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dispatcher.mu.Lock()
		links := append([]*transport.Link(nil), dispatcher.links...)
		dispatcher.mu.Unlock()
		for _, link := range links {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
		deadline := time.Now().Add(time.Second)
		for worker.ActiveConnections() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if active := worker.ActiveConnections(); active != 0 {
			t.Errorf("XUDP experiment cleanup retained %d sessions", active)
		}
		common.Interrupt(peerLink.Reader)
		common.Interrupt(peerLink.Writer)
		select {
		case <-worker.WaitClosed():
		case <-time.After(time.Second):
			t.Error("XUDP experiment worker did not stop after peer close")
		}
	})
	return worker, peerLink
}

func xudpExperimentWrite(t testing.TB, writer buf.Writer, sessionID uint16, target net.Destination, globalID [8]byte, payload string) {
	t.Helper()
	packet := buf.FromBytes([]byte(payload))
	packet.UDP = &target
	if err := NewWriter(sessionID, target, writer, protocol.TransferTypePacket, globalID, nil).WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
}

func xudpExperimentReadPacket(t testing.TB, reader buf.Reader, wantTarget net.Destination, wantPayload string) {
	t.Helper()
	timeoutReader, ok := reader.(buf.TimeoutReader)
	if !ok {
		t.Fatal("XUDP experiment reader has no bounded read")
	}
	mb, err := timeoutReader.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || mb[0].String() != wantPayload || mb[0].UDP == nil || mb[0].UDP.String() != wantTarget.String() {
		t.Fatalf("XUDP packet changed: payload=%q target=%v", mb.String(), mb[0].UDP)
	}
}

func TestXUDPExperimentSameIDReuseForwardsNewPacketTarget(t *testing.T) {
	xudpExperimentReset(t)
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 2)}
	_, peer := xudpExperimentWorker(t, dispatcher)
	id := [8]byte{1}
	first := net.UDPDestination(net.DomainAddress("first.xudp.example"), 53)
	second := net.UDPDestination(net.DomainAddress("second.xudp.example"), 5353)

	xudpExperimentWrite(t, peer.Writer, 1, first, id, "a")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("first XUDP request was not dispatched")
	}
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, first, "a")

	xudpExperimentWrite(t, peer.Writer, 2, second, id, "b")
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, second, "b")
	if got := dispatcher.count(); got != 1 {
		t.Fatalf("same GlobalID dispatched %d downstream links, want 1", got)
	}
}

func TestXUDPExperimentServerWorkerPublishesFreshBindingFlowReference(t *testing.T) {
	xudpExperimentReset(t)
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 1), registry: registry}
	_, peer := xudpExperimentWorker(t, dispatcher)
	destination := net.UDPDestination(net.DomainAddress("observed.xudp.example"), 53)
	xudpExperimentWrite(t, peer.Writer, 1, destination, [8]byte{9}, "first")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("real ServerWorker did not dispatch observed XUDP frame")
	}
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := registry.Snapshot()
		if len(snapshot.Records) == 1 && len(snapshot.Records[0].XUDPBindings) == 1 {
			record := snapshot.Records[0]
			if record.FlowKind != flow_observation.KindXUDPLogical || record.XUDPBindings[0].Ordinal != 1 || record.CarrierReference == "" {
				t.Fatalf("unexpected fresh XUDP record: %+v", record)
			}
			for _, event := range registry.EventsAfter(0, 16).Events {
				if event.Type == flow_observation.EventXUDPBindingTransition && event.XUDPBinding != nil {
					if event.XUDPBinding.FlowID != record.FlowID || event.XUDPBinding.RuntimeInstanceID != record.RuntimeInstanceID {
						t.Fatalf("binding event has empty/foreign FlowRef: %+v", event.XUDPBinding)
					}
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("observed XUDP record was not published: %+v", registry.Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestXUDPExperimentInitializingCollisionIsConsumed(t *testing.T) {
	xudpExperimentReset(t)
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 2)}
	worker, peer := xudpExperimentWorker(t, dispatcher)
	id := [8]byte{2}
	initializing := &XUDP{GlobalID: id, Status: Initializing}
	XUDPManager.Lock()
	XUDPManager.Map[id] = initializing
	XUDPManager.Unlock()
	xudpExperimentWrite(t, peer.Writer, 1, net.UDPDestination(net.DomainAddress("collision.xudp.example"), 53), id, "collision")

	// A following ordinary frame establishes that the worker consumed the collision frame.
	xudpExperimentWrite(t, peer.Writer, 2, net.UDPDestination(net.DomainAddress("ordinary.xudp.example"), 53), [8]byte{}, "ordinary")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("worker did not process the frame after the initializing collision")
	}
	if got := dispatcher.count(); got != 1 {
		t.Fatalf("initializing collision dispatched %d downstream links, want only following ordinary dispatch", got)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, ordinaryFound := worker.sessionManager.Get(2)
		if ordinaryFound || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, collisionFound := worker.sessionManager.Get(1); collisionFound {
		t.Fatal("initializing collision created a local session")
	}
	if _, ordinaryFound := worker.sessionManager.Get(2); !ordinaryFound {
		t.Fatal("following ordinary frame did not create its local session")
	}
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	if XUDPManager.Map[id] != initializing || initializing.Status != Initializing {
		t.Fatal("initializing XUDP entry was changed by collision")
	}
}

func TestXUDPExperimentExpiryOrderControlsReuse(t *testing.T) {
	xudpExperimentReset(t)
	target := net.UDPDestination(net.DomainAddress("expiry.xudp.example"), 53)

	t.Run("expire before reuse dispatches a fresh downstream link", func(t *testing.T) {
		dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 1)}
		_, peer := xudpExperimentWorker(t, dispatcher)
		id := [8]byte{3}
		reader, _ := pipe.New(pipe.WithoutSizeLimit())
		x := &XUDP{GlobalID: id, Status: Expiring, Expire: time.Unix(1, 0), Mux: &Session{input: reader, output: buf.Discard}}
		XUDPManager.Lock()
		XUDPManager.Map[id] = x
		XUDPManager.Unlock()
		expireXUDP(time.Unix(2, 0))
		XUDPManager.Lock()
		_, found := XUDPManager.Map[id]
		XUDPManager.Unlock()
		if found {
			t.Fatal("expired XUDP entry remained reusable")
		}
		xudpExperimentWrite(t, peer.Writer, 3, target, id, "fresh")
		select {
		case <-dispatcher.dispatched:
		case <-time.After(time.Second):
			t.Fatal("expired XUDP ID did not dispatch a fresh link")
		}
		xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, target, "fresh")
	})

	t.Run("reuse before expiry retains existing link", func(t *testing.T) {
		dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 1)}
		worker, peer := xudpExperimentWorker(t, dispatcher)
		id := [8]byte{4}
		owner, retained := xudpExperimentLinkPair()
		dispatcher.mu.Lock()
		dispatcher.links = append(dispatcher.links, owner)
		dispatcher.mu.Unlock()
		x := &XUDP{GlobalID: id, Status: Expiring, Expire: time.Now().Add(time.Hour)}
		x.Mux = &Session{input: retained.Reader, output: retained.Writer, parent: worker.sessionManager, XUDP: x}
		XUDPManager.Lock()
		XUDPManager.Map[id] = x
		XUDPManager.Unlock()
		expireXUDP(time.Now())
		XUDPManager.Lock()
		if XUDPManager.Map[id] != x {
			XUDPManager.Unlock()
			t.Fatal("unexpired XUDP entry was removed")
		}
		XUDPManager.Unlock()
		before := dispatcher.count()
		xudpExperimentWrite(t, peer.Writer, 4, target, id, "retained")
		deadline := time.Now().Add(time.Second)
		for worker.ActiveConnections() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if worker.ActiveConnections() == 0 {
			t.Fatal("reused XUDP session was not retained")
		}
		if got := dispatcher.count(); got != before {
			t.Fatalf("unexpired XUDP ID dispatched %d new links, want none", got-before)
		}
	})
}

type xudpExperimentBlockingWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (w *xudpExperimentBlockingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	return nil
}

func TestXUDPExperimentCloseWaitsForOldReaderReceipt(t *testing.T) {
	xudpExperimentReset(t)
	input, source := pipe.New(pipe.WithoutSizeLimit())
	manager := NewSessionManager()
	blocker := &xudpExperimentBlockingWriter{entered: make(chan struct{}, 1), release: make(chan struct{})}
	x := &XUDP{Status: Active}
	s := &Session{
		input:        input,
		output:       buf.Discard,
		parent:       manager,
		ID:           9,
		XUDP:         x,
		inputDone:    make(chan struct{}),
		inputStarted: true,
	}
	x.Mux = s
	if !manager.Add(s) {
		t.Fatal("failed to retain XUDP session")
	}
	handleDone := make(chan struct{})
	go func() {
		handle(context.Background(), s, blocker, nil)
		close(handleDone)
	}()
	if err := source.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("blocked"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocker.entered:
	case <-time.After(time.Second):
		t.Fatal("old XUDP handle did not reach its blocked response writer")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close(false) }()
	select {
	case err := <-closeDone:
		t.Fatalf("XUDP Close returned before the old reader receipt: %v", err)
	default:
	}
	close(blocker.release)
	if err := common.Close(source); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("old XUDP handle did not finish after release")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("XUDP Close did not return after the old reader receipt")
	}
}
