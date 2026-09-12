package splithttp

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func newLifecycleListener() (*Listener, *requestHandler) {
	ln := &Listener{config: &Config{}, stop: make(chan struct{}), stopDone: make(chan struct{}), unblockDone: make(chan struct{})}
	h := &requestHandler{ln: ln, config: &Config{}, sessionMu: new(sync.Mutex)}
	ln.handler = h
	return ln, h
}

type lifecycleCloser struct{ closed atomic.Int32 }

func (c *lifecycleCloser) Close() error { c.closed.Add(1); return nil }

type blockingLifecycleCloser struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingLifecycleCloser) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return nil
}

func TestDefaultDialerClientResourcePublicationAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &DefaultDialerClient{
		ctx:       ctx,
		cancel:    cancel,
		closeDone: make(chan struct{}),
		resources: make(map[io.Closer]struct{}),
	}
	first := new(lifecycleCloser)
	if !client.trackResource(first) {
		t.Fatal("live client rejected H3 resource publication")
	}
	client.SignalStop()
	if first.closed.Load() != 1 {
		t.Fatal("generation stop did not close tracked H3 resource")
	}
	late := new(lifecycleCloser)
	if client.trackResource(late) {
		t.Fatal("sealed client admitted late H3 resource publication")
	}
	if late.closed.Load() != 1 {
		t.Fatal("late H3 resource was not closed")
	}
}

func TestDefaultDialerClientJoinsH3CleanupCallback(t *testing.T) {
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	client := &DefaultDialerClient{
		ctx:       ownerCtx,
		cancel:    ownerCancel,
		client:    &http.Client{Transport: http.DefaultTransport},
		closeDone: make(chan struct{}),
		resources: make(map[io.Closer]struct{}),
	}
	resourceCtx, cancelResource := context.WithCancel(context.Background())
	resource := &blockingLifecycleCloser{entered: make(chan struct{}), release: make(chan struct{})}
	if !client.trackH3Resources(resourceCtx, resource) {
		t.Fatal("live client rejected H3 resource publication")
	}
	cancelResource()
	select {
	case <-resource.entered:
	case <-time.After(time.Second):
		t.Fatal("H3 cleanup callback did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("client Close returned before H3 cleanup callback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(resource.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client Close did not join H3 cleanup callback")
	}
}

func TestUploadChildAdmissionRollsBackDefaultClientReceipt(t *testing.T) {
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	client := &DefaultDialerClient{ctx: ownerCtx, cancel: ownerCancel, client: &http.Client{Transport: http.DefaultTransport}, closeDone: make(chan struct{}), resources: make(map[io.Closer]struct{})}
	var children task.Lifecycle
	children.Seal()
	if admitted, ok := acquireUploadChild(&children, client); ok || admitted != nil {
		t.Fatal("sealed upload-child gate admitted work")
	}
	client.tasks.Seal()
	joined := make(chan struct{})
	go func() { client.tasks.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("upload admission rejection leaked the default-client receipt")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenerSealRejectsLateSessionAndJoinsHeldReceipt(t *testing.T) {
	ln, h := newLifecycleListener()
	if !ln.acquire() {
		t.Fatal("initial receipt was rejected")
	}
	ln.Seal()
	if ln.acquire() {
		t.Fatal("listener admitted a receipt after seal")
	}
	if got := h.upsertSession("late"); got != nil {
		t.Fatal("listener published a session after seal")
	}
	finished := make(chan struct{})
	go func() { _ = ln.Wait(); close(finished) }()
	select {
	case <-finished:
		t.Fatal("Wait returned before the held receipt")
	case <-time.After(20 * time.Millisecond):
	}
	ln.release()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Wait did not join the released receipt")
	}
}

func TestListenerStopClosesSessionQueueAndReaperKeepsReplacement(t *testing.T) {
	ln, h := newLifecycleListener()
	first := h.upsertSession("same")
	if first == nil {
		t.Fatal("first session was not created")
	}
	second := &httpSession{uploadQueue: NewUploadQueue(1), isFullyConnected: first.isFullyConnected}
	h.sessions.Store("same", second)
	h.deleteSession("same", first)
	if got, ok := h.sessions.Load("same"); !ok || got != second {
		t.Fatal("stale cleanup deleted the replacement session")
	}
	if err := ln.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := ln.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := second.uploadQueue.Push(Packet{Payload: []byte("late")}); err == nil {
		t.Fatal("joined listener shutdown did not close the active upload queue")
	}
}

func TestListenerConcurrentCloseIsIdempotent(t *testing.T) {
	ln, _ := newLifecycleListener()
	results := make(chan error, 2)
	go func() { results <- ln.Close() }()
	go func() { results <- ln.Close() }()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent Listener.Close did not complete")
		}
	}
}

func TestListenerPaddingWaitStopsPromptly(t *testing.T) {
	ln, _ := newLifecycleListener()
	httpSC := &httpServerConn{Instance: done.New()}
	finished := make(chan bool, 1)
	go func() { finished <- ln.waitPadding(time.Hour, httpSC) }()
	ln.Seal()
	select {
	case keepGoing := <-finished:
		if keepGoing {
			t.Fatal("padding wait treated listener stop as a timer tick")
		}
	case <-time.After(time.Second):
		t.Fatal("listener stop did not cancel padding wait")
	}
}

func TestListenerReleaseClearsSessionInventory(t *testing.T) {
	ln, h := newLifecycleListener()
	if h.upsertSession("retained") == nil {
		t.Fatal("session was not created")
	}
	if err := ln.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := ln.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := ln.Release(); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.sessions.Load("retained"); ok {
		t.Fatal("listener release retained a session entry")
	}
}

func TestH3ListenerCloseUnblocksIdleSession(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("matches the existing SplitHTTP H3 test platform boundary")
	}
	listenPort := udp.PickPort()
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "lifecycle",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(certificate)},
			PinnedPeerCertSha256: [][]byte{certificateHash[:]},
			NextProtocol:         []string{"h3"},
		},
	}
	callbackEntered := make(chan struct{})
	callbackDone := make(chan struct{})
	listener, err := ListenXH(context.Background(), xnet.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		close(callbackEntered)
		defer close(callbackDone)
		var payload [1]byte
		_, _ = conn.Read(payload[:])
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	client, err := Dial(context.Background(), xnet.UDPDestination(xnet.DomainAddress("localhost"), listenPort), streamSettings)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-callbackEntered:
	case <-time.After(5 * time.Second):
		_ = listener.Close()
		t.Fatal("H3 callback did not reach the idle upload queue")
	}
	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("H3 listener Close did not fan out network and queue unblock")
	}
	select {
	case <-callbackDone:
	default:
		t.Fatal("H3 listener completed before the idle callback receipt")
	}
}

type lifecycleXmuxConn struct {
	closed atomic.Bool
	stops  atomic.Int32
}

type blockingStopXmuxConn struct {
	entered chan struct{}
	release <-chan struct{}
}

func (*blockingStopXmuxConn) IsClosed() bool { return false }
func (*blockingStopXmuxConn) Close() error   { return nil }
func (c *blockingStopXmuxConn) SignalStop() {
	close(c.entered)
	<-c.release
}

func TestXmuxSignalStopFansOutAcrossClients(t *testing.T) {
	release := make(chan struct{})
	var made []*blockingStopXmuxConn
	manager := NewXmuxManager(XmuxConfig{MaxConnections: &RangeConfig{From: 3, To: 3}}, func() XmuxConn {
		connection := &blockingStopXmuxConn{entered: make(chan struct{}), release: release}
		made = append(made, connection)
		return connection
	})
	for range 3 {
		manager.GetXmuxClient(context.Background())
	}
	stopped := make(chan struct{})
	go func() {
		manager.SignalStop()
		close(stopped)
	}()
	for _, connection := range made {
		select {
		case <-connection.entered:
		case <-time.After(time.Second):
			t.Fatal("XMUX client stop did not fan out before peer release")
		}
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("XMUX client stop fan-out did not join")
	}
}

func (c *lifecycleXmuxConn) IsClosed() bool { return c.closed.Load() }
func (c *lifecycleXmuxConn) Close() error   { c.closed.Store(true); return nil }
func (c *lifecycleXmuxConn) SignalStop()    { c.stops.Add(1) }

func TestXmuxCloseIncludesRetiredRunningClient(t *testing.T) {
	var made []*lifecycleXmuxConn
	m := NewXmuxManager(XmuxConfig{CMaxReuseTimes: &RangeConfig{From: 1, To: 1}}, func() XmuxConn {
		c := new(lifecycleXmuxConn)
		made = append(made, c)
		return c
	})
	retired := m.GetXmuxClient(context.Background())
	retired.AddRunning()
	_ = m.GetXmuxClient(context.Background())
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before retired client receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if made[0].stops.Load() == 0 || !made[0].closed.Load() {
		t.Fatal("retired client was not signaled and closed")
	}
	if len(made) < 2 || made[1].stops.Load() == 0 || !made[1].closed.Load() {
		t.Fatal("active client was not included in the close snapshot")
	}
	retired.DoneRunning()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the retired client")
	}
	if client := m.GetXmuxClient(context.Background()); client != nil {
		t.Fatal("sealed manager admitted a client")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("repeated Close = %v", err)
	}
}
