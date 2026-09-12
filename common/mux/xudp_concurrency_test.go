package mux

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type xudpConcurrencyBlockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *xudpConcurrencyBlockingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	return io.ErrClosedPipe
}
func (w *xudpConcurrencyBlockingWriter) Interrupt() { w.once.Do(func() { close(w.release) }) }

type xudpConcurrencyFailWriter struct{}

func (xudpConcurrencyFailWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return io.ErrClosedPipe
}

func xudpConcurrencyWorker(t *testing.T, dispatcher *xudpExperimentDispatcher, writer buf.Writer) (*ServerWorker, *transport.Link) {
	t.Helper()
	server, peer := xudpExperimentLinkPair()
	server.Writer = writer
	worker, err := NewServerWorker(context.Background(), dispatcher, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = worker.Close()
		common.Interrupt(peer.Reader)
		common.Interrupt(peer.Writer)
		select {
		case <-worker.WaitClosed():
		case <-time.After(time.Second):
			t.Error("XUDP concurrency worker did not stop")
		}
	})
	return worker, peer
}

func xudpConcurrencyWait(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal(message)
	}
}

func xudpConcurrencySession(manager *SessionManager, x *XUDP, id uint16, input buf.Reader, output buf.Writer) *Session {
	return &Session{
		input:        input,
		output:       output,
		parent:       manager,
		ID:           id,
		XUDP:         x,
		inputDone:    make(chan struct{}),
		inputStarted: true,
	}
}

func TestXUDPRebindConcurrencyWaitsForOldReaderReceipt(t *testing.T) {
	xudpExperimentReset(t)
	manager := NewSessionManager()
	reader, _ := pipe.New(pipe.WithoutSizeLimit())
	id := [8]byte{0x71}
	x := &XUDP{GlobalID: id, Status: Active}
	old := xudpConcurrencySession(manager, x, 1, reader, buf.Discard)
	x.Mux = old
	if !manager.Add(old) {
		t.Fatal("failed to add old XUDP binding")
	}
	XUDPManager.Lock()
	XUDPManager.Map[id] = x
	x.Status = Initializing
	XUDPManager.Unlock()

	fenced := make(chan struct{})
	go func() {
		_ = old.Close(false)
		close(fenced)
	}()
	select {
	case <-fenced:
		t.Fatal("old XUDP close returned before its reader receipt")
	case <-time.After(20 * time.Millisecond):
	}
	XUDPManager.Lock()
	if x.Status != Initializing || x.Mux != old {
		XUDPManager.Unlock()
		t.Fatal("new XUDP binding was published before old reader receipt")
	}
	XUDPManager.Unlock()

	old.inputComplete()
	select {
	case <-fenced:
	case <-time.After(time.Second):
		t.Fatal("old XUDP close did not finish after reader receipt")
	}
	newBinding := xudpConcurrencySession(manager, x, 2, reader, buf.Discard)
	if !manager.addAndPublishXUDP(newBinding, x, old) {
		t.Fatal("failed to publish new XUDP binding after receipt")
	}
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	if x.Status != Active || x.Mux != newBinding {
		t.Fatal("new XUDP binding was not published atomically")
	}
}

func TestXUDPStaleBindingCloseCannotExpireCurrentBinding(t *testing.T) {
	xudpExperimentReset(t)
	manager := NewSessionManager()
	oldReader, _ := pipe.New(pipe.WithoutSizeLimit())
	newReader, _ := pipe.New(pipe.WithoutSizeLimit())
	id := [8]byte{0x72}
	x := &XUDP{GlobalID: id, Status: Active}
	old := xudpConcurrencySession(manager, x, 1, oldReader, buf.Discard)
	old.inputComplete()
	newBinding := xudpConcurrencySession(manager, x, 2, newReader, buf.Discard)
	x.Mux = newBinding
	if !manager.Add(old) || !manager.Add(newBinding) {
		t.Fatal("failed to add XUDP test bindings")
	}
	XUDPManager.Lock()
	XUDPManager.Map[id] = x
	XUDPManager.Unlock()
	if err := old.Close(false); err != nil {
		t.Fatal(err)
	}
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	if x.Status != Active || x.Mux != newBinding {
		t.Fatal("stale XUDP binding expired the current binding")
	}
}

func TestXUDPBindingIdentityRejectsStalePublication(t *testing.T) {
	xudpExperimentReset(t)
	manager := NewSessionManager()
	reader, _ := pipe.New(pipe.WithoutSizeLimit())
	id := [8]byte{0x79}
	x := &XUDP{GlobalID: id, Status: Initializing}
	expected := xudpConcurrencySession(manager, x, 1, reader, buf.Discard)
	replacement := xudpConcurrencySession(manager, x, 2, reader, buf.Discard)
	x.Mux = replacement
	XUDPManager.Lock()
	XUDPManager.Map[id] = x
	XUDPManager.Unlock()
	stale := xudpConcurrencySession(manager, x, 3, reader, buf.Discard)
	if manager.addAndPublishXUDP(stale, x, expected) {
		t.Fatal("stale expected binding published over its replacement")
	}
	if manager.Size() != 0 {
		t.Fatal("rejected stale publication mutated the session manager")
	}
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	if x.Status != Initializing || x.Mux != replacement {
		t.Fatal("rejected stale publication mutated the XUDP entry")
	}
}

func TestXUDPConcurrencyRebindAndExpiry(t *testing.T) {
	xudpExperimentReset(t)
	for i := 0; i != 32; i++ {
		manager := NewSessionManager()
		reader, _ := pipe.New(pipe.WithoutSizeLimit())
		id := [8]byte{0x73, byte(i)}
		x := &XUDP{GlobalID: id, Status: Active}
		old := xudpConcurrencySession(manager, x, 1, reader, buf.Discard)
		old.inputComplete()
		x.Mux = old
		if !manager.Add(old) {
			t.Fatal("failed to add old binding")
		}
		XUDPManager.Lock()
		XUDPManager.Map[id] = x
		x.Status = Initializing
		XUDPManager.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = old.Close(false) }()
		go func() { defer wg.Done(); expireXUDP(time.Now().Add(2 * time.Hour)) }()
		wg.Wait()
		newBinding := xudpConcurrencySession(manager, x, 2, reader, buf.Discard)
		if !manager.addAndPublishXUDP(newBinding, x, old) {
			t.Fatal("concurrent expiry removed initializing XUDP reservation")
		}
	}
}

func TestXUDPRebindConcurrencyOldWorkerShutdownUnblocksReceipt(t *testing.T) {
	xudpExperimentReset(t)
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 2)}
	blocker := &xudpConcurrencyBlockingWriter{entered: make(chan struct{}, 1), release: make(chan struct{})}
	oldWorker, oldPeer := xudpConcurrencyWorker(t, dispatcher, blocker)
	newWorker, newPeer := xudpExperimentWorker(t, dispatcher)
	id := [8]byte{0x74}
	target := net.UDPDestination(net.DomainAddress("old-reader.xudp.example"), 53)
	xudpExperimentWrite(t, oldPeer.Writer, 1, target, id, "first")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("first XUDP dispatch did not start")
	}
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, target, "first")
	if err := dispatcher.link(t, 0).Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocker.entered:
	case <-time.After(time.Second):
		t.Fatal("old XUDP handle did not block on carrier writer")
	}
	xudpExperimentWrite(t, newPeer.Writer, 2, target, id, "rebind")
	xudpConcurrencyWait(t, func() bool {
		XUDPManager.Lock()
		defer XUDPManager.Unlock()
		x := XUDPManager.Map[id]
		return x != nil && x.Status == Initializing
	}, "rebind did not reserve an initializing binding")
	if newWorker.ActiveConnections() != 0 {
		t.Fatal("new binding published before old reader receipt")
	}
	if err := oldWorker.Close(); err != nil {
		t.Fatal(err)
	}
	xudpConcurrencyWait(t, func() bool { return newWorker.ActiveConnections() == 1 }, "old worker shutdown did not unblock rebind receipt")
}

func TestXUDPRebindReaderFenceDrainsStaleEOF(t *testing.T) {
	xudpExperimentReset(t)
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 2)}
	_, oldPeer := xudpConcurrencyWorker(t, dispatcher, xudpConcurrencyFailWriter{})
	_, newPeer := xudpExperimentWorker(t, dispatcher)
	id := [8]byte{0x75}
	target := net.UDPDestination(net.DomainAddress("stale-eof.xudp.example"), 53)
	xudpExperimentWrite(t, oldPeer.Writer, 1, target, id, "first")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("first XUDP dispatch did not start")
	}
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, target, "first")
	if err := dispatcher.link(t, 0).Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("old-response"))}); err != nil {
		t.Fatal(err)
	}
	xudpConcurrencyWait(t, func() bool {
		XUDPManager.Lock()
		defer XUDPManager.Unlock()
		x := XUDPManager.Map[id]
		return x != nil && x.Status == Expiring
	}, "old writer failure did not complete XUDP handle")
	xudpExperimentWrite(t, newPeer.Writer, 2, target, id, "rebind")
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, target, "rebind")
	if err := dispatcher.link(t, 0).Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("one")), buf.FromBytes([]byte("two"))}); err != nil {
		t.Fatal(err)
	}
	// The new carrier must receive both retained-reader responses; a stale EOF
	// would terminate its handle before either frame is emitted.
	reader := newPeer.Reader.(buf.TimeoutReader)
	var got string
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(got, "one") || !strings.Contains(got, "two") {
		if time.Now().After(deadline) {
			break
		}
		mb, err := reader.ReadMultiBufferTimeout(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		got += mb.String()
		buf.ReleaseMulti(mb)
	}
	if !strings.Contains(got, "one") || !strings.Contains(got, "two") {
		t.Fatalf("rebound carrier did not receive both responses: %q", got)
	}
}

func TestXUDPRebindUnsupportedRetainedReaderDispatchesFresh(t *testing.T) {
	xudpExperimentReset(t)
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 1)}
	worker, peer := xudpExperimentWorker(t, dispatcher)
	id := [8]byte{0x76}
	old := &XUDP{GlobalID: id, Status: Active}
	oldSession := &Session{input: buf.NewReader(strings.NewReader("")), output: buf.Discard, parent: worker.sessionManager, ID: 1, XUDP: old, inputDone: make(chan struct{}), inputStarted: true}
	old.Mux = oldSession
	if !worker.sessionManager.Add(oldSession) {
		t.Fatal("failed to add unsupported old binding")
	}
	XUDPManager.Lock()
	XUDPManager.Map[id] = old
	XUDPManager.Unlock()
	target := net.UDPDestination(net.DomainAddress("unsupported-reader.xudp.example"), 53)
	xudpExperimentWrite(t, peer.Writer, 2, target, id, "fresh")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("unsupported retained reader did not dispatch a fresh link")
	}
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, target, "fresh")
	xudpConcurrencyWait(t, func() bool {
		XUDPManager.Lock()
		defer XUDPManager.Unlock()
		current := XUDPManager.Map[id]
		return current != nil && current != old && current.Status == Active
	}, "unsupported retained reader did not publish a fresh active binding")
}

func TestXUDPRebindContextCancelCleansExactReservation(t *testing.T) {
	xudpExperimentReset(t)
	dispatcher := &xudpExperimentDispatcher{dispatched: make(chan struct{}, 2)}
	blocker := &xudpConcurrencyBlockingWriter{entered: make(chan struct{}, 1), release: make(chan struct{})}
	_, oldPeer := xudpConcurrencyWorker(t, dispatcher, blocker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, newPeer := xudpExperimentLinkPair()
	newWorker, err := NewServerWorker(ctx, dispatcher, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = newWorker.Close(); common.Interrupt(newPeer.Reader); common.Interrupt(newPeer.Writer) })
	id := [8]byte{0x77}
	target := net.UDPDestination(net.DomainAddress("cancel-rebind.xudp.example"), 53)
	xudpExperimentWrite(t, oldPeer.Writer, 1, target, id, "first")
	select {
	case <-dispatcher.dispatched:
	case <-time.After(time.Second):
		t.Fatal("first XUDP dispatch did not start")
	}
	xudpExperimentReadPacket(t, dispatcher.link(t, 0).Reader, target, "first")
	if err := dispatcher.link(t, 0).Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocker.entered:
	case <-time.After(time.Second):
		t.Fatal("old XUDP handle did not block")
	}
	xudpExperimentWrite(t, newPeer.Writer, 2, target, id, "cancel")
	xudpConcurrencyWait(t, func() bool {
		XUDPManager.Lock()
		defer XUDPManager.Unlock()
		x := XUDPManager.Map[id]
		return x != nil && x.Status == Initializing
	}, "rebind did not reserve before cancellation")
	cancel()
	select {
	case <-newWorker.WaitClosed():
	case <-time.After(time.Second):
		t.Fatal("cancelled rebind worker did not stop")
	}
	if newWorker.ActiveConnections() != 0 {
		t.Fatal("cancelled rebind retained a local session")
	}
	XUDPManager.Lock()
	_, found := XUDPManager.Map[id]
	XUDPManager.Unlock()
	if found {
		t.Fatal("cancelled rebind retained its global reservation")
	}
}

func TestXUDPUnsupportedReaderManagerShutdownDeletesExactBinding(t *testing.T) {
	xudpExperimentReset(t)
	manager := NewSessionManager()
	id := [8]byte{0x78}
	x := &XUDP{GlobalID: id, Status: Active}
	_, output := pipe.New(pipe.WithoutSizeLimit())
	s := &Session{input: buf.NewReader(strings.NewReader("")), output: output, parent: manager, ID: 1, XUDP: x, inputDone: make(chan struct{}), inputStarted: true}
	x.Mux = s
	if !manager.Add(s) {
		t.Fatal("failed to add unsupported binding")
	}
	XUDPManager.Lock()
	XUDPManager.Map[id] = x
	XUDPManager.Unlock()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	XUDPManager.Lock()
	_, found := XUDPManager.Map[id]
	XUDPManager.Unlock()
	if found {
		t.Fatal("manager shutdown retained unsupported XUDP binding")
	}
	if err := output.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("closed"))}); err == nil {
		t.Fatal("manager shutdown did not close unsupported retained output")
	}
}
