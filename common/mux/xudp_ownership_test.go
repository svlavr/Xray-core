package mux

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestSessionRejectsDuplicateID(t *testing.T) {
	m := NewSessionManager()
	first := &Session{ID: 7, parent: m, output: buf.Discard}
	if !m.Add(first) {
		t.Fatal("initial admission failed")
	}
	duplicate := &Session{ID: 7, parent: m, output: buf.Discard}
	if m.Add(duplicate) {
		t.Fatal("duplicate replaced active session")
	}
	duplicate.Close(false)
	if got, ok := m.Get(7); !ok || got != first {
		t.Fatal("rejected duplicate removed active session")
	}
	m.Close()
}

func TestServerRetiredIDDoesNotBlockIdleClose(t *testing.T) {
	m := NewSessionManager()
	r, w := pipe.New()
	w.Close()
	carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	s := &Session{ID: 1, input: r, output: buf.Discard, parent: m, server: true}
	if !m.Add(s) {
		t.Fatal("session not added")
	}
	returned := make(chan struct{})
	go func() { handle(context.Background(), s, carrier); close(returned) }()
	muxWait(t, carrier.entered)
	s.Close(false)
	if m.Size() != 0 {
		t.Fatal("closed wire ID counted as active")
	}
	if m.Add(&Session{ID: 1, parent: m}) {
		t.Fatal("pending END wire ID reused")
	}
	if !m.CloseIfNoSessionAndIdle(0, m.Count()) {
		t.Fatal("closed wire ID blocked idle shutdown")
	}
	release()
	muxWait(t, returned)
}

func TestClientExhaustionRetiresWorker(t *testing.T) {
	m := NewSessionManager()
	m.count = ^uint16(0)
	if m.Allocate(&ClientStrategy{}) != nil {
		t.Fatal("client wire ID wrapped")
	}
	exhausted := &ClientWorker{sessionManager: m, done: done.New()}
	fresh := &ClientWorker{sessionManager: NewSessionManager(), done: done.New()}
	if !exhausted.IsClosing() || !exhausted.IsFull() {
		t.Fatal("exhausted worker remains selectable")
	}
	picker := &IncrementalWorkerPicker{workers: []*ClientWorker{exhausted, fresh}}
	selected, err := picker.PickAvailable()
	if err != nil || selected != fresh {
		t.Fatalf("picker did not bypass exhaustion: %p %v", selected, err)
	}
}

type retainedDispatcher struct {
	dispatch func(context.Context) (*transport.Link, error)
	count    atomic.Int32
}

func (d *retainedDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.count.Add(1)
	return d.dispatch(ctx)
}

func (*retainedDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	panic("unexpected DispatchLink")
}
func (*retainedDispatcher) Start() error      { return nil }
func (*retainedDispatcher) Close() error      { return nil }
func (*retainedDispatcher) Type() interface{} { return routing.DispatcherType() }

type retainedWriteProbe struct {
	*pipe.Writer
	entered chan struct{}
}

func (w *retainedWriteProbe) WriteMultiBufferContext(ctx context.Context, mb buf.MultiBuffer) error {
	w.entered <- struct{}{}
	return w.Writer.WriteMultiBufferContext(ctx, mb)
}

func retainedLink(t *testing.T, limit int32) (*transport.Link, *pipe.Reader, *pipe.Writer, *retainedWriteProbe) {
	t.Helper()
	up, uplink := pipe.New(pipe.WithSizeLimit(limit))
	down, response := pipe.New()
	t.Cleanup(func() { up.Interrupt(); down.Interrupt() })
	probe := &retainedWriteProbe{Writer: uplink, entered: make(chan struct{}, 16)}
	return &transport.Link{Reader: down, Writer: probe}, up, response, probe
}

func retainedWorker(t *testing.T, d routing.Dispatcher, writer buf.Writer) *ServerWorker {
	t.Helper()
	w := &ServerWorker{dispatcher: d, sessionManager: NewSessionManager(), link: &transport.Link{Writer: writer}}
	t.Cleanup(func() { w.sessionManager.Close() })
	return w
}

func retainedNew(w *ServerWorker, id uint16, global [8]byte, payload string) error {
	data := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(data, uint16(len(payload)))
	copy(data[2:], payload)
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(data))}
	return w.handleStatusNew(context.Background(), &FrameMetadata{
		SessionID: id, SessionStatus: SessionStatusNew,
		Option: OptionData, GlobalID: global, Target: net.UDPDestination(net.LocalHostIP, 53),
	}, reader)
}

func retainedObject(t *testing.T, id [8]byte) *XUDP {
	t.Helper()
	XUDPManager.Lock()
	x := XUDPManager.Map[id]
	XUDPManager.Unlock()
	if x == nil {
		t.Fatal("missing retained association")
	}
	return x
}

func retainedCleanup(t *testing.T, id [8]byte) {
	t.Helper()
	t.Cleanup(func() {
		XUDPManager.Lock()
		x := XUDPManager.Map[id]
		XUDPManager.Unlock()
		if x != nil {
			x.Interrupt()
		}
	})
}

func retainedResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("retained operation blocked")
		return nil
	}
}

func retainedRead(t *testing.T, reader *pipe.Reader, want string) {
	t.Helper()
	mb, err := reader.ReadMultiBufferTimeout(3 * time.Second)
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != want {
		t.Fatalf("retained payload: %q %v, want %q", mb.String(), err, want)
	}
}

type blockedCarrier struct {
	entered, release chan struct{}
	once             sync.Once
}

func (w *blockedCarrier) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.once.Do(func() { close(w.entered); <-w.release })
	return nil
}

func TestXUDPRebindDoesNotJoinOldCarrier(t *testing.T) {
	for _, afterPayload := range []bool{false, true} {
		name := "pending-END"
		if afterPayload {
			name = "pending-payload"
		}
		t.Run(name, func(t *testing.T) {
			id := [8]byte{11}
			retainedCleanup(t, id)
			link, up, response, _ := retainedLink(t, -1)
			d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return link, nil }}
			carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(carrier.release) })
			t.Cleanup(release)
			first := retainedWorker(t, d, carrier)
			if err := retainedNew(first, 1, id, "first"); err != nil {
				t.Fatal(err)
			}
			retainedRead(t, up, "first")
			x := retainedObject(t, id)
			old, _ := first.sessionManager.Get(1)
			if afterPayload {
				response.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("old reply"))})
			} else {
				old.Close(false)
			}
			muxWait(t, carrier.entered)
			// A still-running old writer owns the wire ID even after local close.
			if err := retainedNew(first, 1, id, "duplicate"); err == nil {
				t.Fatal("pending response ID reused")
			}
			second := retainedWorker(t, d, buf.Discard)
			result := make(chan error, 1)
			go func() { result <- retainedNew(second, 2, id, "second") }()
			if err := retainedResult(t, result); err != nil {
				t.Fatal(err)
			}
			retainedRead(t, up, "second")
			if retainedObject(t, id) != x || d.count.Load() != 1 {
				t.Fatal("rebind replaced live downstream")
			}
			mb, err := old.input.ReadMultiBuffer()
			buf.ReleaseMulti(mb)
			if err != io.EOF {
				t.Fatalf("old reader kept access: %v", err)
			}
			if err := old.output.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("late"))}); err != context.Canceled {
				t.Fatalf("late write: %v", err)
			}
			release()
			deadline := time.Now().Add(3 * time.Second)
			reserved := func() bool {
				first.sessionManager.RLock()
				defer first.sessionManager.RUnlock()
				return first.sessionManager.sessions[1] != nil
			}
			for reserved() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if reserved() {
				t.Fatal("old response ID not retired")
			}
			XUDPManager.Lock()
			active := x.Status == Active
			XUDPManager.Unlock()
			if !active {
				t.Fatal("old completion expired replacement")
			}
		})
	}
}

func TestXUDPRebindCancelsOldPipeWrite(t *testing.T) {
	id := [8]byte{12}
	retainedCleanup(t, id)
	link, up, _, probe := retainedLink(t, 0)
	d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return link, nil }}
	first := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(first, 1, id, "queued"); err != nil {
		t.Fatal(err)
	}
	muxWait(t, probe.entered)
	old, _ := first.sessionManager.Get(1)
	late := make(chan error, 1)
	go func() { late <- old.output.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("late"))}) }()
	muxWait(t, probe.entered)
	second := retainedWorker(t, d, buf.Discard)
	rebound := make(chan error, 1)
	go func() { rebound <- retainedNew(second, 2, id, "new") }()
	if err := retainedResult(t, late); err != context.Canceled {
		t.Fatalf("old blocked write: %v", err)
	}
	muxWait(t, probe.entered)
	retainedRead(t, up, "queued")
	if err := retainedResult(t, rebound); err != nil {
		t.Fatal(err)
	}
	retainedRead(t, up, "new")
	if d.count.Load() != 1 {
		t.Fatal("live pipe was replaced")
	}
}

func TestXUDPShutdownCancelsInitialWrite(t *testing.T) {
	id := [8]byte{13}
	retainedCleanup(t, id)
	link, up, _, probe := retainedLink(t, 0)
	d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return link, nil }}
	first := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(first, 1, id, "queued"); err != nil {
		t.Fatal(err)
	}
	muxWait(t, probe.entered)
	second := retainedWorker(t, d, buf.Discard)
	result := make(chan error, 1)
	go func() { result <- retainedNew(second, 2, id, "canceled") }()
	muxWait(t, probe.entered)
	second.sessionManager.Close()
	if err := retainedResult(t, result); err != context.Canceled {
		t.Fatalf("initial write: %v", err)
	}
	if d.count.Load() != 1 {
		t.Fatal("canceled binding started fresh dispatch")
	}
	x := retainedObject(t, id)
	XUDPManager.Lock()
	status := x.Status
	XUDPManager.Unlock()
	if status != Expiring {
		t.Fatalf("failed preparation state: %d", status)
	}
	retainedRead(t, up, "queued")
	third := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(third, 3, id, "usable"); err != nil {
		t.Fatal(err)
	}
	retainedRead(t, up, "usable")
}

func TestXUDPDeadEndpointRetriesSavedPacketOnce(t *testing.T) {
	id := [8]byte{14}
	retainedCleanup(t, id)
	link, up, _, _ := retainedLink(t, -1)
	fresh, freshUp, _, _ := retainedLink(t, -1)
	next := link
	d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return next, nil }}
	first := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(first, 1, id, "first"); err != nil {
		t.Fatal(err)
	}
	retainedRead(t, up, "first")
	old := retainedObject(t, id)
	up.Interrupt()
	next = fresh
	second := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(second, 2, id, "retry-payload"); err != nil {
		t.Fatal(err)
	}
	retainedRead(t, freshUp, "retry-payload")
	current := retainedObject(t, id)
	if current == old || d.count.Load() != 2 {
		t.Fatal("expected one fresh retry")
	}
	old.Interrupt()
	if retainedObject(t, id) != current {
		t.Fatal("stale interrupt removed replacement")
	}
	if err := current.Mux.output.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("still live"))}); err != nil {
		t.Fatal(err)
	}
	retainedRead(t, freshUp, "still live")
}

func TestXUDPUnsupportedEndpointIsReleased(t *testing.T) {
	id := [8]byte{15}
	retainedCleanup(t, id)
	d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) {
		return &transport.Link{Reader: buf.NewReader(bytes.NewReader(nil)), Writer: buf.Discard}, nil
	}}
	w := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(w, 1, id, "request"); err == nil {
		t.Fatal("unsupported endpoints retained")
	}
	XUDPManager.Lock()
	x := XUDPManager.Map[id]
	XUDPManager.Unlock()
	if x != nil || w.sessionManager.Size() != 0 {
		t.Fatal("unsupported endpoint left state")
	}
}

type retainedCloseProbe struct {
	*retainedWriteProbe
	entered, release chan struct{}
	once             sync.Once
}

func (w *retainedCloseProbe) Close() error {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.Writer.Close()
}

func TestXUDPExpiryDoesNotHoldGlobalLock(t *testing.T) {
	id := [8]byte{16}
	retainedCleanup(t, id)
	link, up, _, probe := retainedLink(t, -1)
	closer := &retainedCloseProbe{retainedWriteProbe: probe, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(closer.release) })
	t.Cleanup(release)
	link.Writer = closer
	d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return link, nil }}
	w := retainedWorker(t, d, buf.Discard)
	if err := retainedNew(w, 1, id, "first"); err != nil {
		t.Fatal(err)
	}
	retainedRead(t, up, "first")
	x := retainedObject(t, id)
	x.Mux.Close(false)
	XUDPManager.Lock()
	x.Expire = time.Now().Add(-time.Second)
	XUDPManager.Unlock()
	expired := make(chan struct{})
	go func() { expireXUDP(time.Now()); close(expired) }()
	muxWait(t, closer.entered)
	unlocked := make(chan struct{})
	go func() { XUDPManager.Lock(); XUDPManager.Unlock(); close(unlocked) }()
	muxWait(t, unlocked)
	// A replacement under the same key must survive the old close's return.
	fresh, freshUp, _, _ := retainedLink(t, -1)
	d2 := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return fresh, nil }}
	w2 := retainedWorker(t, d2, buf.Discard)
	if err := retainedNew(w2, 2, id, "replacement"); err != nil {
		t.Fatal(err)
	}
	current := retainedObject(t, id)
	if current == x {
		t.Fatal("expired identity retained")
	}
	release()
	muxWait(t, expired)
	if retainedObject(t, id) != current {
		t.Fatal("expired cleanup deleted replacement")
	}
	retainedRead(t, freshUp, "replacement")
}

func TestXUDPConcurrentPreparationAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "conflicting-new"
		if shutdown {
			name = "shutdown-before-publish"
		}
		t.Run(name, func(t *testing.T) {
			id := [8]byte{17}
			retainedCleanup(t, id)
			link, up, _, _ := retainedLink(t, -1)
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { close(entered); <-release; return link, nil }}
			first := retainedWorker(t, d, buf.Discard)
			result := make(chan error, 1)
			go func() { result <- retainedNew(first, 1, id, "first") }()
			muxWait(t, entered)
			if shutdown {
				first.sessionManager.Close()
			} else {
				second := retainedWorker(t, d, buf.Discard)
				if err := retainedNew(second, 2, id, "conflict"); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			err := retainedResult(t, result)
			if d.count.Load() != 1 {
				t.Fatal("conflict started a second downstream")
			}
			if shutdown {
				if err == nil {
					t.Fatal("closed worker accepted binding")
				}
				XUDPManager.Lock()
				remaining := XUDPManager.Map[id]
				XUDPManager.Unlock()
				if remaining != nil {
					t.Fatal("unpublished fresh endpoint leaked")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				retainedRead(t, up, "first")
			}
		})
	}
}

func TestXUDPStaleBindingCannotExpireReplacement(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	defer writer.Close()
	m := NewSessionManager()
	x := &XUDP{GlobalID: [8]byte{99}, Status: Active}
	old := &Session{ID: 1, parent: m, input: reader, output: buf.Discard, XUDP: x}
	current := &Session{ID: 2, parent: m, input: reader, output: buf.Discard, XUDP: x}
	x.Mux = current
	m.Add(old)
	m.Add(current)
	XUDPManager.Lock()
	XUDPManager.Map[x.GlobalID] = x
	XUDPManager.Unlock()
	defer func() { XUDPManager.Lock(); delete(XUDPManager.Map, x.GlobalID); XUDPManager.Unlock() }()
	old.Close(false)
	XUDPManager.Lock()
	status := x.Status
	XUDPManager.Unlock()
	if status != Active {
		t.Fatal("stale binding expired current association")
	}
}
