package mux

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type muxPrefixWriter struct{ left int }

func (w *muxPrefixWriter) Write(p []byte) (int, error) {
	n := min(w.left, len(p))
	w.left -= n
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

type stopAdmissionStore struct {
	fs.AdmissionStore
	view fs.FlowInspection
}

func (s stopAdmissionStore) Begin(kind fs.FlowKind, origin fs.TrafficOrigin, source, dest net.Destination, stop func() error) fs.Exchange {
	flow := s.AdmissionStore.Begin(kind, origin, source, dest, stop)
	s.view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
	return flow
}

func (s stopAdmissionStore) PrepareTCP(origin fs.TrafficOrigin, source, dest net.Destination, stop func() error) fs.Exchange {
	flow := s.AdmissionStore.PrepareTCP(origin, source, dest, stop)
	// This fault provider classifies the logical endpoint before exposing it,
	// then injects stop before its native session endpoints are published.
	flow.BindRoute()
	s.view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
	return flow
}

type stopAdmissionManager struct {
	*appstats.Manager
	view fs.FlowInspection
}

func (m stopAdmissionManager) Observation() fs.AdmissionStore {
	return stopAdmissionStore{m.Manager.Observation(), m.view}
}

func TestMuxServerStopDuringAdmissionKeepsCarrier(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) { muxStopDuringAdmission(t, false) })
	t.Run("retained", func(t *testing.T) { muxStopDuringAdmission(t, true) })
}

func muxStopDuringAdmission(t *testing.T, retained bool) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	wrapped := stopAdmissionManager{manager, view}
	launched := make(chan struct{}, 1)
	d := &retainedDispatcher{dispatch: func(ctx context.Context) (*transport.Link, error) {
		obs := session.LogicalObservationFromContext(ctx)
		obs.ReturnedLink.Store(false)
		launched <- struct{}{}
		return nil, io.ErrClosedPipe
	}}
	var wire bytes.Buffer
	w := &ServerWorker{dispatcher: d, sessionManager: NewSessionManager(), link: &transport.Link{Writer: &buf.SequentialWriter{Writer: &wire}}, stats: wrapped, store: wrapped.Observation()}
	sibling := &Session{ID: 9, parent: w.sessionManager, output: buf.Discard}
	w.sessionManager.Add(sibling)
	meta := &FrameMetadata{SessionID: 1, Option: OptionData, Target: net.TCPDestination(net.LocalHostIP, 80)}
	if retained {
		meta.Target = net.UDPDestination(net.LocalHostIP, 53)
		meta.GlobalID = [8]byte{0xf9, 0xa1}
	}
	err = w.handleStatusNew(context.Background(), meta, lateBodies("canceled"))
	if err != nil {
		t.Fatalf("exact child stop would terminate carrier: %v", err)
	}
	if live, _ := w.sessionManager.Get(9); live != sibling {
		t.Fatal("sibling lost")
	}
	if !retained {
		select {
		case <-launched:
		default:
			t.Fatal("ordinary native dispatch was not exercised")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, _ := view.ReadTerminals(context.Background())
		if len(page.Rows) == 1 {
			if page.Rows[0].Reason != fs.EndReasonLocalStop {
				t.Fatal("lost stop reason")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stopped admission did not release its owners")
}

func muxServerFact(t *testing.T, view fs.FlowInspection) fs.FlowRecord {
	t.Helper()
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live: %+v %v", live, err)
	}
	return live.Rows[0]
}

func TestMuxDecodedOperations(t *testing.T) {
	t.Run("prefix-failure", func(t *testing.T) {
		flow, view := muxInspectionFlow(t)
		header := buf.New()
		FrameMetadata{SessionID: 1, SessionStatus: SessionStatusKeep, Option: OptionData}.WriteTo(header)
		lower := &muxPrefixWriter{left: int(header.Len()) + 2 + 8192 + 2}
		header.Release()
		writer := NewResponseWriter(1, newInspectionOutput(&buf.SequentialWriter{Writer: lower}), protocol.TransferTypeStream)
		writer.receipt = flow
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte{1}, 8197))); err == nil {
			t.Fatal("missing partial error")
		}
		row := muxServerFact(t, view)
		if row.Downlink.Known != 8192 || !row.Downlink.Incomplete {
			t.Fatalf("frame prefix: %+v", row.Downlink)
		}
		flow.Finish()
	})
	t.Run("silent-overflow", func(t *testing.T) {
		flow, view := muxInspectionFlow(t)
		reader, lower := pipe.New(pipe.WithSizeLimit(0), pipe.DiscardOverflow())
		defer reader.Interrupt()
		lower.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("occupied"))})
		writer := NewResponseWriter(1, newInspectionOutput(lower), protocol.TransferTypePacket)
		writer.receipt = flow
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("drop"))}); err != nil {
			t.Fatal(err)
		}
		row := muxServerFact(t, view)
		if row.Downlink.Known != 0 || row.Downlink.Incomplete {
			t.Fatalf("overflow: %+v", row.Downlink)
		}
		flow.Finish()
	})
	t.Run("buffered-header-and-control", func(t *testing.T) {
		flow, view := muxInspectionFlow(t)
		var wire bytes.Buffer
		buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: &wire})
		buffered.Write([]byte("outer header"))
		buffered.SetFlushNext()
		output := newInspectionOutput(buffered)
		writer := NewResponseWriter(1, output, protocol.TransferTypePacket)
		writer.receipt = flow
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("body"))}); err != nil {
			t.Fatal(err)
		}
		writer.Close()
		row := muxServerFact(t, view)
		if row.Downlink.Known != 4 || row.Downlink.Incomplete {
			t.Fatalf("header/control counted: %+v", row.Downlink)
		}
		flow.Finish()
	})
	t.Run("unknown-writer", func(t *testing.T) {
		flow, view := muxInspectionFlow(t)
		writer := NewResponseWriter(1, newInspectionOutput(buf.Discard), protocol.TransferTypeStream)
		writer.receipt = flow
		writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("unknown"))})
		row := muxServerFact(t, view)
		if row.Downlink.Known != 7 || row.Downlink.Incomplete {
			t.Fatalf("successful decoded operation lost: %+v", row.Downlink)
		}
		flow.Finish()
	})
}

func TestMuxDecodedOperationIsolation(t *testing.T) {
	first, a := muxInspectionFlow(t)
	second, b := muxInspectionFlow(t)
	reader, lower := pipe.New()
	defer reader.Interrupt()
	output := newInspectionOutput(lower)
	var wg sync.WaitGroup
	for i, flow := range []fs.Exchange{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writer := NewResponseWriter(uint16(i+1), output, protocol.TransferTypeStream)
			writer.receipt = flow
			for range 20 {
				writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(bytes.Repeat([]byte{1}, i+1))})
			}
			writer.Close()
		}()
	}
	wg.Wait()
	if muxServerFact(t, a).Downlink.Known != 20 || muxServerFact(t, b).Downlink.Known != 40 {
		t.Fatal("carrier mixed child receipts")
	}
	first.Finish()
	second.Finish()
}

func TestMuxDeferredBufferDoesNotInventDrop(t *testing.T) {
	flow, view := muxInspectionFlow(t)
	var wire bytes.Buffer
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: &wire})
	writer := NewResponseWriter(1, newInspectionOutput(buffered), protocol.TransferTypePacket)
	writer.receipt = flow
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("later"))}); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != 0 {
		t.Fatal("native buffering changed")
	}
	if err := buffered.Flush(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire.Bytes(), []byte("later")) {
		t.Fatal("native flush lost frame")
	}
	row := muxServerFact(t, view)
	if row.Downlink.Known != 5 || row.Downlink.Incomplete {
		t.Fatalf("deferred operation result: %+v", row.Downlink)
	}
	flow.Finish()
}

type rebindStopStore struct {
	fs.AdmissionStore
	stop func()
}
type rebindStopExchange struct {
	fs.Exchange
	stop func()
}

func (s rebindStopStore) Begin(k fs.FlowKind, o fs.TrafficOrigin, src, dst net.Destination, stop func() error) fs.Exchange {
	return &rebindStopExchange{Exchange: s.AdmissionStore.Begin(k, o, src, dst, stop), stop: s.stop}
}

func (r *rebindStopExchange) Rebind(runtime fs.RuntimeID, origin fs.TrafficOrigin) {
	r.Exchange.Rebind(runtime, origin)
	r.stop()
}

func TestMuxStopDuringRetainedRebindKeepsCarrier(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	link, up, _, _ := retainedLink(t, 1024)
	d := &retainedDispatcher{dispatch: func(context.Context) (*transport.Link, error) { return link, nil }}
	old := retainedWorker(t, d, buf.Discard)
	id := [8]byte{0xf9, 0xb2}
	retainedCleanup(t, id)
	old.store = rebindStopStore{manager.Observation(), func() { retainedObject(t, id).Interrupt() }}
	if err := retainedNew(old, 1, id, "first"); err != nil {
		t.Fatal(err)
	}
	mb, err := up.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(mb)
	carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	next := retainedWorker(t, d, carrier)
	next.runtime = view.Info().Runtime
	sibling := &Session{ID: 9, parent: next.sessionManager, output: buf.Discard}
	next.sessionManager.Add(sibling)
	if err := retainedNew(next, 2, id, "stopped"); err != nil {
		t.Fatalf("retained stop killed carrier: %v", err)
	}
	muxWait(t, carrier.entered)
	if got, _ := next.sessionManager.Get(9); got != sibling {
		t.Fatal("sibling lost")
	}
	if d.count.Load() != 1 {
		t.Fatal("stopped rebind dispatched again")
	}
	muxCheckTerminal(t, view, 0)
	release()
	waitMuxTerminal(t, view)
}

func waitMuxTerminal(t *testing.T, view fs.FlowInspection) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, _ := view.ReadTerminals(context.Background())
		if len(page.Rows) == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("native owners did not complete")
}

func TestMuxStopDuringRetainedDispatchKeepsCarrier(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	entered, canceled, returnDispatch := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(returnDispatch) })
	t.Cleanup(resume)
	d := &retainedDispatcher{dispatch: func(ctx context.Context) (*transport.Link, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-returnDispatch
		return nil, ctx.Err()
	}}
	carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	w := retainedWorker(t, d, carrier)
	w.store = manager.Observation()
	id := [8]byte{0xf9, 0xb3}
	retainedCleanup(t, id)
	sibling := &Session{ID: 9, parent: w.sessionManager, output: buf.Discard}
	w.sessionManager.Add(sibling)
	done := make(chan error, 1)
	go func() { done <- retainedNew(w, 1, id, "initial") }()
	muxWait(t, entered)
	row := muxServerFact(t, view)
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("stop: %+v %v", outcomes, err)
	}
	muxWait(t, canceled)
	muxCheckTerminal(t, view, 1)
	resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled dispatch killed carrier: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatch did not return")
	}
	muxWait(t, carrier.entered)
	muxCheckTerminal(t, view, 1)
	if got, _ := w.sessionManager.Get(9); got != sibling {
		t.Fatal("sibling lost")
	}
	release()
	waitMuxTerminal(t, view)
	page, _ := view.ReadTerminals(context.Background())
	if page.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatal("local stop reason lost")
	}
}

type muxHeaderGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func (w *muxHeaderGate) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return len(p), nil
}

func TestMuxHeaderCloseKeepsReceiptOwner(t *testing.T) {
	flow, view := muxInspectionFlow(t)
	lower := &muxHeaderGate{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(lower.release) })
	t.Cleanup(release)
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: lower})
	buffered.Write([]byte("header"))
	buffered.SetFlushNext()
	output := newInspectionOutput(buffered)
	closed := make(chan struct{})
	go func() { output.Close(); close(closed) }()
	muxWait(t, lower.entered)
	started, written := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		writer := NewResponseWriter(1, output, protocol.TransferTypeStream)
		writer.receipt = flow
		writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
		close(written)
	}()
	muxWait(t, started)
	select {
	case <-written:
		t.Fatal("frame bypassed pending header")
	case <-time.After(10 * time.Millisecond):
	}
	flow.Finish()
	muxCheckTerminal(t, view, 1)
	release()
	muxWait(t, closed)
	muxWait(t, written)
	muxCheckTerminal(t, view, 1)
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, row := range totals.Rows {
		known += row.Downlink.Known
	}
	if known != uint64(len("payload")) {
		t.Fatalf("late frame total = %d", known)
	}
}
