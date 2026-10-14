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
	view     fs.FlowInspection
	t        *testing.T
	admitted chan fs.FlowRef
}

func (s stopAdmissionStore) Begin(kind net.Network, origin fs.TrafficOrigin, source, dest net.Destination, stop func() error) fs.Exchange {
	flow := s.AdmissionStore.Begin(kind, origin, source, dest, stop)
	ref := flow.Ref()
	if ref.ID == 0 {
		s.t.Fatal("fault provider did not admit a logical reference")
	}
	outcomes, err := s.view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
		s.t.Fatalf("admission exact stop: %+v %v", outcomes, err)
	}
	s.admitted <- ref
	return flow
}

func (s stopAdmissionStore) PrepareTCP(origin fs.TrafficOrigin, source, dest net.Destination, stop func() error) fs.Exchange {
	flow := s.AdmissionStore.PrepareTCP(origin, source, dest, stop)
	// This fault provider classifies the logical endpoint before exposing it,
	// then injects stop before its native session endpoints are published.
	flow.Route(fs.OutboundRef{})
	ref := flow.Ref()
	if ref.ID == 0 {
		s.t.Fatal("fault provider did not admit a logical reference")
	}
	outcomes, err := s.view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
		s.t.Fatalf("admission exact stop: %+v %v", outcomes, err)
	}
	s.admitted <- ref
	return flow
}

type stopAdmissionManager struct {
	*appstats.Manager
	view     fs.FlowInspection
	t        *testing.T
	admitted chan fs.FlowRef
}

func (m stopAdmissionManager) Observation() fs.AdmissionStore {
	return stopAdmissionStore{m.Manager.Observation(), m.view, m.t, m.admitted}
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
	admitted := make(chan fs.FlowRef, 1)
	wrapped := stopAdmissionManager{manager, view, t, admitted}
	launched := make(chan struct{}, 1)
	d := &retainedDispatcher{dispatch: func(ctx context.Context) (*transport.Link, error) {
		obs := session.LogicalObservationFromContext(ctx)
		obs.ReturnedLink.Store(false)
		launched <- struct{}{}
		return nil, io.ErrClosedPipe
	}}
	var wire bytes.Buffer
	w := &ServerWorker{dispatcher: d, sessionManager: NewSessionManager(), link: &transport.Link{Writer: &buf.SequentialWriter{Writer: &wire}}, store: wrapped.Observation()}
	sink := new(latePayloadWriter)
	sibling := &Session{ID: 9, parent: w.sessionManager, output: sink, transferType: protocol.TransferTypeStream}
	w.sessionManager.Add(sibling)
	meta := &FrameMetadata{SessionID: 1, Option: OptionData, Target: net.TCPDestination(net.LocalHostIP, 80)}
	if retained {
		meta.Target = net.UDPDestination(net.LocalHostIP, 53)
		meta.GlobalID = [8]byte{0xf9, 0xa1}
	}
	reader := lateBodies("canceled")
	err = w.handleStatusNew(context.Background(), meta, reader)
	if err != nil {
		t.Fatalf("exact child stop would terminate carrier: %v", err)
	}
	select {
	case ref := <-admitted:
		if ref.ID == 0 {
			t.Fatal("stopped admission had no exact reference")
		}
	default:
		t.Fatal("native admission stop was not exercised")
	}
	if live, _ := w.sessionManager.Get(9); live != sibling {
		t.Fatal("sibling lost")
	}
	if !retained {
		// The explicit selected stop won before native Session publication.
		// Starting downstream execution after that stop would violate admission.
		select {
		case <-launched:
			t.Fatal("stopped selected admission started downstream execution")
		default:
		}
		if d.count.Load() != 0 {
			t.Fatal("stopped selected child was dispatched")
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("stopped initial frame was not drained: %v", err)
	}
	if err := w.handleStatusKeep(&FrameMetadata{SessionID: 9, Option: OptionData}, lateBodies("sibling")); err != nil {
		t.Fatalf("stopped admission blocked sibling forwarding: %v", err)
	}
	if sink.body != "sibling" {
		t.Fatalf("sibling payload lost: %q", sink.body)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLiveInto(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stopped admission did not release its owners")
}

func TestMuxEndRetiresBeforeLateInitialFrame(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	link, _, response, _ := retainedLink(t, 1024)
	response.Close()
	d := &retainedDispatcher{dispatch: func(ctx context.Context) (*transport.Link, error) {
		observation := session.LogicalObservationFromContext(ctx)
		observation.Exchange.Route(fs.OutboundRef{Tag: "tag-1"})
		return link, nil
	}}
	carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	w := retainedWorker(t, d, carrier)
	w.store = manager.Observation()
	sibling := &Session{ID: 9, parent: w.sessionManager, output: buf.Discard}
	w.sessionManager.Add(sibling)
	input, payload := io.Pipe()
	t.Cleanup(func() { input.Close(); payload.Close() })
	returned := make(chan error, 1)
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	meta := &FrameMetadata{SessionID: 1, Option: OptionData, Target: net.TCPDestination(net.LocalHostIP, 80)}
	go func() {
		returned <- w.handleStatusNew(ctx, meta, &buf.BufferedReader{Reader: buf.NewReader(input)})
	}()
	muxWait(t, carrier.entered)
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref.ID == 0 || live.Rows[0].Uplink != 0 {
		t.Fatalf("blocked END admission: %+v %v", live, err)
	}
	release()
	deadline := time.Now().Add(3 * time.Second)
	for {
		live, err = view.ReadLiveInto(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 0 {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("END did not retire before late initial frame")
		}
		time.Sleep(time.Millisecond)
	}

	if got, _ := w.sessionManager.Get(9); got != sibling {
		t.Fatal("END retirement closed a sibling")
	}
	if _, err := payload.Write([]byte{0, 3, 'l', 'a', 't'}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("late initial frame did not drain: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late initial frame blocked the carrier")
	}

	totals, _ := view.ReadTotals()
	var uplink uint64
	for _, row := range totals.Rows {
		uplink += row.Uplink
	}
	// The late frame is drained at general admission, never read by selected execution.
	if totals.User.Uplink != 3 || uplink != 0 {
		t.Fatalf("late initial frame USER/selected bytes: %+v", totals)
	}
}

func muxServerFact(t *testing.T, view fs.FlowInspection) fs.FlowRecord {
	t.Helper()
	live, err := view.ReadLiveInto(nil)
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
		writer := NewResponseWriter(1, &buf.SequentialWriter{Writer: lower}, protocol.TransferTypeStream)
		writer.receipt = flow
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte{1}, 8197))); err == nil {
			t.Fatal("missing partial error")
		}
		row := muxServerFact(t, view)
		if row.Downlink != 8192 {
			t.Fatalf("frame prefix: %+v", row.Downlink)
		}
		flow.Finish()
	})
	t.Run("buffered-header-and-control", func(t *testing.T) {
		flow, view := muxInspectionFlow(t)
		var wire bytes.Buffer
		buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: &wire})
		buffered.Write([]byte("outer header"))
		buffered.SetFlushNext()
		output := buffered
		writer := NewResponseWriter(1, output, protocol.TransferTypePacket)
		writer.receipt = flow
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("body"))}); err != nil {
			t.Fatal(err)
		}
		writer.Close()
		row := muxServerFact(t, view)
		if row.Downlink != 4 {
			t.Fatalf("header/control counted: %+v", row.Downlink)
		}
		flow.Finish()
	})
	t.Run("unknown-writer", func(t *testing.T) {
		flow, view := muxInspectionFlow(t)
		writer := NewResponseWriter(1, buf.Discard, protocol.TransferTypeStream)
		writer.receipt = flow
		writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("unknown"))})
		row := muxServerFact(t, view)
		if row.Downlink != 7 {
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
	manager := new(appstats.Manager)
	if _, err := manager.EnableInspection(fs.ObservationOptions{}); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	worker := &ServerWorker{link: &transport.Link{Writer: lower}, store: manager.Observation()}
	output := worker.carrierWriter()
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
	if muxServerFact(t, a).Downlink != 20 || muxServerFact(t, b).Downlink != 40 {
		t.Fatal("carrier mixed child receipts")
	}
	first.Finish()
	second.Finish()
}

func TestMuxDeferredBufferDoesNotInventDrop(t *testing.T) {
	flow, view := muxInspectionFlow(t)
	var wire bytes.Buffer
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: &wire})
	writer := NewResponseWriter(1, buffered, protocol.TransferTypePacket)
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
	if row.Downlink != 5 {
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

func (s rebindStopStore) Begin(k net.Network, o fs.TrafficOrigin, src, dst net.Destination, stop func() error) fs.Exchange {
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
	next.store = manager.Observation()
	if next.store.Runtime() != view.Runtime() {
		t.Fatal("rebind runtime differs")
	}
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

	release()
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
	if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
		t.Fatalf("stop: %+v %v", outcomes, err)
	}
	muxWait(t, canceled)

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

	if got, _ := w.sessionManager.Get(9); got != sibling {
		t.Fatal("sibling lost")
	}
	release()
}

// Observation-off native dispatch still executes and forwards ordinary initial
// data. The selected admission-stop fixture above must not force its execution.
func TestMuxNativeOrdinaryDispatchRetainsForwarding(t *testing.T) {
	link, up, response, _ := retainedLink(t, 1024)
	d := &retainedDispatcher{dispatch: func(ctx context.Context) (*transport.Link, error) {
		if ctx.Err() != nil || session.LogicalObservationFromContext(ctx) != nil {
			t.Fatal("native ordinary dispatch inherited selected cancellation or observation")
		}
		return link, nil
	}}
	carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	w := &ServerWorker{dispatcher: d, sessionManager: NewSessionManager(), link: &transport.Link{Writer: carrier}}
	t.Cleanup(func() { w.sessionManager.Close() })
	if err := w.handleStatusNew(context.Background(), &FrameMetadata{
		SessionID: 1, Option: OptionData, Target: net.TCPDestination(net.LocalHostIP, 80),
	}, lateBodies("native ordinary")); err != nil {
		t.Fatal(err)
	}
	if d.count.Load() != 1 {
		t.Fatal("native ordinary dispatcher not exercised exactly once")
	}
	retainedRead(t, up, "native ordinary")
	response.Close()
	muxWait(t, carrier.entered)
	release()
}
