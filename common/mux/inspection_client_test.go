package mux

import (
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
	"github.com/xtls/xray-core/common/signal/done"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// Dispatch and carrier shutdown race at the real SessionManager publication
// boundary. The original Allocate exposes nil endpoints to Close.
func TestClientSessionPublication(t *testing.T) {
	for range 200 {
		reader, writer := pipe.New(pipe.WithoutSizeLimit())
		writer.Close()
		worker := &ClientWorker{sessionManager: NewSessionManager(), done: done.New(), link: transport.Link{Writer: buf.Discard}}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.UDPDestination(net.LocalHostIP, 53)}})
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			worker.Dispatch(ctx, &transport.Link{Reader: reader, Writer: buf.Discard})
		}()
		go func() {
			defer wg.Done()
			<-start
			worker.sessionManager.Close()
		}()
		close(start)
		wg.Wait()
	}
}

func muxInspectionFlow(t *testing.T) (fs.Exchange, fs.FlowInspection) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUser, net.Destination{}, net.TCPDestination(net.LocalHostIP, 80), nil)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	return flow, view
}

func muxWait(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("native task did not reach gate")
	}
}

func muxCheckTerminal(t *testing.T, view fs.FlowInspection, count int) {
	t.Helper()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != count {
		t.Fatalf("terminal count %d: %+v %v", count, page, err)
	}
}

type muxBlockedWriter struct{ entered, release chan struct{} }

func (w *muxBlockedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	close(w.entered)
	<-w.release
	return nil
}

func TestClientInspectionPendingEnd(t *testing.T) {
	flow, view := muxInspectionFlow(t)
	lower, input := pipe.New(pipe.WithoutSizeLimit())
	input.Close()
	cursor := buf.NewInspectionReader(&buf.BufferedReader{Reader: lower}, flow, lower.Interrupt)
	ctx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: flow})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 80)}})
	output := &muxBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(output.release) })
	t.Cleanup(release)
	worker := &ClientWorker{sessionManager: NewSessionManager(), done: done.New(), link: transport.Link{Writer: output}}
	dispatched := make(chan struct{})
	go func() { worker.Dispatch(ctx, &transport.Link{Reader: cursor, Writer: buf.Discard}); close(dispatched) }()
	muxWait(t, output.entered)
	worker.sessionManager.Close()
	muxWait(t, dispatched)
	flow.Finish()
	muxCheckTerminal(t, view, 1)
	release()
	muxCheckTerminal(t, view, 1)
}

type muxBlockedReader struct{ entered, release chan struct{} }

func (r *muxBlockedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.entered)
	<-r.release
	return nil, io.EOF
}

func TestClientInspectionPendingResponse(t *testing.T) {
	t.Run("KEEP", func(t *testing.T) { muxPendingResponse(t, false) })
	t.Run("END", func(t *testing.T) { muxPendingResponse(t, true) })
}

func muxPendingResponse(t *testing.T, ending bool) {
	t.Helper()
	flow, view := muxInspectionFlow(t)
	manager := NewSessionManager()
	lower, input := pipe.New(pipe.WithoutSizeLimit())
	defer input.Close()
	s := manager.allocate(&ClientStrategy{}, &Session{input: lower, output: buf.Discard, transferType: protocol.TransferTypeStream, inspection: flow})
	worker := &ClientWorker{sessionManager: manager}
	reader := &muxBlockedReader{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(reader.release) })
	t.Cleanup(release)
	returned := make(chan struct{})
	go func() {
		meta := &FrameMetadata{SessionID: s.ID, Option: OptionData}
		buffered := &buf.BufferedReader{Reader: reader}
		if ending {
			worker.handleStatusEnd(meta, buffered)
		} else {
			worker.handleStatusKeep(meta, buffered)
		}
		close(returned)
	}()
	muxWait(t, reader.entered)
	s.Close(false)
	flow.Finish()
	muxCheckTerminal(t, view, 1)
	release()
	muxWait(t, returned)
	muxCheckTerminal(t, view, 1)
}

func TestClientInspectionFailedAllocation(t *testing.T) {
	flow, view := muxInspectionFlow(t)
	manager := NewSessionManager()
	manager.Close()
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	defer writer.Close()
	cursor := buf.NewInspectionReader(&buf.BufferedReader{Reader: reader}, flow, reader.Interrupt)
	observation := &session.LogicalObservation{Exchange: flow}
	ctx := session.ContextWithLogicalObservation(context.Background(), observation)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 80)}})
	worker := &ClientWorker{sessionManager: manager, done: done.New()}
	if worker.Dispatch(ctx, &transport.Link{Reader: cursor, Writer: buf.Discard}) {
		t.Fatal("closed manager accepted child")
	}
	flow.Finish()
	muxCheckTerminal(t, view, 1)
}

type muxInspectionPicker struct {
	worker *ClientWorker
	err    error
}

func (p muxInspectionPicker) PickAvailable() (*ClientWorker, error) { return p.worker, p.err }

func TestClientInspectionPickerFailure(t *testing.T) {
	for _, failedFactory := range []bool{false, true} {
		name := "all-workers-full"
		if failedFactory {
			name = "factory-failure"
		}
		t.Run(name, func(t *testing.T) {
			flow, view := muxInspectionFlow(t)
			reader, writer := pipe.New(pipe.WithoutSizeLimit())
			defer writer.Close()
			cursor := buf.NewInspectionReader(&buf.BufferedReader{Reader: reader}, flow, reader.Interrupt)
			observation := &session.LogicalObservation{Exchange: flow}
			ctx := session.ContextWithLogicalObservation(context.Background(), observation)
			worker := &ClientWorker{sessionManager: NewSessionManager(), done: done.New()}
			worker.done.Close()
			picker := muxInspectionPicker{worker: worker}
			if failedFactory {
				picker.err = io.ErrClosedPipe
			}
			manager := ClientManager{Picker: picker}
			if err := manager.Dispatch(ctx, &transport.Link{Reader: cursor, Writer: buf.Discard}); err == nil {
				t.Fatal("unavailable worker accepted dispatch")
			}
			flow.Finish()
			muxCheckTerminal(t, view, 1)
		})
	}
}
