package tun

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appdispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type flowTestCounter struct {
	value int64
}

func (c *flowTestCounter) Value() int64          { return atomic.LoadInt64(&c.value) }
func (c *flowTestCounter) Set(value int64) int64 { return atomic.SwapInt64(&c.value, value) }
func (c *flowTestCounter) Add(value int64) int64 { return atomic.AddInt64(&c.value, value) - value }

type flowTestConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
	closed int32
}

func newFlowTestConn(input []byte) *flowTestConn {
	return &flowTestConn{reader: bytes.NewReader(input)}
}

func (c *flowTestConn) Read(payload []byte) (int, error)  { return c.reader.Read(payload) }
func (c *flowTestConn) Write(payload []byte) (int, error) { return c.writer.Write(payload) }
func (c *flowTestConn) Close() error {
	atomic.AddInt32(&c.closed, 1)
	return nil
}

func (*flowTestConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (*flowTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}
func (*flowTestConn) SetDeadline(time.Time) error      { return nil }
func (*flowTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*flowTestConn) SetWriteDeadline(time.Time) error { return nil }

type flowFallbackDispatcher struct {
	writePayload []byte
	readBytes    int32
	linkCalls    int32
}

func (*flowFallbackDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*flowFallbackDispatcher) Start() error      { return nil }
func (*flowFallbackDispatcher) Close() error      { return nil }
func (*flowFallbackDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *flowFallbackDispatcher) DispatchLink(_ context.Context, _ xnet.Destination, link *transport.Link) error {
	atomic.AddInt32(&d.linkCalls, 1)
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

type flowUserStreamDispatcher struct {
	flowFallbackDispatcher
	userCalls int32
	stopped   bool
}

func (d *flowUserStreamDispatcher) DispatchUserStream(ctx context.Context, _ xnet.Destination, stream routing.UserStream) error {
	atomic.AddInt32(&d.userCalls, 1)
	mb, err := buf.NewReader(stream.Connection).ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)
	if _, err := stream.Connection.Write(d.writePayload); err != nil {
		return err
	}
	if stream.Stop == nil {
		return nil
	}
	if err := stream.Stop(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		d.stopped = true
	default:
	}
	return nil
}

func TestHandlerKeepsDispatchLinkFallback(t *testing.T) {
	dispatcher := &flowFallbackDispatcher{writePayload: []byte("downlink")}
	conn := newFlowTestConn([]byte("uplink"))
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher}

	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := atomic.LoadInt32(&dispatcher.linkCalls); got != 1 {
		t.Fatalf("fallback dispatch calls: got %d, want 1", got)
	}
	if got := atomic.LoadInt32(&dispatcher.readBytes); got != int32(len("uplink")) {
		t.Fatalf("fallback read bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("fallback write mismatch: got %q, want %q", got, "downlink")
	}
	if got := atomic.LoadInt32(&conn.closed); got != 1 {
		t.Fatalf("fallback close count: got %d, want 1", got)
	}
}

func TestHandlerDispatchesTCPThroughCanonicalUserStream(t *testing.T) {
	uplinkCounter := new(flowTestCounter)
	downlinkCounter := new(flowTestCounter)
	dispatcher := &flowUserStreamDispatcher{flowFallbackDispatcher: flowFallbackDispatcher{writePayload: []byte("downlink")}}
	conn := newFlowTestConn([]byte("uplink"))
	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}

	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := atomic.LoadInt32(&dispatcher.userCalls); got != 1 {
		t.Fatalf("user dispatch calls: got %d, want 1", got)
	}
	if got := atomic.LoadInt32(&dispatcher.linkCalls); got != 0 {
		t.Fatalf("fallback dispatch called: %d", got)
	}
	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("canonical uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("canonical downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("canonical read bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("canonical write mismatch: got %q, want %q", got, "downlink")
	}
	if !dispatcher.stopped {
		t.Fatal("stop did not cancel exact flow context")
	}
	if got := atomic.LoadInt32(&conn.closed); got != 1 {
		t.Fatalf("exact connection close count: got %d, want 1", got)
	}
}

type blockingFlowTestConn struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls int32
	remote     *net.TCPAddr
}

func newBlockingFlowTestConn(port int) *blockingFlowTestConn {
	return &blockingFlowTestConn{
		closed: make(chan struct{}),
		remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: port},
	}
}

func (c *blockingFlowTestConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (*blockingFlowTestConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *blockingFlowTestConn) Close() error {
	atomic.AddInt32(&c.closeCalls, 1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockingFlowTestConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}
func (c *blockingFlowTestConn) RemoteAddr() net.Addr           { return c.remote }
func (*blockingFlowTestConn) SetDeadline(time.Time) error      { return nil }
func (*blockingFlowTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingFlowTestConn) SetWriteDeadline(time.Time) error { return nil }

type flowSeamEvent struct {
	source   string
	finished bool
	canceled bool
}

type flowSeamOutboundHandler struct {
	outbound.Handler
	events chan flowSeamEvent
}

func (*flowSeamOutboundHandler) Tag() string { return "selected" }
func (h *flowSeamOutboundHandler) Dispatch(ctx context.Context, link *transport.Link) {
	source := session.InboundFromContext(ctx).Source.String()
	h.events <- flowSeamEvent{source: source}
	mb, _ := link.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	h.events <- flowSeamEvent{source: source, finished: true, canceled: ctx.Err() != nil}
}
func (*flowSeamOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*flowSeamOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }

type flowSeamOutboundManager struct {
	outbound.Manager
	h *flowSeamOutboundHandler
}

func (m flowSeamOutboundManager) GetDefaultHandler() outbound.Handler { return m.h }
func (m flowSeamOutboundManager) GetHandler(tag string) outbound.Handler {
	if tag == m.h.Tag() {
		return m.h
	}
	return nil
}

func TestHandlerCloseFlowRealDispatcherSeam(t *testing.T) {
	events := make(chan flowSeamEvent, 4)
	outboundHandler := &flowSeamOutboundHandler{events: events}
	dispatcher := new(appdispatcher.DefaultDispatcher)
	if err := dispatcher.Init(new(appdispatcher.Config), flowSeamOutboundManager{h: outboundHandler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.EnableConnectionTracking(2); err != nil {
		t.Fatal(err)
	}

	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.test"), 443)
	firstConn := newBlockingFlowTestConn(12001)
	siblingConn := newBlockingFlowTestConn(12002)
	t.Cleanup(func() {
		_ = firstConn.Close()
		_ = siblingConn.Close()
		_ = dispatcher.Close()
	})
	firstDone, siblingDone := make(chan struct{}), make(chan struct{})
	go func() {
		handler.HandleConnection(firstConn, destination)
		close(firstDone)
	}()
	go func() {
		handler.HandleConnection(siblingConn, destination)
		close(siblingDone)
	}()

	started := make(map[string]bool)
	for len(started) != 2 {
		select {
		case event := <-events:
			if event.finished {
				t.Fatalf("flow finished before close: %+v", event)
			}
			started[event.source] = true
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for live TUN flows")
		}
	}

	snapshot := dispatcher.ConnectionSnapshot()
	if len(snapshot.Connections) != 2 {
		t.Fatalf("live rows: %+v", snapshot)
	}
	firstSource := xnet.DestinationFromAddr(firstConn.RemoteAddr()).String()
	siblingSource := xnet.DestinationFromAddr(siblingConn.RemoteAddr()).String()
	var firstRef, siblingRef appdispatcher.FlowRef
	for _, row := range snapshot.Connections {
		if row.FlowRef == (appdispatcher.FlowRef{}) || row.Destination != destination.String() || row.OutboundTag != "selected" || !row.OutboundSelected || row.UplinkReadBytes != 0 || row.DownlinkWrittenBytes != 0 || row.UplinkCoverage != appdispatcher.BytesExact || row.DownlinkCoverage != appdispatcher.BytesExact {
			t.Fatalf("raw row facts: %+v", row)
		}
		switch row.Source {
		case firstSource:
			firstRef = row.FlowRef
		case siblingSource:
			siblingRef = row.FlowRef
		}
	}
	if firstRef == (appdispatcher.FlowRef{}) || siblingRef == (appdispatcher.FlowRef{}) {
		t.Fatalf("missing instance-scoped refs: %+v", snapshot.Connections)
	}

	if got := dispatcher.CloseFlow(firstRef); got.Outcome != appdispatcher.CloseFlowAccepted || got.Err != nil {
		t.Fatalf("first close: %+v", got)
	}
	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first TUN flow did not unblock")
	}
	select {
	case <-siblingDone:
		t.Fatal("sibling stopped with first flow")
	default:
	}
	if got := atomic.LoadInt32(&firstConn.closeCalls); got != 1 {
		t.Fatalf("first underlying close calls: got %d, want 1", got)
	}
	if got := atomic.LoadInt32(&siblingConn.closeCalls); got != 0 {
		t.Fatalf("sibling underlying close calls: got %d, want 0", got)
	}
	remaining := dispatcher.ConnectionSnapshot().Connections
	if len(remaining) != 1 || remaining[0].Source != siblingSource || remaining[0].FlowRef != siblingRef {
		t.Fatalf("wrong remaining flow: %+v", remaining)
	}

	finished := <-events
	if !finished.finished || finished.source != firstSource || !finished.canceled {
		t.Fatalf("first completion receipt: %+v", finished)
	}
	if got := dispatcher.CloseFlow(siblingRef); got.Outcome != appdispatcher.CloseFlowAccepted || got.Err != nil {
		t.Fatalf("sibling close: %+v", got)
	}
	select {
	case <-siblingDone:
	case <-time.After(5 * time.Second):
		t.Fatal("sibling TUN flow did not unblock")
	}
	if got := atomic.LoadInt32(&siblingConn.closeCalls); got != 1 {
		t.Fatalf("sibling underlying close calls: got %d, want 1", got)
	}
	finished = <-events
	if !finished.finished || finished.source != siblingSource || !finished.canceled {
		t.Fatalf("sibling completion receipt: %+v", finished)
	}
	if rows := dispatcher.ConnectionSnapshot().Connections; len(rows) != 0 {
		t.Fatalf("retired rows: %+v", rows)
	}
}
