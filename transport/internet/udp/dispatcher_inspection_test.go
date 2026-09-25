package udp

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type inspectionDiscardWriter struct{}

func (inspectionDiscardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

type inspectionRootWithLegFinish struct {
	fs.Exchange
	legFinished chan struct{}
}

func (e *inspectionRootWithLegFinish) NewLeg() fs.Exchange {
	leg := e.Exchange.NewLeg()
	if leg == nil {
		return nil
	}
	return &inspectionLegFinish{Exchange: leg, finished: e.legFinished}
}

type inspectionLegFinish struct {
	fs.Exchange
	finished chan struct{}
	once     sync.Once
}

func (e *inspectionLegFinish) Finish() {
	e.Exchange.Finish()
	e.once.Do(func() { close(e.finished) })
}

func (e *inspectionLegFinish) FinishSelectedLeg() {
	e.Exchange.(interface{ FinishSelectedLeg() }).FinishSelectedLeg()
}

func TestUDPDispatcherInspectionEarlyRayFinishBeforeSelectedRole(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{MaxDestinations: 2})
	t.Cleanup(func() { manager.Close() })
	dest := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, dest, nil)
	legFinished := make(chan struct{})
	roleSelected := make(chan struct{})
	selectedDone := make(chan struct{})
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		observation := session.LogicalObservationFromContext(ctx)
		if observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
			t.Fatal("dispatcher did not claim the pending ray")
		}
		reader, writer := pipe.New()
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		go func() {
			defer close(selectedDone)
			<-roleSelected
			observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionRule, Outbound: fs.OutboundRef{Serial: 41, Tag: "ordinary"}})
			observation.Exchange.BindRoute()
			observation.Exchange.(interface{ FinishSelectedLeg() }).FinishSelectedLeg()
		}()
		return &transport.Link{Reader: reader, Writer: inspectionDiscardWriter{}}, nil
	}}, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
	d.Observation = &inspectionRootWithLegFinish{Exchange: root, legFinished: legFinished}
	d.Dispatch(context.Background(), dest, buf.FromBytes([]byte("pending input")))
	lifecycleWait(t, legFinished)
	root.Finish()
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 0 || len(page.Rows[0].Flow.Routes) != 0 || len(page.Rows[0].Flow.Destinations) != 0 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("owner-end pending snapshot: %+v", page)
	}
	close(roleSelected)
	lifecycleWait(t, selectedDone)
	again, _ := view.ReadTerminals(context.Background())
	if len(again.Rows) != 1 || again.Rows[0].Flow.Uplink.Known != 0 || len(again.Rows[0].Flow.Routes) != 0 || len(again.Rows[0].Flow.Destinations) != 0 {
		t.Fatalf("selected role changed immutable terminal: %+v", again)
	}
	totals, _ := view.ReadTotals(context.Background())
	for _, total := range totals.Rows {
		if total.Outbound.Serial == 41 {
			if total.Uplink.Known != uint64(len("pending input")) || total.Downlink.Known != 0 || total.Uplink.Incomplete || total.Downlink.Incomplete {
				t.Fatalf("late ordinary total: %+v", total)
			}
			return
		}
	}
	t.Fatalf("late ordinary bucket missing: %+v", totals)
}

func TestUDPDispatcherInspectionSynchronousRejection(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	dest := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, dest, nil)
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return nil, errors.New("synchronous route rejection")
	}}, func(context.Context, *protocoludp.Packet) { t.Error("rejected dispatch started a callback") })
	d.Observation = root
	payload := buf.New()
	payload.WriteString("already decoded")
	want := uint64(payload.Len())
	d.Dispatch(context.Background(), dest, payload)
	if !payload.IsEmpty() {
		t.Fatal("rejection retained the submitted packet")
	}
	d.RemoveRay()
	root.Finish()
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || len(page.Rows[0].Flow.Routes) == 0 || page.Rows[0].Flow.Uplink.Known != want || page.Rows[0].Flow.Downlink.Known != 0 || page.Rows[0].Flow.Routes[0].Selection != fs.SelectionRejected {
		t.Fatalf("synchronous rejection lost decoded custody: %+v", page.Rows)
	}
	totals, _ := view.ReadTotals(context.Background())
	for _, total := range totals.Rows {
		if total.Origin == fs.TrafficOriginUser && total.Outbound.Serial == 0 && (total.Uplink.Known != want || total.Uplink.Incomplete) {
			t.Fatalf("rejected unassigned total: %+v", total)
		}
	}
}

func TestUDPDispatcherInspectionOverlappingRays(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	dest := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, dest, nil)
	var serial uint64
	var outputs []*pipe.Writer
	firstStarted, releaseFirst, firstDone, secondDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		serial++
		observation := session.LogicalObservationFromContext(ctx)
		if observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
			t.Fatal("missing fresh ray claim")
		}
		observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionRule, Outbound: fs.OutboundRef{Serial: serial}})
		observation.Exchange.BindRoute()
		r, w := pipe.New()
		t.Cleanup(r.Interrupt)
		t.Cleanup(w.Interrupt)
		outputs = append(outputs, w)
		return &transport.Link{Reader: r, Writer: inspectionDiscardWriter{}}, nil
	}}, func(ctx context.Context, packet *protocoludp.Packet) {
		defer packet.Payload.Release()
		if packet.Payload.String() == "old response" {
			close(firstStarted)
			<-releaseFirst
		} else {
			defer close(secondDone)
		}
		session.LogicalObservationFromContext(ctx).Exchange.AddDownlink(uint64(packet.Payload.Len()))
		if packet.Payload.String() == "old response" {
			close(firstDone)
		}
	})
	d.Observation = root
	t.Cleanup(d.RemoveRay)
	d.Dispatch(context.Background(), dest, buf.FromBytes([]byte("old input")))
	old := d.conn
	outputs[0].WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("old response"))})
	lifecycleWait(t, firstStarted)
	old.Close()
	d.Dispatch(context.Background(), dest, buf.FromBytes([]byte("new input")))
	if d.conn == old || serial != 2 {
		t.Fatal("did not replace retired native ray")
	}
	old.Close() // A stale close must leave the new entry intact.
	outputs[1].WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("new response"))})
	lifecycleWait(t, secondDone)
	d.RemoveRay()
	root.Finish()
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 18 || page.Rows[0].Flow.Downlink.Known != 12 {
		t.Fatalf("owner-end association snapshot: %+v", page)
	}
	close(releaseFirst)
	lifecycleWait(t, firstDone)
	page, _ = view.ReadTerminals(context.Background())
	row := page.Rows[0].Flow
	if row.Ref != root.Ref() || row.Uplink.Known != 18 || row.Downlink.Known != 12 || len(row.Routes) != 2 || row.AccountingRoute.Outbound.Serial != 2 {
		t.Fatalf("overlapping ray facts: %+v", row)
	}
	totals, _ := view.ReadTotals(context.Background())
	for _, total := range totals.Rows {
		if total.Outbound.Serial != 0 && (total.Uplink.Known != 9 || total.Downlink.Known != 12) {
			t.Fatalf("late callback moved buckets: %+v", total)
		}
	}
}

func TestUDPDispatcherInspectionUnclaimedOwner(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	dest := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUnknown, net.Destination{}, dest, nil)
	r, w := pipe.New()
	t.Cleanup(r.Interrupt)
	t.Cleanup(w.Interrupt)
	done := make(chan struct{})
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: r, Writer: inspectionDiscardWriter{}}, nil
	}}, func(_ context.Context, p *protocoludp.Packet) { p.Payload.Release() })
	d.Observation = root
	d.callClose = func() error { close(done); return nil }
	d.Dispatch(context.Background(), dest, buf.FromBytes([]byte("unknown owner")))
	d.RemoveRay()
	root.Finish()
	lifecycleWait(t, done)
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 0 {
		t.Fatalf("unclaimed owner snapshot: %+v", page)
	}
}

func TestInspectionDispatcherAPIConsumption(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	destination := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	ctx := session.ContextWithLogicalObservation(context.Background(), rootObservation)

	var input *buf.InspectionReader
	var response *pipe.Writer
	dispatcher := lifecycleDispatcher{dispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
		observation := session.LogicalObservationFromContext(ctx)
		if observation == nil || !observation.InputAtExecution || !observation.ReturnedLink.CompareAndSwap(true, false) {
			t.Fatal("API ray did not retain execution-consumption custody")
		}
		observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 17, Tag: "api"}})
		observation.Exchange.BindRoute()
		uplinkReader, uplinkWriter := pipe.New()
		downlinkReader, downlinkWriter := pipe.New()
		input = buf.NewInspectionReader(&buf.BufferedReader{Reader: uplinkReader}, observation.Exchange, uplinkReader.Interrupt)
		input.PacketDestination = dest
		response = downlinkWriter
		return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
	}}
	conn, err := DialDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("not credited at WriteTo")
	if n, err := conn.WriteTo(payload, destination.RawNetAddr()); err != nil || n != len(payload) {
		t.Fatalf("WriteTo %d/%d: %v", n, len(payload), err)
	}
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Uplink.Known != 0 {
		t.Fatalf("WriteTo submission credited execution bytes: %+v %v", live, err)
	}
	mb, err := input.ReadMultiBuffer()
	if err != nil || mb.Len() != int32(len(payload)) {
		t.Fatalf("consume API payload: %d %v", mb.Len(), err)
	}
	buf.ReleaseMulti(mb)
	if err := response.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response payload"))}); err != nil {
		t.Fatal(err)
	}
	read := make([]byte, 8)
	n, _, err := conn.ReadFrom(read)
	if err != nil || n != len(read) {
		t.Fatalf("ReadFrom %d/%d: %v", n, len(read), err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) == 1 {
			flow := page.Rows[0].Flow
			if flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(n) || len(flow.Destinations) != 1 || flow.Destinations[0] != destination || flow.AccountingRoute.Outbound.Serial != 17 {
				t.Fatalf("API dispatcher facts: %+v", flow)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("API dispatcher root did not finish")
}

func TestInspectionDispatcherAPINaturalEndDrainsBeforeFinish(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	destination := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	ctx := session.ContextWithLogicalObservation(context.Background(), rootObservation)

	var response *pipe.Writer
	dispatcher := lifecycleDispatcher{dispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		observation := session.LogicalObservationFromContext(ctx)
		if observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
			t.Fatal("missing API ray observation")
		}
		observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 23, Tag: "api"}})
		observation.Exchange.BindRoute()
		downlinkReader, downlinkWriter := pipe.New()
		response = downlinkWriter
		return &transport.Link{Reader: downlinkReader, Writer: inspectionDiscardWriter{}}, nil
	}}
	packetConn, err := DialDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packetConn.WriteTo([]byte("request"), destination.RawNetAddr()); err != nil {
		t.Fatal(err)
	}
	responsePayload := []byte("queued response")
	if err := response.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(responsePayload)}); err != nil {
		t.Fatal(err)
	}
	if err := response.Close(); err != nil {
		t.Fatal(err)
	}
	c := packetConn.(*dispatcherConn)
	deadline := time.Now().Add(5 * time.Second)
	for !c.done.Done() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !c.done.Done() {
		t.Fatal("native ray did not end")
	}
	if page, _ := view.ReadTerminals(context.Background()); len(page.Rows) != 0 {
		t.Fatalf("native EOF finished root before queued response read: %+v", page.Rows)
	}
	read := make([]byte, len(responsePayload))
	n, _, err := packetConn.ReadFrom(read)
	if err != nil || n != len(responsePayload) {
		t.Fatalf("read queued response %d/%d: %v", n, len(responsePayload), err)
	}
	if page, _ := view.ReadTerminals(context.Background()); len(page.Rows) != 0 {
		t.Fatalf("last queued response finished before caller observed EOF: %+v", page.Rows)
	}
	if _, _, err := packetConn.ReadFrom(read); !errors.Is(err, io.EOF) {
		t.Fatalf("post-drain read: %v", err)
	}
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != uint64(len(responsePayload)) {
		t.Fatalf("post-drain terminal: %+v", page.Rows)
	}
}

func TestInspectionDispatcherAPIExplicitCloseDrainsCache(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	packetConn, err := DialDispatcher(session.ContextWithLogicalObservation(context.Background(), rootObservation), lifecycleDispatcher{})
	if err != nil {
		t.Fatal(err)
	}
	c := packetConn.(*dispatcherConn)
	leg := root.NewLeg()
	leg.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 29, Tag: "api"}})
	leg.BindRoute()
	callbackCtx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: leg})
	buffers := make([]*buf.Buffer, cap(c.cache))
	for i := range buffers {
		buffers[i] = buf.New()
		buffers[i].WriteByte(byte(i + 1))
		c.callback(callbackCtx, &protocoludp.Packet{Payload: buffers[i]})
	}
	if len(c.cache) != cap(c.cache) {
		t.Fatalf("cache fill: %d/%d", len(c.cache), cap(c.cache))
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	for i, buffer := range buffers {
		if !buffer.IsEmpty() {
			t.Fatalf("cached payload %d retained after close", i)
		}
	}
	late := buf.New()
	late.WriteString("late")
	c.callback(callbackCtx, &protocoludp.Packet{Payload: late})
	if !late.IsEmpty() || len(c.cache) != 0 {
		t.Fatalf("callback enqueued after close: empty=%v cache=%d", late.IsEmpty(), len(c.cache))
	}
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("explicit-close loss facts: %+v", page.Rows)
	}
}

func TestInspectionDispatcherAPIReadCloseSamePacket(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	packetConn, err := DialDispatcher(session.ContextWithLogicalObservation(context.Background(), rootObservation), lifecycleDispatcher{})
	if err != nil {
		t.Fatal(err)
	}
	c := packetConn.(*dispatcherConn)
	leg := root.NewLeg()
	leg.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 31, Tag: "api"}})
	leg.BindRoute()
	payload := buf.New()
	payload.WriteString("racing response")
	c.callback(session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: leg}), &protocoludp.Packet{Payload: payload, Source: net.UDPDestination(net.LocalHostIP, 53)})
	c.mu.Lock()
	type readResult struct {
		n   int
		err error
	}
	readDone := make(chan readResult, 1)
	go func() {
		n, _, err := packetConn.ReadFrom(make([]byte, 32))
		readDone <- readResult{n, err}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for len(c.cache) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(c.cache) != 0 {
		c.mu.Unlock()
		t.Fatal("read did not take the queued packet")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- packetConn.Close() }()
	c.mu.Unlock()
	read := <-readDone
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if read.n == 0 && !errors.Is(read.err, io.EOF) {
		t.Fatalf("closed read: %d %v", read.n, read.err)
	}
	if read.n != 0 && (read.n != len("racing response") || read.err != nil) {
		t.Fatalf("returned read: %d %v", read.n, read.err)
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != uint64(read.n) || !payload.IsEmpty() {
		t.Fatalf("read/close terminal: %+v %v released=%v", page.Rows, err, payload.IsEmpty())
	}
}

func TestInspectionDispatcherAPIUnclaimedEndReconcilesBeforeEOF(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	ctx := session.ContextWithLogicalObservation(context.Background(), rootObservation)
	reader, writer := pipe.New()
	t.Cleanup(reader.Interrupt)
	dispatcher := lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: reader, Writer: inspectionDiscardWriter{}}, nil
	}}
	packetConn, err := DialDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	c := packetConn.(*dispatcherConn)
	destination := net.UDPDestination(net.LocalHostIP, 53)
	if _, err := packetConn.WriteTo([]byte("unclaimed"), destination.RawNetAddr()); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, _, err := packetConn.ReadFrom(make([]byte, 1))
		readDone <- err
	}()
	c.dispatcher.Lock()
	if err := writer.Close(); err != nil {
		c.dispatcher.Unlock()
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		c.dispatcher.Unlock()
		t.Fatalf("EOF reached caller before ray reconciliation: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if page, _ := view.ReadTerminals(context.Background()); len(page.Rows) != 0 {
		c.dispatcher.Unlock()
		t.Fatalf("unclaimed root published before ray reconciliation: %+v", page.Rows)
	}
	c.dispatcher.Unlock()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("post-reconciliation read: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unclaimed ray did not retire")
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 0 {
		t.Fatalf("unclaimed root terminal: %+v %v", page.Rows, err)
	}
}
