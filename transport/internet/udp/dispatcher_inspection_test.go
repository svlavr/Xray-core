package udp

import (
	"context"
	"errors"
	"fmt"
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

func TestUDPDispatcherInspectionEarlyRayFinishBeforeSelectedRole(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})

	t.Cleanup(func() { manager.Close() })
	dest := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, dest, nil)
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
			observation.Exchange.Route(fs.OutboundRef{Tag: "ordinary"})
		}()
		return &transport.Link{Reader: reader, Writer: inspectionDiscardWriter{}}, nil
	}}, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
	d.Observation = &inspectionRootWithLegFinish{Exchange: root, legFinished: legFinished}
	d.Dispatch(context.Background(), dest, buf.FromBytes([]byte("pending input")))
	lifecycleWait(t, legFinished)
	root.Finish()

	close(roleSelected)
	lifecycleWait(t, selectedDone)

	totals, _ := view.ReadTotals()
	for _, total := range totals.Rows {
		if total.Outbound.Tag == "ordinary" {
			if total.Uplink != 0 || total.Downlink != 0 {
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
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, dest, nil)
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

	totals, _ := view.ReadTotals()
	if totals.User.Uplink != want || totals.User.Downlink != 0 || len(totals.Rows) != 0 {
		t.Fatalf("rejected general total: %+v", totals)
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
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, dest, nil)
	var rayCount uint64
	var outputs []*pipe.Writer
	firstStarted, releaseFirst, firstDone, secondDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		rayCount++
		observation := session.LogicalObservationFromContext(ctx)
		if observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
			t.Fatal("missing fresh ray claim")
		}
		observation.Exchange.Route(fs.OutboundRef{Tag: fmt.Sprintf("ray-%d", rayCount)})
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
	if d.conn == old || rayCount != 2 {
		t.Fatal("did not replace retired native ray")
	}
	old.Close() // A stale close must leave the new entry intact.
	outputs[1].WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("new response"))})
	lifecycleWait(t, secondDone)
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != root.Ref() || live.Rows[0].Outbound.Tag != "ray-2" || live.Rows[0].Uplink != 18 || live.Rows[0].Downlink != 12 {
		t.Fatalf("overlapping ray live facts: %+v %v", live, err)
	}
	d.RemoveRay()
	root.Finish()

	close(releaseFirst)
	lifecycleWait(t, firstDone)

	totals, _ := view.ReadTotals()
	if len(totals.Rows) != 2 || totals.User != (fs.ClientTotals{Uplink: 18, Downlink: 24}) {
		t.Fatalf("late ray general bytes/buckets: %+v", totals)
	}
	seen := make(map[string]bool)
	for _, total := range totals.Rows {
		tag := total.Outbound.Tag
		// This fixture discards queued input without a selected read.
		if (tag != "ray-1" && tag != "ray-2") || seen[tag] || total.Uplink != 0 || total.Downlink != 12 {
			t.Fatalf("late callback moved buckets: %+v", total)
		}
		seen[tag] = true
	}
}

func TestUDPDispatcherInspectionUnclaimedOwner(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	dest := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUnknown, net.Destination{}, dest, nil)
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
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != root.Ref() || live.Rows[0].Outbound.Tag != "" || live.Rows[0].Destination != dest || live.Rows[0].Uplink != uint64(len("unknown owner")) || live.Rows[0].Downlink != 0 {
		t.Fatalf("unclaimed native owner facts: %+v %v", live, err)
	}
	d.RemoveRay()
	root.Finish()
	lifecycleWait(t, done)
	if live, err := view.ReadLiveInto(nil); err != nil || len(live.Rows) != 0 {
		t.Fatalf("joined unclaimed root remained live: %+v %v", live, err)
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
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
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
		observation.Exchange.Route(fs.OutboundRef{Tag: "api"})
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
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Uplink != 0 {
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
	live, err = view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != root.Ref() || live.Rows[0].Uplink != uint64(len(payload)) || live.Rows[0].Downlink != uint64(n) || live.Rows[0].Destination != destination || live.Rows[0].Outbound.Tag != "api" {
		t.Fatalf("API consumed bytes/destination: %+v %v", live, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
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
	t.Fatal("API dispatcher root did not finish")
}

func TestInspectionDispatcherAPINaturalEndDrainsBeforeFinish(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	destination := net.UDPDestination(net.LocalHostIP, 53)
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	ctx := session.ContextWithLogicalObservation(context.Background(), rootObservation)

	var response *pipe.Writer
	dispatcher := lifecycleDispatcher{dispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		observation := session.LogicalObservationFromContext(ctx)
		if observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
			t.Fatal("missing API ray observation")
		}
		observation.Exchange.Route(fs.OutboundRef{Tag: "api"})
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

	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != root.Ref() || live.Rows[0].Downlink != 0 {
		t.Fatalf("queued native end retired root before delivery: %+v %v", live, err)
	}
	read := make([]byte, len(responsePayload))
	n, _, err := packetConn.ReadFrom(read)
	if err != nil || n != len(responsePayload) {
		t.Fatalf("read queued response %d/%d: %v", n, len(responsePayload), err)
	}

	live, err = view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Downlink != uint64(n) {
		t.Fatalf("delivered packet root before EOF: %+v %v", live, err)
	}
	if _, _, err := packetConn.ReadFrom(read); !errors.Is(err, io.EOF) {
		t.Fatalf("post-drain read: %v", err)
	}
	if live, err := view.ReadLiveInto(nil); err != nil || len(live.Rows) != 0 {
		t.Fatalf("EOF retained API root: %+v %v", live, err)
	}
}

func TestInspectionDispatcherAPIExplicitCloseDrainsCache(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	_, _ = manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	packetConn, err := DialDispatcher(session.ContextWithLogicalObservation(context.Background(), rootObservation), lifecycleDispatcher{})
	if err != nil {
		t.Fatal(err)
	}
	c := packetConn.(*dispatcherConn)
	leg := root.NewLeg()
	leg.Route(fs.OutboundRef{Tag: "api"})
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
}

func TestInspectionDispatcherAPIBurstQueue(t *testing.T) {
	for _, inspected := range []bool{false, true} {
		t.Run(fmt.Sprintf("inspection=%v", inspected), func(t *testing.T) {
			ctx := context.Background()
			var view fs.FlowInspection
			if inspected {
				manager, err := appstats.NewManager(ctx, &appstats.Config{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { manager.Close() })
				view, err = manager.EnableInspection(fs.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
				observation := &session.LogicalObservation{Exchange: root}
				observation.ReturnedLink.Store(true)
				ctx = session.ContextWithLogicalObservation(ctx, observation)
			}
			conn, err := DialDispatcher(ctx, lifecycleDispatcher{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			c := conn.(*dispatcherConn)
			callbackCtx := ctx
			if inspected {
				leg := c.root.NewLeg()
				leg.Route(fs.OutboundRef{Tag: "burst"})
				callbackCtx = session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{Exchange: leg})
			}
			// Verify FIFO and byte credit within the native resource budget.
			const burst = 16
			for i := 0; i < burst; i++ {
				payload := buf.New()
				payload.WriteByte(byte(i))
				c.callback(callbackCtx, &protocoludp.Packet{Payload: payload, Source: net.UDPDestination(net.LocalHostIP, net.Port(1000+i))})
			}
			if len(c.cache) != burst {
				t.Fatalf("burst retained %d/%d replies", len(c.cache), burst)
			}
			for i := 0; i < burst; i++ {
				payload := make([]byte, 1)
				n, addr, err := conn.ReadFrom(payload)
				if err != nil || n != 1 || payload[0] != byte(i) || addr.String() != fmt.Sprintf("127.0.0.1:%d", 1000+i) {
					t.Fatalf("reply %d: n=%d addr=%v payload=%v err=%v", i, n, addr, payload, err)
				}
			}
			// Capacity remains bounded; a full cache releases the excess buffer.
			for i := 0; i < cap(c.cache); i++ {
				c.callback(callbackCtx, &protocoludp.Packet{Payload: buf.FromBytes([]byte{1})})
			}
			excess := buf.New()
			excess.WriteByte(2)
			c.callback(callbackCtx, &protocoludp.Packet{Payload: excess})
			if !excess.IsEmpty() || len(c.cache) != cap(c.cache) {
				t.Fatal("overflow was retained")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if inspected {
				totals, err := view.ReadTotals()
				if err != nil {
					t.Fatal(err)
				}
				var down uint64
				for _, row := range totals.Rows {
					down += row.Downlink
				}
				if down != burst {
					t.Fatalf("delivered bytes %d; queued/overflow bytes must stay uncredited", down)
				}
			}
		})
	}
}

func TestInspectionDispatcherAPIReadCloseSamePacket(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
	rootObservation := &session.LogicalObservation{Exchange: root, InputAtExecution: true}
	rootObservation.ReturnedLink.Store(true)
	packetConn, err := DialDispatcher(session.ContextWithLogicalObservation(context.Background(), rootObservation), lifecycleDispatcher{})
	if err != nil {
		t.Fatal(err)
	}
	c := packetConn.(*dispatcherConn)
	leg := root.NewLeg()
	leg.Route(fs.OutboundRef{Tag: "api"})
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
	if !payload.IsEmpty() {
		t.Fatal("joined read/close retained packet payload")
	}
	totals, err := view.ReadTotals()
	if err != nil || totals.User.Downlink != uint64(read.n) || len(totals.Rows) != 1 || totals.Rows[0].Outbound.Tag != "api" || totals.Rows[0].Downlink != uint64(read.n) {
		t.Fatalf("persistent read/close byte totals: %+v %v read=%d", totals, err, read.n)
	}
}

func TestInspectionDispatcherAPIUnclaimedEndReconcilesBeforeEOF(t *testing.T) {
	manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
	view, _ := manager.EnableInspection(fs.ObservationOptions{})
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginInternal, net.Destination{}, net.Destination{}, nil)
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

	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Ref != root.Ref() || live.Rows[0].Outbound.Tag != "" || live.Rows[0].Destination != destination || live.Rows[0].Uplink != 0 || live.Rows[0].Downlink != 0 {
		c.dispatcher.Unlock()
		t.Fatalf("unclaimed root before reconciliation: %+v %v", live, err)
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
	if live, err := view.ReadLiveInto(nil); err != nil || len(live.Rows) != 0 {
		t.Fatalf("joined unclaimed API root remained live: %+v %v", live, err)
	}
}
