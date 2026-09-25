package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

func TestInspectionUDPStaleClosePreservesReplacement(t *testing.T) {
	created := make(chan *udpConn, 2)
	u := newUdpConnectionHandler(func(c net.Conn, _ net.Destination) { created <- c.(*udpConn) }, func([]byte, net.Destination, net.Destination) error { return nil })
	src := net.UDPDestination(net.LocalHostIP, 1234)
	dst := net.UDPDestination(net.LocalHostIP, 53)
	u.HandlePacket(src, dst, []byte("old"))
	old := <-created
	old.Close()
	u.HandlePacket(src, dst, []byte("replacement"))
	next := <-created
	defer next.Close()
	old.Close()
	u.RLock()
	current := u.udpConns[src]
	u.RUnlock()
	if current != next {
		t.Fatal("stale close removed the replacement association")
	}
}

func TestInspectionUDPScalarWritePreservesError(t *testing.T) {
	want := io.ErrUnexpectedEOF
	u := newUdpConnectionHandler(nil, func([]byte, net.Destination, net.Destination) error { return want })
	c := &udpConn{handler: u}
	n, err := c.Write([]byte("payload"))
	if n != 0 || !errors.Is(err, want) {
		t.Fatalf("native result hidden: %d %v", n, err)
	}
}

func TestInspectionUDPLargePacketAndDestination(t *testing.T) {
	destination := net.UDPDestination(net.LocalHostIP, 5353)
	payload := bytes.Repeat([]byte{0x5a}, buf.Size+73)
	queue := make(chan *packet, 1)
	queue <- &packet{data: payload, dest: &destination}
	close(queue)
	c := &udpConn{egress: queue}
	mb, err := c.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || *mb[0].UDP != destination {
		t.Fatalf("packet lost or changed: %v %v", mb, err)
	}
}

func TestInspectionUDPPrefixAndPendingWrite(t *testing.T) {
	t.Run("native", func(t *testing.T) { testInspectionUDPPrefixAndPendingWrite(t, false) })
	t.Run("counter", func(t *testing.T) { testInspectionUDPPrefixAndPendingWrite(t, true) })
}

func testInspectionUDPPrefixAndPendingWrite(t *testing.T, withCounter bool) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	entered, release := make(chan struct{}), make(chan struct{})
	dst := net.UDPDestination(net.LocalHostIP, 53)
	alternate := net.UDPDestination(net.LocalHostIP, 5353)
	calls := 0
	write := func(payload []byte, from, to net.Destination) error {
		calls++
		if calls == 1 && from != dst {
			t.Errorf("default destination: %v", from)
		}
		if calls == 2 {
			if from != alternate {
				t.Errorf("packet destination: %v", from)
			}
			close(entered)
			<-release
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	c := &udpConn{handler: newUdpConnectionHandler(nil, write), dst: dst}
	var writer buf.Writer = c
	counter := new(testCounter)
	if withCounter {
		writer = &tunUDPStatsWriter{writer: writer, counter: counter}
	}
	writer = buf.AttachWriterReceipt(writer, flow)
	done := make(chan error, 1)
	first, second, tail := buf.FromBytes([]byte("ok")), buf.FromBytes([]byte("fail")), buf.FromBytes([]byte("tail"))
	second.UDP = &alternate
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{first, second, tail, buf.FromBytes(nil)}) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("native write did not start")
	}
	flow.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 2 || page.Rows[0].Flow.Downlink.Incomplete {
		t.Errorf("owner-end write snapshot: %+v %v", page, err)
	}
	close(release)
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	page, err = view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	if withCounter && counter.Value() != 2 {
		t.Fatalf("counter: %d", counter.Value())
	}
	fact := page.Rows[0].Flow.Downlink
	if calls != 2 || fact.Known != 2 || fact.Incomplete {
		t.Fatalf("native partial result: calls=%d fact=%+v", calls, fact)
	}
	totals, _ := view.ReadTotals(context.Background())
	var incomplete bool
	for _, row := range totals.Rows {
		incomplete = incomplete || row.Downlink.Incomplete
	}
	if !incomplete {
		t.Fatalf("late error missing from totals: %+v", totals)
	}
}

type inspectionDispatcher struct {
	testDispatcher
	entered chan context.Context
	wait    bool
}

func (d *inspectionDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if observation := session.LogicalObservationFromContext(ctx); observation != nil {
		observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
		proxy.ClaimObservedEndpoint(ctx, link.Reader, true)
	}
	if d.entered != nil {
		d.entered <- ctx
	}
	if d.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return d.testDispatcher.DispatchLink(ctx, dest, link)
}

func TestInspectionTUNHandlerEnabledAndDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			manager := new(appstats.Manager)
			defer manager.Close()
			var view fs.FlowInspection
			if enabled {
				var err error
				view, err = manager.EnableInspection(fs.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}
			up, down := new(testCounter), new(testCounter)
			dispatcher := &inspectionDispatcher{testDispatcher: testDispatcher{writePayload: []byte("downlink")}}
			handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher, statsManager: manager, uplinkCounter: up, downlinkCounter: down}
			destination := net.TCPDestination(net.LocalHostIP, 443)
			var conn net.Conn = newTestConn([]byte("uplink"))
			var reply string
			if udp {
				destination.Network = net.Network_UDP
				queue := make(chan *packet, 1)
				queue <- &packet{data: []byte("uplink"), dest: &destination}
				native := newUdpConnectionHandler(nil, func(p []byte, _, _ net.Destination) error { reply = string(p); return nil })
				uc := &udpConn{handler: native, src: net.UDPDestination(net.LocalHostIP, 1234), dst: destination, egress: queue}
				native.udpConns[uc.src] = uc
				conn = uc
			}
			handler.HandleConnection(conn, destination)
			if up.Value() != 6 || down.Value() != 8 {
				t.Fatalf("native counters enabled=%t udp=%t: %d/%d", enabled, udp, up.Value(), down.Value())
			}
			if udp && reply != "downlink" {
				t.Fatal(reply)
			}
			if enabled {
				page, err := view.ReadTerminals(context.Background())
				if err != nil || len(page.Rows) != 1 {
					t.Fatalf("terminal: %+v %v", page, err)
				}
				f := page.Rows[0].Flow
				if f.Origin != fs.TrafficOriginUser || f.Uplink.Known != 6 || f.Downlink.Known != 8 || f.AccountingRoute.Outbound.Tag != "direct" {
					t.Fatalf("endpoint: %+v", f)
				}
			}
		}
	}
}

func TestInspectionTUNStopKeepsSiblingAssociation(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	dispatcher := &inspectionDispatcher{entered: make(chan context.Context, 2), wait: true}
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher, statsManager: manager}
	finished := make(chan struct{}, 2)
	native := newUdpConnectionHandler(func(c net.Conn, d net.Destination) { handler.HandleConnection(c, d); finished <- struct{}{} }, func([]byte, net.Destination, net.Destination) error { return nil })
	destination := net.UDPDestination(net.LocalHostIP, 53)
	first, second := net.UDPDestination(net.LocalHostIP, 1234), net.UDPDestination(net.LocalHostIP, 1235)
	native.HandlePacket(first, destination, []byte("first"))
	ctx1 := <-dispatcher.entered
	native.HandlePacket(second, destination, []byte("second"))
	ctx2 := <-dispatcher.entered
	ref1 := session.LogicalObservationFromContext(ctx1).Exchange.Ref()
	ref2 := session.LogicalObservationFromContext(ctx2).Exchange.Ref()
	defer view.CloseFlows(context.Background(), []fs.FlowRef{ref2})
	if _, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stopped association remained alive")
	}
	native.RLock()
	_, old := native.udpConns[first]
	sibling := native.udpConns[second]
	native.RUnlock()
	if old || sibling == nil || ctx2.Err() != nil {
		t.Fatal("exact stop affected sibling")
	}
	native.HandlePacket(second, destination, []byte("still alive"))
	for _, want := range []string{"second", "still alive"} {
		mb, err := sibling.ReadMultiBuffer()
		got := mb.String()
		buf.ReleaseMulti(mb)
		if err != nil || got != want {
			t.Fatalf("sibling: %q %v", got, err)
		}
	}
	view.CloseFlows(context.Background(), []fs.FlowRef{ref2})
	<-finished
}

func TestInspectionTUNCounterStopBetweenBatchAndPacket(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, func() error { return nil })
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	c := &udpConn{handler: newUdpConnectionHandler(nil, func([]byte, net.Destination, net.Destination) error {
		calls++
		if calls == 2 {
			close(entered)
			<-release
		}
		return nil
	})}
	counter := new(testCounter)
	writer := buf.AttachWriterReceipt(&tunUDPStatsWriter{writer: c, counter: counter}, flow)
	done := make(chan error, 1)
	go func() {
		done <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("head")), buf.FromBytes([]byte("tail")), buf.FromBytes(nil)})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("packet entry did not reach stop boundary")
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		close(release)
		t.Fatalf("stop: %+v %v", outcomes, err)
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != uint64(len("head")) {
		t.Errorf("owner-end batch snapshot: %+v %v", page, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	page, err = view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	fact := page.Rows[0].Flow.Downlink
	if calls != 3 || counter.Value() != int64(len("headtail")) || fact.Known != uint64(len("head")) || fact.Incomplete {
		t.Fatalf("late native batch: native=%d counter=%d fact=%+v", calls, counter.Value(), fact)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, row := range totals.Rows {
		known += row.Downlink.Known
	}
	if known != uint64(len("headtail")) {
		t.Fatalf("late packet totals: %+v", totals)
	}
}
