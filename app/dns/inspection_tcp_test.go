package dns

import (
	"context"
	"io"
	stdnet "net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

type dnsTCPTestExchange struct {
	uplink             atomic.Uint64
	downlink           atomic.Uint64
	uplinkIncomplete   atomic.Bool
	downlinkIncomplete atomic.Bool
	finished           atomic.Uint32
	reason             atomic.Uint32
}

func (*dnsTCPTestExchange) Ref() stats.FlowRef                          { return stats.FlowRef{} }
func (*dnsTCPTestExchange) ExcludeCarrier() bool                        { return true }
func (*dnsTCPTestExchange) Rebind(stats.RuntimeID, stats.TrafficOrigin) {}
func (*dnsTCPTestExchange) NewLeg() stats.Exchange                      { return nil }
func (*dnsTCPTestExchange) Route(stats.RouteStep)                       {}
func (*dnsTCPTestExchange) BindRoute()                                  {}
func (*dnsTCPTestExchange) Unassign()                                   {}
func (*dnsTCPTestExchange) Effective(net.Destination)                   {}
func (*dnsTCPTestExchange) SetSource(net.Destination)                   {}
func (*dnsTCPTestExchange) PacketDestination(net.Destination)           {}
func (e *dnsTCPTestExchange) AddUplink(n uint64)                        { e.uplink.Add(n) }
func (e *dnsTCPTestExchange) AddDownlink(n uint64)                      { e.downlink.Add(n) }
func (e *dnsTCPTestExchange) MarkUplinkIncomplete()                     { e.uplinkIncomplete.Store(true) }

func (e *dnsTCPTestExchange) MarkDownlinkIncomplete() { e.downlinkIncomplete.Store(true) }

func (e *dnsTCPTestExchange) SetEndReason(reason stats.EndReason) { e.reason.Store(uint32(reason)) }
func (e *dnsTCPTestExchange) Finish()                             { e.finished.Add(1) }

type dnsTCPCloseCountingConn struct {
	closed atomic.Uint32
}

func (*dnsTCPCloseCountingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*dnsTCPCloseCountingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *dnsTCPCloseCountingConn) Close() error                   { c.closed.Add(1); return nil }
func (*dnsTCPCloseCountingConn) LocalAddr() stdnet.Addr           { return &stdnet.TCPAddr{} }
func (*dnsTCPCloseCountingConn) RemoteAddr() stdnet.Addr          { return &stdnet.TCPAddr{} }
func (*dnsTCPCloseCountingConn) SetDeadline(time.Time) error      { return nil }
func (*dnsTCPCloseCountingConn) SetReadDeadline(time.Time) error  { return nil }
func (*dnsTCPCloseCountingConn) SetWriteDeadline(time.Time) error { return nil }

type dnsTCPTrackingReader struct{ interrupted atomic.Uint32 }

func (*dnsTCPTrackingReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }
func (r *dnsTCPTrackingReader) Interrupt()                              { r.interrupted.Add(1) }

type dnsTCPTrackingWriter struct{ closed atomic.Uint32 }

func (*dnsTCPTrackingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}
func (w *dnsTCPTrackingWriter) Close() error { w.closed.Add(1); return nil }

type dnsTCPBlockingDispatcher struct {
	started  chan struct{}
	returned chan struct{}
	reader   *dnsTCPTrackingReader
	writer   *dnsTCPTrackingWriter
}

func (*dnsTCPBlockingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dnsTCPBlockingDispatcher) Start() error      { return nil }
func (*dnsTCPBlockingDispatcher) Close() error      { return nil }
func (d *dnsTCPBlockingDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	observation := session.LogicalObservationFromContext(ctx)
	if observation == nil || observation.Exchange == nil || session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal {
		return nil, io.ErrUnexpectedEOF
	}
	observation.Exchange.Route(stats.RouteStep{
		Selection:      stats.SelectionDefault,
		Original:       destination,
		SelectedTarget: destination,
	})
	observation.Exchange.BindRoute()
	close(d.started)
	<-ctx.Done()
	close(d.returned)
	return &transport.Link{Reader: d.reader, Writer: d.writer}, nil
}

func (*dnsTCPBlockingDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return io.ErrClosedPipe
}

func TestDNSTCPExchangeFramingAndPartialResponse(t *testing.T) {
	root := new(dnsTCPTestExchange)
	exchange := newDNSTCPExchange(root, 5)

	// The prefix is split across calls, the body straddles the second call and
	// bytes after the declared DNS body are never credited.
	exchange.AddUplink(1)
	exchange.AddUplink(3)
	exchange.AddUplink(32)
	exchange.AddUplink(5) // replay/overflow after the body is already complete
	exchange.finishUplink()
	if got := root.uplink.Load(); got != 5 {
		t.Fatalf("decoded uplink: got %d want 5", got)
	}
	if root.uplinkIncomplete.Load() {
		t.Fatal("complete framed query marked incomplete")
	}

	owner := &dnsTCPQueryOwner{exchange: exchange}
	owner.recordResponseRead(3, 7, io.ErrUnexpectedEOF)
	if got := root.downlink.Load(); got != 3 {
		t.Fatalf("partial decoded downlink: got %d want 3", got)
	}
	if !root.downlinkIncomplete.Load() || stats.EndReason(root.reason.Load()) != stats.EndReasonReadError {
		t.Fatalf("partial response facts: incomplete=%v reason=%v", root.downlinkIncomplete.Load(), root.reason.Load())
	}
}

func TestDNSTCPObservationDisabledAndLocalUnchanged(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&appstats.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	inherited := &session.LogicalObservation{Exchange: new(dnsTCPTestExchange)}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithLogicalObservation(ctx, inherited)
	destination := net.TCPDestination(net.LocalHostIP, 53)
	observed, owner := beginRoutedDNSTCPObservation(ctx, destination, 12)
	if owner != nil {
		t.Fatal("disabled observation created a DNS TCP owner")
	}
	if got := session.LogicalObservationFromContext(observed); got != nil {
		t.Fatalf("inherited observation retained: %p", got)
	}

	endpoint, err := url.Parse("tcp+local://127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewTCPLocalNameServer(endpoint, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if local.routed {
		t.Fatal("tcp+local entered routed observation path")
	}
}

func TestRoutedDNSTCPCloseCancelsDispatchBeforeLateAttach(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	dispatcher := &dnsTCPBlockingDispatcher{
		started:  make(chan struct{}),
		returned: make(chan struct{}),
		reader:   new(dnsTCPTrackingReader),
		writer:   new(dnsTCPTrackingWriter),
	}
	endpoint, err := url.Parse("tcp://192.0.2.80:53")
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewTCPNameServer(endpoint, dispatcher, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	type lookupResult struct{ err error }
	result := make(chan lookupResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
		defer cancel()
		_, _, lookupErr := resolver.QueryIP(ctx, "blocked.routed.example", dnsfeature.IPOption{IPv4Enable: true})
		result <- lookupResult{err: lookupErr}
	}()
	select {
	case <-dispatcher.started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocking dispatcher was not entered")
	}

	var ref stats.FlowRef
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		if readErr == nil && len(live.Rows) == 1 {
			ref = live.Rows[0].Ref
		}
		return len(live.Rows), readErr
	}, 1)
	outcomes, err := view.CloseFlows(context.Background(), []stats.FlowRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Code != stats.CloseCodeAccepted {
		t.Fatalf("close outcome: %+v", outcomes)
	}
	select {
	case <-dispatcher.returned:
	case <-time.After(time.Second):
		t.Fatal("request-local cancellation did not unblock Dispatch")
	}
	select {
	case got := <-result:
		if got.err == nil {
			t.Fatal("stopped routed DNS lookup unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stopped routed DNS lookup did not return")
	}
	if got := dispatcher.reader.interrupted.Load(); got != 1 {
		t.Fatalf("late reader interrupt count: got %d want 1", got)
	}
	if got := dispatcher.writer.closed.Load(); got != 1 {
		t.Fatalf("late writer close count: got %d want 1", got)
	}
	terminals, err := view.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(terminals.Rows) != 1 || terminals.Rows[0].Reason != stats.EndReasonLocalStop || !terminals.Rows[0].Flow.Uplink.Incomplete {
		t.Fatalf("stopped dispatch terminal: %+v", terminals.Rows)
	}
}

func TestDNSTCPQueryOwnerAttachCloseRaceAndSibling(t *testing.T) {
	for i := 0; i < 64; i++ {
		root := new(dnsTCPTestExchange)
		owner := &dnsTCPQueryOwner{exchange: newDNSTCPExchange(root, 4)}
		conn := new(dnsTCPCloseCountingConn)
		siblingRoot := new(dnsTCPTestExchange)
		sibling := &dnsTCPQueryOwner{exchange: newDNSTCPExchange(siblingRoot, 1)}
		siblingConn := new(dnsTCPCloseCountingConn)
		if err := sibling.attach(siblingConn); err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = owner.attach(conn)
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = owner.Close()
		}()
		close(start)
		wg.Wait()
		owner.finish()
		owner.finish()

		if got := conn.closed.Load(); got != 1 {
			t.Fatalf("iteration %d owner close count: got %d want 1", i, got)
		}
		if got := siblingConn.closed.Load(); got != 0 {
			t.Fatalf("iteration %d sibling was closed: %d", i, got)
		}
		if !root.uplinkIncomplete.Load() || root.finished.Load() != 1 {
			t.Fatalf("iteration %d owner finish: incomplete=%v finish=%d", i, root.uplinkIncomplete.Load(), root.finished.Load())
		}
		sibling.finish()
	}
}

func newDNSTCPInspectionCore(t *testing.T) (*core.Instance, stats.FlowInspection, routing.Dispatcher) {
	t.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           "direct",
			ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	view, err := core.EnableFlowInspection(instance, stats.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, view, instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
}

func dnsTCPTestContext(instance *core.Instance) context.Context {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	return session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{Exchange: new(dnsTCPTestExchange)})
}

func waitDNSTCPRows(t *testing.T, read func() (int, error), want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := read()
		if err != nil {
			t.Fatal(err)
		}
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, err := read()
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("rows: got %d want %d", got, want)
}

func TestRoutedDNSTCPObservationSuccess(t *testing.T) {
	type messageSizes struct{ query, response uint64 }
	sizes := make(chan messageSizes, 1)
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			response := new(mdns.Msg)
			response.SetReply(request)
			answer, answerErr := mdns.NewRR("routed.example. 60 IN A 192.0.2.53")
			if answerErr != nil {
				t.Errorf("answer: %v", answerErr)
				return
			}
			response.Answer = append(response.Answer, answer)
			queryWire, queryErr := request.Pack()
			responseWire, responseErr := response.Pack()
			if queryErr != nil || responseErr != nil {
				t.Errorf("pack request=%v response=%v", queryErr, responseErr)
				return
			}
			sizes <- messageSizes{query: uint64(len(queryWire)), response: uint64(len(responseWire))}
			if writeErr := w.WriteMsg(response); writeErr != nil {
				t.Errorf("write response: %v", writeErr)
			}
		}),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("DNS test server did not stop")
		}
	})

	instance, view, routedDispatcher := newDNSTCPInspectionCore(t)
	endpoint, err := url.Parse("tcp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewTCPNameServer(endpoint, routedDispatcher, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dnsTCPTestContext(instance)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, _, err := resolver.QueryIP(ctx, "routed.example", dnsfeature.IPOption{IPv4Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.53" {
		t.Fatalf("response IPs: %v", ips)
	}

	wantSizes := <-sizes
	var terminals stats.TerminalSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		terminals, err = view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(terminals.Rows) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(terminals.Rows) != 1 {
		t.Fatalf("terminal rows: %d", len(terminals.Rows))
	}
	row := terminals.Rows[0]
	if row.Flow.Origin != stats.TrafficOriginInternal || row.Flow.Kind != stats.FlowKindTCP || row.Flow.InitialDestination.String() != "tcp:"+listener.Addr().String() {
		t.Fatalf("routed DNS identity: %+v", row.Flow)
	}
	if len(row.Flow.Routes) != 1 || row.Flow.AccountingRoute.Outbound.Tag != "direct" {
		t.Fatalf("routed DNS route: %+v", row.Flow)
	}
	if row.Flow.Uplink.Known != wantSizes.query || row.Flow.Downlink.Known != wantSizes.response || row.Flow.Uplink.Incomplete || row.Flow.Downlink.Incomplete {
		t.Fatalf("routed DNS bytes: uplink=%+v downlink=%+v want=%+v", row.Flow.Uplink, row.Flow.Downlink, wantSizes)
	}
	if row.Reason != stats.EndReasonUnknown {
		t.Fatalf("successful routed DNS end reason: got %v want unknown", row.Reason)
	}
}

func TestRoutedDNSTCPExactStopKeepsSibling(t *testing.T) {
	firstStarted := make(chan struct{}, 1)
	secondStarted := make(chan struct{}, 1)
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	var releaseFirstOnce sync.Once
	var releaseSecondOnce sync.Once
	releaseFirst := func() { releaseFirstOnce.Do(func() { close(firstRelease) }) }
	releaseSecond := func() { releaseSecondOnce.Do(func() { close(secondRelease) }) }
	defer releaseFirst()
	defer releaseSecond()

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			if len(request.Question) != 1 {
				return
			}
			name := request.Question[0].Name
			var started chan<- struct{}
			var release <-chan struct{}
			address := "192.0.2.61"
			switch name {
			case "first.routed.example.":
				started, release = firstStarted, firstRelease
			case "second.routed.example.":
				started, release = secondStarted, secondRelease
				address = "192.0.2.62"
			default:
				return
			}
			started <- struct{}{}
			<-release
			response := new(mdns.Msg)
			response.SetReply(request)
			answer, answerErr := mdns.NewRR(name + " 60 IN A " + address)
			if answerErr != nil {
				return
			}
			response.Answer = append(response.Answer, answer)
			_ = w.WriteMsg(response)
		}),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		releaseFirst()
		releaseSecond()
		_ = server.Shutdown()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("DNS test server did not stop")
		}
	})

	instance, view, routedDispatcher := newDNSTCPInspectionCore(t)
	endpoint, err := url.Parse("tcp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewTCPNameServer(endpoint, routedDispatcher, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	type lookupResult struct {
		ips []net.IP
		err error
	}
	lookup := func(name string) <-chan lookupResult {
		result := make(chan lookupResult, 1)
		go func() {
			ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
			defer cancel()
			ips, _, lookupErr := resolver.QueryIP(ctx, name, dnsfeature.IPOption{IPv4Enable: true})
			result <- lookupResult{ips: ips, err: lookupErr}
		}()
		return result
	}

	firstResult := lookup("first.routed.example")
	select {
	case <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first routed DNS request did not arrive")
	}
	var firstRef stats.FlowRef
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		if readErr == nil && len(live.Rows) == 1 {
			firstRef = live.Rows[0].Ref
		}
		return len(live.Rows), readErr
	}, 1)

	secondResult := lookup("second.routed.example")
	select {
	case <-secondStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("second routed DNS request did not arrive")
	}
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		return len(live.Rows), readErr
	}, 2)

	outcomes, err := view.CloseFlows(context.Background(), []stats.FlowRef{firstRef})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Code != stats.CloseCodeAccepted {
		t.Fatalf("close outcome: %+v", outcomes)
	}
	select {
	case result := <-firstResult:
		if result.err == nil {
			t.Fatalf("stopped request unexpectedly succeeded: %v", result.ips)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stopped request did not return")
	}

	releaseSecond()
	select {
	case result := <-secondResult:
		if result.err != nil || len(result.ips) != 1 || result.ips[0].String() != "192.0.2.62" {
			t.Fatalf("sibling result: ips=%v err=%v", result.ips, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sibling request did not return")
	}
	releaseFirst()

	waitDNSTCPRows(t, func() (int, error) {
		terminals, readErr := view.ReadTerminals(context.Background())
		return len(terminals.Rows), readErr
	}, 2)
	terminals, err := view.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range terminals.Rows {
		if row.Flow.Ref == firstRef {
			// CloseFlows publishes the owner snapshot after exact close. The
			// unblocked read may report its uncertainty later to the aggregate.
			if row.Reason != stats.EndReasonLocalStop {
				t.Fatalf("stopped terminal: %+v", row)
			}
			totals, totalsErr := view.ReadTotals(context.Background())
			if totalsErr != nil {
				t.Fatal(totalsErr)
			}
			for _, total := range totals.Rows {
				if total.Outbound.Tag == "direct" && total.Origin == stats.TrafficOriginInternal {
					if !total.Downlink.Incomplete {
						t.Fatalf("late stopped-read aggregate: %+v", total)
					}
					return
				}
			}
			t.Fatalf("routed INTERNAL aggregate not found: %+v", totals.Rows)
		}
	}
	t.Fatal("stopped terminal not found")
}
