package dns

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsUDPNoopDispatcher struct{}

func (dnsUDPNoopDispatcher) Type() interface{} { return routing.DispatcherType() }
func (dnsUDPNoopDispatcher) Start() error      { return nil }
func (dnsUDPNoopDispatcher) Close() error      { return nil }
func (dnsUDPNoopDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, io.ErrClosedPipe
}

func (dnsUDPNoopDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return io.ErrClosedPipe
}

type dnsUDPBlockingDispatcher struct {
	started  chan struct{}
	returned chan struct{}
	reader   *dnsTCPTrackingReader
	writer   *dnsTCPTrackingWriter
}

func (*dnsUDPBlockingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dnsUDPBlockingDispatcher) Start() error      { return nil }
func (*dnsUDPBlockingDispatcher) Close() error      { return nil }
func (d *dnsUDPBlockingDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	observation := session.LogicalObservationFromContext(ctx)
	if observation == nil || observation.Exchange == nil || session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal {
		return nil, io.ErrUnexpectedEOF
	}
	observation.Exchange.Route(featurestats.RouteStep{
		Selection:      featurestats.SelectionDefault,
		Original:       destination,
		SelectedTarget: destination,
	})
	observation.Exchange.BindRoute()
	close(d.started)
	<-ctx.Done()
	close(d.returned)
	return &transport.Link{Reader: d.reader, Writer: d.writer}, nil
}

func (*dnsUDPBlockingDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return io.ErrClosedPipe
}

type dnsUDPBlackholeReader struct {
	done        chan struct{}
	interrupt   sync.Once
	interrupted atomic.Uint32
}

func (r *dnsUDPBlackholeReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.done
	return nil, io.EOF
}

func (r *dnsUDPBlackholeReader) Interrupt() {
	r.interrupt.Do(func() {
		r.interrupted.Add(1)
		close(r.done)
	})
}

type dnsUDPBlackholeDispatcher struct {
	reader *dnsUDPBlackholeReader
	writer *dnsTCPTrackingWriter
}

func (*dnsUDPBlackholeDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dnsUDPBlackholeDispatcher) Start() error      { return nil }
func (*dnsUDPBlackholeDispatcher) Close() error      { return nil }
func (d *dnsUDPBlackholeDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	observation := session.LogicalObservationFromContext(ctx)
	if observation == nil || observation.Exchange == nil {
		return nil, io.ErrUnexpectedEOF
	}
	observation.Exchange.Route(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Original: destination, SelectedTarget: destination})
	observation.Exchange.BindRoute()
	return &transport.Link{Reader: d.reader, Writer: d.writer}, nil
}

func (*dnsUDPBlackholeDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return io.ErrClosedPipe
}

func routedDNSUDPResponse(t *testing.T, id uint16) *udp_proto.Packet {
	t.Helper()
	message := new(mdns.Msg)
	message.Id = id
	message.Response = true
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &udp_proto.Packet{Payload: buf.FromBytes(wire)}
}

func TestRoutedDNSUDPObservationDisabledKeepsSharedDispatcher(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&stats.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
	shared := server.udpServer
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	observed, owner := beginRoutedDNSUDPObservation(ctx, ctx, server, *server.address, 1, nil)
	if owner != nil {
		t.Fatal("disabled inspection created a routed UDP owner")
	}
	if server.udpServer != shared {
		t.Fatal("disabled inspection replaced the shared UDP dispatcher")
	}
	if inherited := session.LogicalObservationFromContext(observed); inherited != nil {
		t.Fatal("disabled routed query retained an inherited observation")
	}
}

func TestRoutedDNSUDPCloseCancelsBlockedDispatchAndWakesAAAA(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	dispatcher := &dnsUDPBlockingDispatcher{
		started:  make(chan struct{}),
		returned: make(chan struct{}),
		reader:   new(dnsTCPTrackingReader),
		writer:   new(dnsTCPTrackingWriter),
	}
	resolver := NewClassicNameServer(net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 80}), 53), dispatcher, true, false, 0, nil)
	type lookupResult struct{ err error }
	result := make(chan lookupResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
		defer cancel()
		_, _, lookupErr := resolver.QueryIP(ctx, "blocked-udp.routed.example", dnsfeature.IPOption{IPv4Enable: true, IPv6Enable: true})
		result <- lookupResult{err: lookupErr}
	}()
	select {
	case <-dispatcher.started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocking UDP dispatcher was not entered")
	}

	var ref featurestats.FlowRef
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		if readErr == nil && len(live.Rows) == 1 {
			ref = live.Rows[0].Ref
		}
		return len(live.Rows), readErr
	}, 1)
	outcomes, err := view.CloseFlows(context.Background(), []featurestats.FlowRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Code != featurestats.CloseCodeAccepted {
		t.Fatalf("close outcome: %+v", outcomes)
	}
	select {
	case <-dispatcher.returned:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not unblock UDP Dispatch")
	}
	select {
	case got := <-result:
		if got.err == nil {
			t.Fatal("stopped A+AAAA lookup unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stopped A+AAAA lookup was not woken")
	}
	deadline := time.Now().Add(time.Second)
	for (dispatcher.reader.interrupted.Load() == 0 || dispatcher.writer.closed.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dispatcher.reader.interrupted.Load() == 0 || dispatcher.writer.closed.Load() == 0 {
		t.Fatalf("late UDP link not cleaned: reader=%d writer=%d", dispatcher.reader.interrupted.Load(), dispatcher.writer.closed.Load())
	}
	terminals, err := view.ReadTerminals(context.Background())
	if err != nil || len(terminals.Rows) != 1 || terminals.Rows[0].Reason != featurestats.EndReasonLocalStop {
		t.Fatalf("stopped UDP terminal: %+v err=%v", terminals.Rows, err)
	}
}

func TestRoutedDNSUDPCallerTimeoutRetiresBlackholeResources(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	dispatcher := &dnsUDPBlackholeDispatcher{
		reader: &dnsUDPBlackholeReader{done: make(chan struct{})},
		writer: new(dnsTCPTrackingWriter),
	}
	resolver := NewClassicNameServer(net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 81}), 53), dispatcher, true, false, 0, nil)
	ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := resolver.QueryIP(ctx, "blackhole-udp.routed.example", dnsfeature.IPOption{IPv4Enable: true})
	if err == nil {
		t.Fatal("blackhole lookup unexpectedly succeeded")
	}
	if time.Since(started) > time.Second {
		t.Fatal("blackhole lookup waited for periodic request cleanup")
	}
	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 1)
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("blackhole query retained live resources: %+v err=%v", live.Rows, err)
	}
	deadline := time.Now().Add(time.Second)
	for (dispatcher.reader.interrupted.Load() == 0 || dispatcher.writer.closed.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dispatcher.reader.interrupted.Load() == 0 || dispatcher.writer.closed.Load() == 0 {
		t.Fatalf("blackhole resources not retired: reader=%d writer=%d", dispatcher.reader.interrupted.Load(), dispatcher.writer.closed.Load())
	}
}

func TestRoutedDNSUDPForcedIDCollisionRetiresDisplacedOwner(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
	caller := dnsTCPTestContext(instance)
	routed := toDnsContext(caller, server.address.String())
	firstErrors := make(chan error, 1)
	_, first := beginRoutedDNSUDPObservation(routed, caller, server, *server.address, 1, firstErrors)
	_, second := beginRoutedDNSUDPObservation(routed, caller, server, *server.address, 1, make(chan error, 1))
	if first == nil || second == nil {
		t.Fatal("failed to create collision owners")
	}
	const id = uint16(65535)
	firstReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: id}}}, owner: first}
	secondReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: id}}}, owner: second}
	if !server.addPendingRequest(firstReq) || !server.addPendingRequest(secondReq) {
		t.Fatal("failed to force request ID collision")
	}
	server.RLock()
	firstRemaining := len(first.requests)
	secondMapped := second.requests[id]
	serverMapped := server.requests[id]
	server.RUnlock()
	if firstRemaining != 0 || secondMapped != secondReq || serverMapped != secondReq {
		t.Fatalf("collision maps: first=%d second=%p server=%p", firstRemaining, secondMapped, serverMapped)
	}
	select {
	case err := <-firstErrors:
		if !errors.Is(err, errDNSUDPRequestIDCollision) {
			t.Fatalf("collision wake error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("displaced owner was not woken")
	}
	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 1)
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("collision terminal/loss: %+v err=%v", page.Rows, err)
	}
	second.finishCanceled()
}

func TestRoutedDNSUDPPartialLossPrecedesFinalResponseTerminal(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
	caller := dnsTCPTestContext(instance)
	routed := toDnsContext(caller, server.address.String())
	_, owner := beginRoutedDNSUDPObservation(routed, caller, server, *server.address, 2, make(chan error, 2))
	if owner == nil {
		t.Fatal("failed to create partial-loss owner")
	}
	leg := owner.exchange.NewLeg()
	if leg == nil {
		t.Fatal("failed to create selected DNS UDP leg")
	}
	leg.Route(featurestats.RouteStep{
		Selection: featurestats.SelectionDefault,
		Outbound: featurestats.OutboundRef{
			Runtime: view.Info().Runtime,
			Serial:  91,
			Tag:     "partial-loss",
		},
	})
	leg.BindRoute()
	responseCtx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: leg})

	const firstID, secondID = uint16(101), uint16(102)
	firstReq := &udpDnsRequest{dnsRequest: dnsRequest{reqType: dnsmessage.TypeA, domain: "partial.example.", start: time.Now(), msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: firstID}}}, owner: owner}
	secondReq := &udpDnsRequest{dnsRequest: dnsRequest{reqType: dnsmessage.TypeAAAA, domain: "partial.example.", start: time.Now(), msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: secondID}}}, owner: owner}
	if !server.addPendingRequest(firstReq) || !server.addPendingRequest(secondReq) {
		t.Fatal("failed to register partial-loss requests")
	}

	// Retire A under the nameserver lock, then deliberately delay its outside-
	// lock notification until after B delivers the final matched response.
	server.Lock()
	delete(server.requests, firstID)
	lost := server.retireObservedRequestLocked(firstReq, true)
	server.Unlock()
	if lost.owner != owner || lost.done {
		t.Fatalf("first retirement: %+v", lost)
	}
	packet := routedDNSUDPResponse(t, secondID)
	wantDownlink := uint64(packet.Payload.Len())
	server.handleResponse(responseCtx, packet, owner)
	lost.owner.requestLost(errDNSUDPRequestIDCollision, lost.done)

	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 1)
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || !page.Rows[0].Flow.Downlink.Incomplete || page.Rows[0].Flow.Downlink.Known != wantDownlink {
		t.Fatalf("partial-loss terminal: %+v err=%v", page.Rows, err)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, total := range totals.Rows {
		if total.Outbound.Tag == "partial-loss" && total.Origin == featurestats.TrafficOriginInternal {
			if !total.Downlink.Incomplete || total.Downlink.Known != wantDownlink {
				t.Fatalf("partial-loss selected totals: %+v", total)
			}
			return
		}
	}
	t.Fatalf("partial-loss selected total missing: %+v", totals.Rows)
}

func TestRoutedDNSUDPCapacityFallsBackWithoutPrivateRay(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&stats.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	view, err := core.EnableFlowInspection(instance, featurestats.ObservationOptions{MaxLive: 1})
	if err != nil {
		t.Fatal(err)
	}
	provider := instance.GetFeature(featurestats.ManagerType()).(featurestats.ObservationProvider)
	retained := provider.Observation().Begin(featurestats.FlowKindUDPAssociation, featurestats.TrafficOriginInternal, net.Destination{}, net.UDPDestination(net.LocalHostIP, 53), nil)
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	routed := toDnsContext(ctx, server.address.String())
	_, owner := beginRoutedDNSUDPObservation(routed, ctx, server, *server.address, 1, make(chan error, 1))
	if owner != nil {
		t.Fatal("capacity overflow allocated a private UDP dispatcher owner")
	}
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 || live.Loss.UntrackedAdmissions != 1 {
		t.Fatalf("capacity fallback facts: %+v err=%v", live, err)
	}
	retained.Finish()
}

func TestRoutedDNSUDPStaleIDResponseCannotRetireReplacement(t *testing.T) {
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
	oldOwner := &dnsUDPQueryOwner{server: server, exchange: new(dnsTCPTestExchange), requests: make(map[uint16]*udpDnsRequest)}
	newOwner := &dnsUDPQueryOwner{server: server, exchange: new(dnsTCPTestExchange), requests: make(map[uint16]*udpDnsRequest)}
	const id = 41
	oldReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: id}}}, owner: oldOwner}
	newReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: id}}}, owner: newOwner}
	oldOwner.requests[id] = oldReq
	newOwner.requests[id] = newReq
	server.requests[id] = newReq

	packet := routedDNSUDPResponse(t, id)
	server.handleResponse(context.Background(), packet, oldOwner)
	if server.requests[id] != newReq || newOwner.requests[id] != newReq {
		t.Fatal("stale response retired the replacement request")
	}
	server.HandleResponse(context.Background(), routedDNSUDPResponse(t, id))
	if server.requests[id] != newReq || newOwner.requests[id] != newReq {
		t.Fatal("stale shared-dispatcher response retired the observed request")
	}
}

func TestRoutedDNSUDPExactStopKeepsSiblingAndFuture(t *testing.T) {
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
	newOwner := func() *dnsUDPQueryOwner {
		o := &dnsUDPQueryOwner{server: server, exchange: new(dnsTCPTestExchange), requests: make(map[uint16]*udpDnsRequest)}
		o.dispatcher = udp.NewDispatcher(dnsUDPNoopDispatcher{}, o.handleResponse)
		return o
	}
	first, sibling := newOwner(), newOwner()
	firstReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: 1}}}, owner: first}
	siblingReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: 2}}}, owner: sibling}
	if !server.addPendingRequest(firstReq) || !server.addPendingRequest(siblingReq) {
		t.Fatal("failed to register test requests")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if server.requests[1] != nil || server.requests[2] != siblingReq {
		t.Fatalf("exact stop changed sibling map: %+v", server.requests)
	}
	future := newOwner()
	futureReq := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: 3}}}, owner: future}
	if !server.addPendingRequest(futureReq) || server.requests[3] != futureReq {
		t.Fatal("stopped query poisoned future registration")
	}
	_ = sibling.Close()
	_ = future.Close()
}

func TestRoutedDNSUDPResponseStopRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
		owner := &dnsUDPQueryOwner{server: server, exchange: new(dnsTCPTestExchange), requests: make(map[uint16]*udpDnsRequest)}
		owner.dispatcher = udp.NewDispatcher(dnsUDPNoopDispatcher{}, owner.handleResponse)
		id := uint16(i + 1)
		req := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: id}}}, owner: owner}
		if !server.addPendingRequest(req) {
			t.Fatal("failed to register racing request")
		}
		packet := routedDNSUDPResponse(t, id)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = owner.Close() }()
		go func() { defer wg.Done(); server.handleResponse(context.Background(), packet, owner) }()
		wg.Wait()
		server.RLock()
		remaining := len(owner.requests)
		mapped := server.requests[id]
		server.RUnlock()
		if remaining != 0 || mapped != nil {
			t.Fatalf("iteration %d race result: remaining=%d mapped=%p", i, remaining, mapped)
		}
	}
}

func TestRoutedDNSUDPImmediateCallerCancelAfterSuccessKeepsExactFacts(t *testing.T) {
	listener, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	type wireSizes struct{ query, response uint64 }
	sizes := make(chan wireSizes, 4)
	server := &mdns.Server{
		PacketConn: listener,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			response := new(mdns.Msg)
			response.SetReply(request)
			if len(request.Extra) == 0 {
				response.Truncated = true
			} else if len(request.Question) == 1 {
				var answer string
				switch request.Question[0].Qtype {
				case mdns.TypeA:
					answer = request.Question[0].Name + " 60 IN A 192.0.2.53"
				case mdns.TypeAAAA:
					answer = request.Question[0].Name + " 60 IN AAAA 2001:db8::53"
				}
				if answer != "" {
					rr, parseErr := mdns.NewRR(answer)
					if parseErr != nil {
						t.Errorf("answer: %v", parseErr)
						return
					}
					response.Answer = append(response.Answer, rr)
				}
			}
			queryWire, queryErr := request.Pack()
			responseWire, responseErr := response.Pack()
			if queryErr != nil || responseErr != nil {
				t.Errorf("pack request=%v response=%v", queryErr, responseErr)
				return
			}
			sizes <- wireSizes{uint64(len(queryWire)), uint64(len(responseWire))}
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
			t.Error("DNS UDP server did not stop")
		}
	})

	instance, view, routedDispatcher := newDNSTCPInspectionCore(t)
	destination := net.DestinationFromAddr(listener.LocalAddr())
	resolver := NewClassicNameServer(destination, routedDispatcher, true, false, 0, nil)
	ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
	t.Cleanup(cancel)
	ips, _, err := resolver.QueryIP(ctx, "routed-udp.example", dnsfeature.IPOption{IPv4Enable: true, IPv6Enable: true})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("response IPs: %v", ips)
	}
	var want wireSizes
	for range 4 {
		select {
		case got := <-sizes:
			want.query += got.query
			want.response += got.response
		case <-time.After(5 * time.Second):
			t.Fatal("missing DNS exchange")
		}
	}
	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 1)
	page, err := view.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := page.Rows[0]
	if row.Flow.Kind != featurestats.FlowKindUDPAssociation || row.Flow.Origin != featurestats.TrafficOriginInternal || row.Flow.InitialDestination != destination {
		t.Fatalf("routed DNS UDP identity: %+v", row.Flow)
	}
	if len(row.Flow.Routes) != 1 || row.Flow.AccountingRoute.Outbound.Tag != "direct" {
		t.Fatalf("routed DNS UDP route: %+v", row.Flow)
	}
	if row.Flow.Uplink.Known != want.query || row.Flow.Downlink.Known != want.response || row.Flow.Uplink.Incomplete || row.Flow.Downlink.Incomplete {
		t.Fatalf("routed DNS UDP bytes: uplink=%+v downlink=%+v want=%+v", row.Flow.Uplink, row.Flow.Downlink, want)
	}
	if row.Reason != featurestats.EndReasonUnknown {
		t.Fatalf("successful routed DNS UDP end reason: %v", row.Reason)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, total := range totals.Rows {
		if total.Outbound.Tag == "direct" && total.Origin == featurestats.TrafficOriginInternal {
			if total.Uplink.Known != want.query || total.Downlink.Known != want.response || total.Uplink.Incomplete || total.Downlink.Incomplete {
				t.Fatalf("immediate-cancel INTERNAL totals: %+v want=%+v", total, want)
			}
			return
		}
	}
	t.Fatalf("immediate-cancel INTERNAL total missing: %+v", totals.Rows)
}
