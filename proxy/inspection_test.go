package proxy_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

type inspectionCloseResultConn struct {
	net.Conn
	result error
}

func (c *inspectionCloseResultConn) Close() error {
	_ = c.Conn.Close()
	return c.result
}

func TestRecordPacketWritePartialZeroPayload(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload uint64
	}{{"empty", 0}, {"nonempty", 7}} {
		t.Run(test.name, func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1}})
			flow.BindRoute()
			proxy.RecordPacketWrite(flow, test.payload, 10, 3, io.ErrClosedPipe)
			flow.Finish()
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("packet terminal: %+v %v", page, err)
			}
			want := fs.ByteFact{Incomplete: test.payload != 0}
			if page.Rows[0].Flow.Downlink != want || page.Rows[0].Reason != fs.EndReasonWriteError {
				t.Fatalf("partial packet facts: %+v", page.Rows[0])
			}
		})
	}
}

func TestObservedEndpointStopNormalizesOnlyAlreadyClosed(t *testing.T) {
	for _, mode := range []string{"direct", "deferred"} {
		for _, test := range []struct {
			name string
			err  error
			want fs.CloseCode
		}{
			{name: "network closed", err: net.ErrClosed, want: fs.CloseCodeAccepted},
			{name: "pipe closed", err: io.ErrClosedPipe, want: fs.CloseCodeAccepted},
			{name: "joined owner failure", err: errors.Join(net.ErrClosed, errors.New("owner cleanup failed")), want: fs.CloseCodeFailed},
			{name: "native failure", err: errors.New("native close failed"), want: fs.CloseCodeFailed},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				manager := new(appstats.Manager)
				view, err := manager.EnableInspection(fs.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = manager.Close() })
				endpoint, peer := net.Pipe()
				t.Cleanup(func() { _ = endpoint.Close(); _ = peer.Close() })
				conn := &inspectionCloseResultConn{Conn: endpoint, result: test.err}
				destination := cnet.TCPDestination(cnet.LocalHostIP, 443)
				var flow fs.Exchange
				if mode == "direct" {
					_, observed, cancel := proxy.BeginObservedEndpoint(context.Background(), manager.Observation(), conn, destination, fs.FlowKindTCP)
					flow = observed
					t.Cleanup(cancel)
				} else {
					link := &transport.Link{Reader: buf.NewReader(conn), Writer: buf.NewWriter(conn)}
					ctx, finish := proxy.ObserveTCP(context.Background(), manager, conn, destination, link)
					flow = session.LogicalObservationFromContext(ctx).Exchange
					t.Cleanup(finish)
				}
				flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "selected", Serial: 1}})
				flow.BindRoute()
				outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
				if err != nil || len(outcomes) != 1 || outcomes[0].Code != test.want {
					t.Fatalf("exact stop: %+v %v, want %v", outcomes, err, test.want)
				}
				page, err := view.ReadTerminals(context.Background())
				if err != nil || len(page.Rows) != 1 || page.Rows[0].Reason != fs.EndReasonLocalStop {
					t.Fatalf("terminal: %+v %v", page, err)
				}
			})
		}
	}
}

func TestObserveTCPDisabledPreservesEndpoint(t *testing.T) {
	for _, manager := range []fs.Manager{nil, fs.NoopManager{}, new(appstats.Manager)} {
		ctx := context.Background()
		link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.Discard}
		original := *link
		observed, finish := proxy.ObserveTCP(ctx, manager, nil, cnet.Destination{}, link)
		if observed != ctx || finish != nil || *link != original {
			t.Fatal("disabled collection changed the endpoint")
		}
	}
}

func TestObserveReturnedTCPDisabledPreservesEndpoint(t *testing.T) {
	for _, manager := range []fs.Manager{nil, fs.NoopManager{}, new(appstats.Manager)} {
		ctx := context.Background()
		link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.Discard}
		original := *link
		observed, finish := proxy.ObserveReturnedTCP(ctx, manager, nil, cnet.Destination{}, link)
		if observed != ctx || finish != nil || *link != original {
			t.Fatal("disabled returned collection changed the endpoint")
		}
	}
}

func TestBeginReturnedObservationExcludesReservedCarrier(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	ctx := context.Background()
	for _, destination := range []cnet.Destination{
		cnet.TCPDestination(cnet.DomainAddress("v1.mux.cool"), 0),
		cnet.UDPDestination(cnet.DomainAddress("v1.mux.cool"), 0),
	} {
		observed, observation, cleanup := proxy.BeginReturnedObservation(ctx, manager, conn, destination, fs.FlowKindTCP)
		if observed != ctx || observation != nil || cleanup != nil {
			t.Fatal("reserved carrier was admitted")
		}
		link := &transport.Link{Reader: buf.NewReader(conn), Writer: buf.NewWriter(conn)}
		observed, cleanup = proxy.ObserveTCP(ctx, manager, conn, destination, link)
		if observed != ctx || cleanup != nil {
			t.Fatal("supplied TCP carrier was admitted")
		}
		observed, cleanup = proxy.ObserveUDP(ctx, manager, conn, destination, link)
		if observed != ctx || cleanup != nil {
			t.Fatal("supplied UDP carrier was admitted")
		}
	}
	live, err := view.ReadLive(ctx)
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("carrier facts: %+v %v", live, err)
	}
}

func TestInspectionClaimObservedEndpoint(t *testing.T) {
	for _, test := range []struct {
		name        string
		eligible    bool
		observed    bool
		override    bool
		withContext bool
		wantClaim   bool
	}{
		{name: "direct", eligible: true, observed: true, withContext: true, wantClaim: true},
		{name: "endpoint override", eligible: true, observed: true, override: true, withContext: true, wantClaim: true},
		{name: "ineligible", observed: true, withContext: true},
		{name: "unobserved", eligible: true, withContext: true},
		{name: "no observation context", eligible: true, observed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close() })
			flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUnknown, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "selected"}})
			observation := &session.LogicalObservation{Exchange: flow}
			ctx := context.Background()
			if test.withContext {
				ctx = session.ContextWithLogicalObservation(ctx, observation)
			}
			var reader buf.Reader = buf.NewReader(strings.NewReader("payload"))
			if test.observed {
				reader = buf.NewInspectionReader(&buf.BufferedReader{Reader: reader}, flow, nil)
			}
			if test.override {
				reader = &buf.EndpointOverrideReader{Reader: reader}
			}

			claimed := proxy.ClaimObservedEndpoint(ctx, reader, test.eligible)
			if (claimed == observation) != test.wantClaim {
				t.Fatalf("claim=%t, want %t", claimed == observation, test.wantClaim)
			}
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 {
				t.Fatalf("live rows: %+v %v", live, err)
			}
			bound := live.Rows[0].AccountingRoute.Outbound.Tag == "selected"
			if bound != test.wantClaim {
				t.Fatalf("route bound=%t, want %t: %+v", bound, test.wantClaim, live.Rows[0].AccountingRoute)
			}
		})
	}
}

func TestNativeCopyTasksEarlyReturnKeepsHistoryImmutable(t *testing.T) {
	for _, delayedRequest := range []bool{false, true} {
		manager := new(appstats.Manager)
		view, err := manager.EnableInspection(fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { manager.Close() })
		flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUnknown, cnet.Destination{}, cnet.Destination{}, nil)
		release := make(chan struct{})
		t.Cleanup(func() {
			select {
			case <-release:
			default:
				close(release)
			}
		})
		done := make(chan struct{})
		failure := errors.New("native pump failed")
		delayed := func() error {
			<-release
			flow.AddUplink(7)
			return nil
		}
		failed := func() error { return failure }
		request, response := failed, delayed
		if delayedRequest {
			request, response = delayed, failed
		}
		if delayedRequest {
			f := request
			request = func() error { defer close(done); return f() }
		} else {
			f := response
			response = func() error { defer close(done); return f() }
		}
		if err := task.Run(context.Background(), request, response); !errors.Is(err, failure) {
			t.Fatalf("native error changed: %v", err)
		}
		flow.Finish()
		page, err := view.ReadTerminals(context.Background())
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 0 {
			t.Fatalf("owner-end snapshot: %+v %v", page, err)
		}
		close(release)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("copy task did not release")
		}
		page, err = view.ReadTerminals(context.Background())
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 0 {
			t.Fatalf("late receipt mutated history: %+v %v", page, err)
		}
		totals, _ := view.ReadTotals(context.Background())
		var known uint64
		for _, row := range totals.Rows {
			known += row.Uplink.Known
		}
		if known != 7 {
			t.Fatalf("late receipt missing from totals: %+v", totals)
		}
	}
}

func TestObserveTCPRetainedInputAndOwnerEnd(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	reader := &buf.BufferedReader{Reader: buf.NewReader(strings.NewReader("tail")), Buffer: buf.MultiBuffer{buf.FromBytes([]byte("retained"))}}
	link := &transport.Link{Reader: reader, Writer: buf.NewWriter(conn)}
	originalWriter := link.Writer
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginInternal)
	ctx, finish := proxy.ObserveTCP(ctx, manager, conn, cnet.TCPDestination(cnet.LocalHostIP, 80), link)
	if finish == nil || reader.Buffer != nil {
		t.Fatal("retained input did not transfer to the cursor")
	}
	defer finish()
	for _, want := range []string{"retained", "tail"} {
		mb, err := link.Reader.ReadMultiBuffer()
		got := mb.String()
		buf.ReleaseMulti(mb)
		if err != nil || got != want {
			t.Fatalf("input %q want %q: %v", got, want, err)
		}
	}
	observation := session.LogicalObservationFromContext(ctx)
	flow := observation.Exchange
	if link.Writer == originalWriter || buf.WriterReceipt(link.Writer) != flow {
		t.Fatal("inspection failed to install the enabled receipt writer")
	}
	finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Origin != fs.TrafficOriginInternal || page.Rows[0].Flow.Uplink.Known != 12 {
		t.Fatalf("owner-end snapshot: %+v %v", page, err)
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("cleanup did not cancel the endpoint")
	}
}

func TestObserveTCPCustomWriterRemainsUnavailable(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	writer := &struct{ buf.Writer }{buf.NewWriter(conn)}
	link := &transport.Link{Reader: buf.NewReader(conn), Writer: writer}
	ctx, finish := proxy.ObserveTCP(context.Background(), manager, conn, cnet.TCPDestination(cnet.LocalHostIP, 80), link)
	if finish == nil {
		t.Fatal("inspection was not enabled")
	}
	defer finish()
	proxy.ClaimObservedEndpoint(ctx, link.Reader, true)
	if link.Writer != writer || buf.WriterReceipt(link.Writer) != nil {
		t.Fatal("custom writer was replaced or given an unsupported receipt")
	}
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 || !live.Rows[0].Downlink.Incomplete {
		t.Fatalf("unsupported endpoint result: %+v %v", live, err)
	}
}

func TestObserveReturnedTCPDispatcherCleanupAndOwnerEnd(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.NewWriter(conn)}
	ctx, finish := proxy.ObserveReturnedTCP(context.Background(), manager, conn, cnet.TCPDestination(cnet.LocalHostIP, 80), link)
	if finish == nil {
		t.Fatal("returned observation was not enabled")
	}
	observation := session.LogicalObservationFromContext(ctx)
	if observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
		t.Fatal("dispatcher role was not claimed")
	}
	observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "selected", Serial: 7}})
	observation.Exchange.BindRoute()

	releasePump := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-releasePump:
		default:
			close(releasePump)
		}
	})
	pumpDone := make(chan struct{})
	request, response := func() error {
		<-releasePump
		observation.Exchange.AddUplink(7)
		return nil
	}, func() error { return nil }
	go func() {
		defer close(pumpDone)
		_ = request()
	}()
	if err := response(); err != nil {
		t.Fatal(err)
	}
	finish()
	if page, err := view.ReadTerminals(context.Background()); err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 0 {
		t.Fatalf("owner-end snapshot: %+v %v", page, err)
	}
	close(releasePump)
	select {
	case <-pumpDone:
	case <-time.After(3 * time.Second):
		t.Fatal("late inbound pump did not release")
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.AccountingRoute.Outbound.Tag != "selected" || page.Rows[0].Flow.Uplink.Known != 0 {
		t.Fatalf("late pump mutated history: %+v %v", page, err)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, row := range totals.Rows {
		known += row.Uplink.Known
	}
	if known != 7 {
		t.Fatalf("late pump missing from totals: %+v", totals)
	}
}

func TestObserveReturnedTCPCleanupEndsUnclaimed(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.NewWriter(conn)}
	ctx, finish := proxy.ObserveReturnedTCP(context.Background(), manager, conn, cnet.TCPDestination(cnet.LocalHostIP, 80), link)
	observation := session.LogicalObservationFromContext(ctx)
	if finish == nil || observation == nil || !observation.ReturnedLink.CompareAndSwap(true, false) {
		t.Fatal("returned dispatcher claim failed")
	}
	finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 0 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("unclaimed owner-end snapshot: %+v %v", page, err)
	}
	observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionRule, RuleTag: "late", Outbound: fs.OutboundRef{Tag: "selected", Serial: 9}})
	downstream := buf.NewInspectionReader(&buf.BufferedReader{Reader: buf.NewReader(strings.NewReader(""))}, observation.Exchange, nil)
	downstream.InputAlreadyObserved = true
	if claimed := proxy.ClaimObservedEndpoint(ctx, downstream, true); claimed != observation {
		t.Fatal("late downstream role claim was not returned")
	}
	finish()
	page, err = view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 0 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("late attribution mutated owner-end history: %+v %v", page, err)
	}
}

func TestObserveReturnedTCPUnconsumedOwnerEndsIncomplete(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.NewWriter(conn)}
	ctx, finish := proxy.ObserveReturnedTCP(context.Background(), manager, conn, cnet.TCPDestination(cnet.LocalHostIP, 80), link)
	observation := session.LogicalObservationFromContext(ctx)
	if finish == nil || observation == nil || !observation.ReturnedLink.Load() {
		t.Fatal("returned claim token was not installed")
	}
	finish()
	observation.Exchange.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 0 || !page.Rows[0].Flow.Uplink.Incomplete || !page.Rows[0].Flow.Downlink.Incomplete {
		t.Fatalf("unconsumed owner snapshot: %+v %v", page, err)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatalf("unconsumed returned owner lost uncertainty: %+v %v", totals, err)
	}
	var incomplete bool
	for _, row := range totals.Rows {
		if row.Outbound.Serial != 0 {
			t.Fatalf("unconsumed returned owner acquired an outbound: %+v", row)
		}
		incomplete = incomplete || row.Uplink.Incomplete || row.Downlink.Incomplete
	}
	if !incomplete {
		t.Fatalf("unconsumed returned owner lost uncertainty: %+v", totals)
	}
}

func TestObserveReturnedTCPRoleClaimAfterBoundStop(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("payload")), Writer: buf.NewWriter(conn)}
	ctx, finish := proxy.ObserveReturnedTCP(context.Background(), manager, conn, cnet.TCPDestination(cnet.LocalHostIP, 80), link)
	observation := session.LogicalObservationFromContext(ctx)
	// Statistical owner ending does not replace the native launch/cancel guard.
	observation.Exchange.BindRoute()
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{observation.Exchange.Ref()})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("pre-dispatch stop: %+v %v", outcomes, err)
	}
	if !observation.ReturnedLink.CompareAndSwap(true, false) {
		t.Fatal("owner ending blocked the native role claim")
	}
	finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatalf("failed dispatch ordering: %+v %v", page, err)
	}
}
