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
			flow := manager.Observation().Begin(cnet.Network_UDP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.OutboundRef{Tag: "tag-1"})
			proxy.RecordPacketWrite(flow, test.payload, 10, 3)
			flow.Finish()
			page, err := view.ReadTerminals()
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("packet terminal: %+v %v", page, err)
			}
			want := uint64(0)
			if page.Rows[0].Flow.Downlink != want {
				t.Fatalf("partial packet facts: %+v", page.Rows[0])
			}
		})
	}
}

func TestObservedEndpointStopNormalizesOnlyAlreadyClosed(t *testing.T) {
	for _, mode := range []string{"direct", "deferred"} {
		for _, test := range []struct {
			name        string
			err         error
			wantFailure bool
		}{
			{name: "network closed", err: net.ErrClosed},
			{name: "pipe closed", err: io.ErrClosedPipe},
			{name: "joined owner failure", err: errors.Join(net.ErrClosed, errors.New("owner cleanup failed")), wantFailure: true},
			{name: "native failure", err: errors.New("native close failed"), wantFailure: true},
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
					_, observed, cancel := proxy.BeginObservedEndpoint(context.Background(), manager.Observation(), conn, destination, cnet.Network_TCP)
					flow = observed
					t.Cleanup(cancel)
				} else {
					link := &transport.Link{Reader: buf.NewReader(conn), Writer: buf.NewWriter(conn)}
					ctx, finish := proxy.ObserveTCP(context.Background(), manager, conn, destination, link)
					flow = session.LogicalObservationFromContext(ctx).Exchange
					t.Cleanup(finish)
				}
				flow.Route(fs.OutboundRef{Tag: "selected"})
				outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
				if err != nil || len(outcomes) != 1 || (test.wantFailure && !errors.Is(outcomes[0], test.err)) || (!test.wantFailure && outcomes[0] != nil) {
					t.Fatalf("exact stop: %+v %v, want failure=%t", outcomes, err, test.wantFailure)
				}
				page, err := view.ReadTerminals()
				if err != nil || len(page.Rows) != 1 {
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
		observed, observation, cleanup := proxy.BeginReturnedObservation(ctx, manager, conn, destination, cnet.Network_TCP)
		if observed != ctx || observation != nil || cleanup != nil {
			t.Fatal("reserved carrier was admitted")
		}
		link := &transport.Link{Reader: buf.NewReader(conn), Writer: buf.NewWriter(conn)}
		original := *link
		observed, cleanup = proxy.ObserveTCP(ctx, manager, conn, destination, link)
		if observed != ctx || cleanup != nil || *link != original {
			t.Fatal("supplied TCP carrier was admitted")
		}
		observed, cleanup = proxy.ObserveUDP(ctx, manager, conn, destination, link)
		if observed != ctx || cleanup != nil || *link != original {
			t.Fatal("supplied UDP carrier was admitted")
		}
	}
	live, err := view.ReadLive()
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("carrier facts: %+v %v", live, err)
	}
}

func TestInspectionObservedEndpoint(t *testing.T) {
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
			flow := manager.Observation().Begin(cnet.Network_TCP, fs.TrafficOriginUnknown, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.OutboundRef{Tag: "selected"})
			flow.AddUplink(7)
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

			claimed := proxy.ObservedEndpoint(ctx, reader, test.eligible)
			if (claimed == observation) != test.wantClaim {
				t.Fatalf("claim=%t, want %t", claimed == observation, test.wantClaim)
			}
			live, err := view.ReadLive()
			if err != nil || len(live.Rows) != 1 {
				t.Fatalf("live rows: %+v %v", live, err)
			}
			if live.Rows[0].Outbound.Tag != "selected" {
				t.Fatalf("selection not visible: %+v", live.Rows[0])
			}
			totals, err := view.ReadTotals()
			if err != nil {
				t.Fatal(err)
			}
			bound := false
			for _, total := range totals.Rows {
				if total.Outbound.Tag == "selected" {
					bound = true
					if total.Uplink != 7 {
						t.Fatalf("bound credit: %+v", total)
					}
				} else if total.Uplink != 0 {
					t.Fatalf("unexpected credit: %+v", total)
				}
			}
			if !bound {
				t.Fatal("endpoint lookup changed selected-route accounting")
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
		flow := manager.Observation().Begin(cnet.Network_TCP, fs.TrafficOriginUnknown, cnet.Destination{}, cnet.Destination{}, nil)
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
		page, err := view.ReadTerminals()
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 {
			t.Fatalf("owner-end snapshot: %+v %v", page, err)
		}
		close(release)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("copy task did not release")
		}
		page, err = view.ReadTerminals()
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != 0 {
			t.Fatalf("late receipt mutated history: %+v %v", page, err)
		}
		totals, _ := view.ReadTotals()
		var known uint64
		for _, row := range totals.Rows {
			known += row.Uplink
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
	if buf.WriterReceipt(link.Writer) != flow {
		t.Fatal("endpoint receipt was not attached")
	}
	finish()
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Origin != fs.TrafficOriginInternal || page.Rows[0].Flow.Uplink != 12 {
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
	session.LogicalObservationFromContext(ctx).Exchange.Route(fs.OutboundRef{Tag: "custom"})
	if link.Writer != writer || buf.WriterReceipt(link.Writer) != nil {
		t.Fatal("custom writer was replaced or given an unsupported receipt")
	}
	live, err := view.ReadLive()
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("unsupported endpoint result: %+v %v", live, err)
	}
}
