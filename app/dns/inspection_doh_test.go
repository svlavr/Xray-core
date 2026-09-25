package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/loopback"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestDoHRouteReceiptCommitsLastContinuationOnce(t *testing.T) {
	receipt := newDoHRouteReceipt()
	receipt.Offer(featurestats.RouteStep{Outbound: featurestats.OutboundRef{Serial: 7, Tag: "loopback"}})
	receipt.Offer(featurestats.RouteStep{Outbound: featurestats.OutboundRef{Serial: 11, Tag: "direct"}})
	ctx := session.ContextWithRouteOnlyReceipt(context.Background(), receipt)
	proxy.ClaimObservedEndpoint(ctx, nil, true)
	receipt.Offer(featurestats.RouteStep{Outbound: featurestats.OutboundRef{Serial: 13, Tag: "late"}})
	step, ok := receipt.Snapshot()
	if !ok || step.Outbound.Serial != 11 || step.Outbound.Tag != "direct" {
		t.Fatalf("committed continuation route: ok=%v step=%+v", ok, step)
	}
}

func TestRoutedDoHHTTP2ReuseAndExactStreamStop(t *testing.T) {
	firstStarted := make(chan struct{}, 1)
	secondStarted := make(chan struct{}, 1)
	releaseSecond := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSecond) }) }
	t.Cleanup(release)

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Uint32
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepts.Add(1)
			go new(http2.Server).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					return
				}
				switch string(body) {
				case "warm":
					_, _ = w.Write([]byte("warm-response"))
				case "first":
					firstStarted <- struct{}{}
					<-r.Context().Done()
				case "second":
					secondStarted <- struct{}{}
					select {
					case <-releaseSecond:
						_, _ = w.Write([]byte("second-response"))
					case <-r.Context().Done():
					}
				case "failure":
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte("excluded-http-framing"))
				case "malformed":
					_, _ = w.Write([]byte{0xff, 0x00, 0x01})
				}
			})})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("HTTP/2 accept loop did not stop")
		}
	})

	instance, view, routedDispatcher := newDNSTCPInspectionCore(t)
	endpoint, err := url.Parse("https://" + listener.Addr().String() + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewDoHNameServer(endpoint, routedDispatcher, true, true, false, 0, nil)
	t.Cleanup(func() { resolver.httpClient.Transport.(*http2.Transport).CloseIdleConnections() })
	request := func(payload string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
		defer cancel()
		return resolver.dohHTTPSContext(ctx, []byte(payload))
	}
	if response, requestErr := request("warm"); requestErr != nil || string(response) != "warm-response" {
		t.Fatalf("warm request: response=%q err=%v", response, requestErr)
	}
	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 1)

	type result struct {
		body []byte
		err  error
	}
	firstResult := make(chan result, 1)
	go func() { body, requestErr := request("first"); firstResult <- result{body, requestErr} }()
	select {
	case <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first stream did not reach the server")
	}
	var firstRef featurestats.FlowRef
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		if readErr == nil && len(live.Rows) == 1 {
			firstRef = live.Rows[0].Ref
		}
		return len(live.Rows), readErr
	}, 1)

	secondResult := make(chan result, 1)
	go func() { body, requestErr := request("second"); secondResult <- result{body, requestErr} }()
	select {
	case <-secondStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("second stream did not reach the server")
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("concurrent requests did not reuse one HTTP/2 carrier: accepts=%d", got)
	}
	outcomes, err := view.CloseFlows(context.Background(), []featurestats.FlowRef{firstRef})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != featurestats.CloseCodeAccepted {
		t.Fatalf("stop first stream: outcomes=%+v err=%v", outcomes, err)
	}
	select {
	case stopped := <-firstResult:
		if stopped.err == nil {
			t.Fatalf("stopped stream unexpectedly succeeded: %q", stopped.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stopped stream did not return")
	}
	release()
	select {
	case sibling := <-secondResult:
		if sibling.err != nil || string(sibling.body) != "second-response" {
			t.Fatalf("sibling stream: body=%q err=%v", sibling.body, sibling.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sibling stream did not survive exact stop")
	}
	if body, requestErr := request("failure"); requestErr == nil || body != nil {
		t.Fatalf("non-200 request: body=%q err=%v", body, requestErr)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("non-200 request did not preserve the pooled carrier: accepts=%d", got)
	}
	decodeCtx, decodeCancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
	response, decodeObservation, requestErr := resolver.dohHTTPSContextObserved(decodeCtx, []byte("malformed"))
	decodeCancel()
	if requestErr != nil || decodeObservation == nil {
		t.Fatalf("malformed response transport: response=%x observation=%p err=%v", response, decodeObservation, requestErr)
	}
	if _, decodeErr := parseObservedDoHResponse(response, decodeObservation); decodeErr == nil {
		t.Fatal("malformed DNS response unexpectedly decoded")
	}

	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 5)
	page, err := view.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var stoppedFound, routedSibling, failureFound, decodeFailureFound bool
	for _, row := range page.Rows {
		if row.Flow.Ref == firstRef {
			stoppedFound = row.Reason == featurestats.EndReasonLocalStop
		}
		if row.Flow.Uplink.Known == uint64(len("second")) && row.Flow.Downlink.Known == uint64(len("second-response")) && row.Flow.AccountingRoute.Outbound.Tag == "direct" && row.Flow.AccountingRoute.Outbound.Serial != 0 {
			routedSibling = true
		}
		if row.Flow.Uplink.Known == uint64(len("failure")) && row.Flow.Downlink.Known == 0 && row.Flow.Downlink.Incomplete && row.Flow.AccountingRoute.Outbound.Tag == "direct" {
			failureFound = true
		}
		if row.Flow.Uplink.Known == uint64(len("malformed")) && row.Flow.Downlink.Known == 3 && row.Flow.Downlink.Incomplete && row.Reason == featurestats.EndReasonReadError {
			decodeFailureFound = true
		}
	}
	if !stoppedFound || !routedSibling || !failureFound || !decodeFailureFound {
		t.Fatalf("DoH terminal facts: stopped=%v routedSibling=%v failure=%v decode=%v rows=%+v", stoppedFound, routedSibling, failureFound, decodeFailureFound, page.Rows)
	}
}

type dohRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f dohRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestLocalDoHLeavesObservationDisabled(t *testing.T) {
	server := &DoHNameServer{
		dohURL: "https://local.invalid/dns-query",
		httpClient: &http.Client{Transport: dohRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != "query" {
				t.Fatalf("local request body=%q err=%v", body, err)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("response")), Header: make(http.Header), Request: request}, nil
		})},
	}
	response, err := server.dohHTTPSContext(context.Background(), []byte("query"))
	if err != nil || string(response) != "response" {
		t.Fatalf("local DoH response=%q err=%v", response, err)
	}
}

func TestDoHRetryBodyReadsFollowEachCarrierLeg(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	store := instance.GetFeature(featurestats.ManagerType()).(featurestats.ObservationProvider).Observation()
	destination := dohDestination("127.0.0.1", "443")
	root := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginInternal, destination, destination, nil)
	observation := &dohRequestObservation{root: root, bodySize: 5, cancel: func() {}}

	carrier := func(serial uint64, tag string) *dohCarrierConn {
		route := newDoHRouteReceipt()
		route.Offer(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Serial: serial, Tag: tag}})
		route.Commit()
		return &dohCarrierConn{Conn: new(dnsTCPCloseCountingConn), route: route}
	}
	observation.gotConn(httptrace.GotConnInfo{Conn: carrier(71, "first")})
	observation.recordBodyRead(5)
	observation.gotConn(httptrace.GotConnInfo{Conn: carrier(72, "retry")})
	observation.recordBodyRead(5)
	observation.recordResponseRead(7, nil)
	observation.finish(true)

	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 10 || page.Rows[0].Flow.Downlink.Known != 7 {
		t.Fatalf("retry root: page=%+v err=%v", page, err)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var first, retry bool
	for _, total := range totals.Rows {
		switch total.Outbound.Serial {
		case 71:
			first = total.Uplink.Known == 5 && total.Downlink.Known == 0 && total.Downlink.Incomplete
		case 72:
			retry = total.Uplink.Known == 5 && total.Downlink.Known == 7 && !total.Uplink.Incomplete && !total.Downlink.Incomplete
		}
	}
	if !first || !retry {
		t.Fatalf("per-carrier retry totals: first=%v retry=%v totals=%+v", first, retry, totals.Rows)
	}
}

type dohGoAwayRetryRequest struct {
	carrier uint32
	stream  uint32
	body    []byte
}

type dohGoAwayRetryDispatcher struct {
	dispatches atomic.Uint32
	requests   chan dohGoAwayRetryRequest
	errors     chan error
}

func (*dohGoAwayRetryDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dohGoAwayRetryDispatcher) Start() error      { return nil }
func (*dohGoAwayRetryDispatcher) Close() error      { return nil }

func (d *dohGoAwayRetryDispatcher) Dispatch(ctx context.Context, _ xnet.Destination) (*transport.Link, error) {
	carrier := d.dispatches.Add(1)
	if carrier > 2 {
		return nil, fmt.Errorf("unexpected DoH carrier %d", carrier)
	}
	receipt := session.RouteOnlyReceiptFromContext(ctx)
	if receipt == nil {
		return nil, fmt.Errorf("carrier %d has no route receipt", carrier)
	}
	tag := "goaway-first"
	if carrier == 2 {
		tag = "goaway-retry"
	}
	receipt.Offer(featurestats.RouteStep{
		Selection: featurestats.SelectionDefault,
		Outbound:  featurestats.OutboundRef{Serial: uint64(100 + carrier), Tag: tag},
	})
	receipt.Commit()

	client, server := stdnet.Pipe()
	go func() {
		defer server.Close()
		if err := serveDoHGoAwayRetryCarrier(server, carrier, d.requests); err != nil {
			d.errors <- fmt.Errorf("carrier %d: %w", carrier, err)
		}
	}()
	return &transport.Link{Reader: buf.NewReader(client), Writer: buf.NewWriter(client)}, nil
}

func (*dohGoAwayRetryDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return io.ErrClosedPipe
}

func serveDoHGoAwayRetryCarrier(conn stdnet.Conn, carrier uint32, requests chan<- dohGoAwayRetryRequest) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return fmt.Errorf("read client preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("client preface %q", preface)
	}
	framer := http2.NewFramer(conn, conn)
	var receivedSettings, receivedWindowUpdate bool
	for !receivedSettings || !receivedWindowUpdate {
		frame, err := framer.ReadFrame()
		if err != nil {
			return fmt.Errorf("read client handshake: %w", err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			receivedSettings = !frame.IsAck()
		case *http2.WindowUpdateFrame:
			receivedWindowUpdate = frame.StreamID == 0
		default:
			return fmt.Errorf("client handshake frame %T", frame)
		}
	}
	if err := framer.WriteSettings(); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}

	var stream uint32
	var body []byte
	var clientSettingsAck, requestComplete bool
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return fmt.Errorf("read request frame: %w", err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if frame.IsAck() {
				clientSettingsAck = true
			} else {
				return fmt.Errorf("unexpected repeated client settings")
			}
		case *http2.PingFrame:
			if !frame.Flags.Has(http2.FlagPingAck) {
				if err := framer.WritePing(true, frame.Data); err != nil {
					return fmt.Errorf("ack ping: %w", err)
				}
			}
		case *http2.HeadersFrame:
			stream = frame.StreamID
			if frame.StreamEnded() {
				return fmt.Errorf("request stream %d ended before its body", stream)
			}
		case *http2.DataFrame:
			if stream == 0 || frame.StreamID != stream {
				return fmt.Errorf("data stream %d without headers for stream %d", frame.StreamID, stream)
			}
			body = append(body, frame.Data()...)
			if frame.StreamEnded() {
				requestComplete = true
			}
		}
		if !requestComplete || !clientSettingsAck {
			continue
		}
		requests <- dohGoAwayRetryRequest{carrier: carrier, stream: stream, body: append([]byte(nil), body...)}
		if err := framer.WriteSettingsAck(); err != nil {
			return fmt.Errorf("ack settings: %w", err)
		}
		if carrier == 1 {
			if err := framer.WriteGoAway(0, http2.ErrCodeNo, []byte("retry after consumed body")); err != nil {
				return fmt.Errorf("write GOAWAY: %w", err)
			}
			return nil
		}

		response := []byte("retry-response")
		var header bytes.Buffer
		encoder := hpack.NewEncoder(&header)
		if err := encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
			return fmt.Errorf("encode response status: %w", err)
		}
		if err := encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(response))}); err != nil {
			return fmt.Errorf("encode response length: %w", err)
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      stream,
			BlockFragment: header.Bytes(),
			EndHeaders:    true,
		}); err != nil {
			return fmt.Errorf("write response headers: %w", err)
		}
		if err := framer.WriteData(stream, true, response); err != nil {
			return fmt.Errorf("write response body: %w", err)
		}
		return nil
	}
}

func TestRoutedDoHNativeGoAwayRetryAttribution(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	dispatcher := &dohGoAwayRetryDispatcher{
		requests: make(chan dohGoAwayRetryRequest, 2),
		errors:   make(chan error, 2),
	}
	endpoint, err := url.Parse("https://goaway.invalid/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewDoHNameServer(endpoint, dispatcher, true, true, false, 0, nil)
	t.Cleanup(func() { resolver.httpClient.Transport.(*http2.Transport).CloseIdleConnections() })

	payload := []byte("retry-query")
	ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
	defer cancel()
	response, err := resolver.dohHTTPSContext(ctx, payload)
	if err != nil || string(response) != "retry-response" {
		t.Fatalf("native GOAWAY retry: response=%q err=%v", response, err)
	}
	if got := dispatcher.dispatches.Load(); got != 2 {
		t.Fatalf("native GOAWAY did not move the retry to a second carrier: dispatches=%d", got)
	}

	for wantCarrier := uint32(1); wantCarrier <= 2; wantCarrier++ {
		select {
		case request := <-dispatcher.requests:
			if request.carrier != wantCarrier || request.stream != 1 || !bytes.Equal(request.body, payload) {
				t.Fatalf("carrier request: got=%+v want carrier=%d stream=1 body=%q", request, wantCarrier, payload)
			}
		case serverErr := <-dispatcher.errors:
			t.Fatal(serverErr)
		case <-time.After(5 * time.Second):
			t.Fatalf("carrier %d did not consume the replayed request body", wantCarrier)
		}
	}
	select {
	case serverErr := <-dispatcher.errors:
		t.Fatal(serverErr)
	default:
	}

	waitDNSTCPRows(t, func() (int, error) {
		page, readErr := view.ReadTerminals(context.Background())
		return len(page.Rows), readErr
	}, 1)
	page, err := view.ReadTerminals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	flow := page.Rows[0].Flow
	if flow.Ref == (featurestats.FlowRef{}) || flow.Origin != featurestats.TrafficOriginInternal || flow.Uplink.Known != uint64(2*len(payload)) || flow.Downlink.Known != uint64(len("retry-response")) || flow.Uplink.Incomplete || !flow.Downlink.Incomplete {
		t.Fatalf("native GOAWAY root facts: %+v", page.Rows[0])
	}
	if len(flow.Routes) != 2 || flow.Routes[0].Outbound.Serial != 101 || flow.Routes[1].Outbound.Serial != 102 || flow.AccountingRoute.Outbound.Serial != 102 {
		t.Fatalf("native GOAWAY attempt routes: %+v", flow)
	}

	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var first, retry bool
	for _, total := range totals.Rows {
		switch total.Outbound.Serial {
		case 101:
			first = total.Origin == featurestats.TrafficOriginInternal && total.Uplink.Known == uint64(len(payload)) && total.Downlink.Known == 0 && !total.Uplink.Incomplete && total.Downlink.Incomplete
		case 102:
			retry = total.Origin == featurestats.TrafficOriginInternal && total.Uplink.Known == uint64(len(payload)) && total.Downlink.Known == uint64(len("retry-response")) && !total.Uplink.Incomplete && !total.Downlink.Incomplete
		}
	}
	if !first || !retry {
		t.Fatalf("native GOAWAY per-attempt totals: first=%v retry=%v totals=%+v", first, retry, totals.Rows)
	}
}

func TestRoutedDoHCapacityFallsBackWithoutHiddenAggregate(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	store := instance.GetFeature(featurestats.ManagerType()).(featurestats.ObservationProvider).Observation()
	roots := make([]featurestats.Exchange, 0, store.Info().Limits.MaxLive)
	for range store.Info().Limits.MaxLive {
		roots = append(roots, store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginUser, xnet.Destination{}, xnet.TCPDestination(xnet.LocalHostIP, 80), nil))
	}
	t.Cleanup(func() {
		for _, root := range roots {
			root.Finish()
		}
	})
	server := &DoHNameServer{
		routed:      true,
		destination: xnet.TCPDestination(xnet.LocalHostIP, 443),
		dohURL:      "https://capacity.invalid/dns-query",
		httpClient: &http.Client{Transport: dohRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != "native" {
				t.Fatalf("fallback request body=%q err=%v", body, err)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("response")), Header: make(http.Header), Request: request}, nil
		})},
	}
	response, err := server.dohHTTPSContext(dnsTCPTestContext(instance), []byte("native"))
	if err != nil || string(response) != "response" {
		t.Fatalf("capacity fallback response=%q err=%v", response, err)
	}
	live, _ := view.ReadLive(context.Background())
	terminals, _ := view.ReadTerminals(context.Background())
	totals, _ := view.ReadTotals(context.Background())
	if len(live.Rows) != int(store.Info().Limits.MaxLive) || len(terminals.Rows) != 0 || live.Loss.UntrackedAdmissions != 1 {
		t.Fatalf("capacity fallback visibility: live=%d terminals=%d loss=%+v", len(live.Rows), len(terminals.Rows), live.Loss)
	}
	for _, total := range totals.Rows {
		if total.Uplink.Known != 0 || total.Downlink.Known != 0 || total.Uplink.Incomplete || total.Downlink.Incomplete {
			t.Fatalf("capacity fallback created hidden aggregate: %+v", total)
		}
	}
}

func TestRoutedDoHMissingForcedHandlerIsRejected(t *testing.T) {
	instance, view, routedDispatcher := newDNSTCPInspectionCore(t)
	endpoint, err := url.Parse("https://127.0.0.1:1/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewDoHNameServer(endpoint, routedDispatcher, true, true, false, 0, nil)
	ctx := session.SetForcedOutboundTagToContext(dnsTCPTestContext(instance), "missing")
	if response, requestErr := resolver.dohHTTPSContext(ctx, []byte("rejected")); requestErr == nil || response != nil {
		t.Fatalf("missing forced handler response=%q err=%v", response, requestErr)
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
	if row.Reason != featurestats.EndReasonRejected || row.Flow.AccountingRoute.Selection != featurestats.SelectionRejected || row.Flow.AccountingRoute.Outbound.Tag != "missing" || row.Flow.Uplink.Known != 0 || row.Flow.Downlink.Known != 0 || !row.Flow.Uplink.Incomplete || !row.Flow.Downlink.Incomplete {
		t.Fatalf("missing forced handler facts: %+v", row)
	}
}

type blockedDoHDispatcher struct {
	started   chan struct{}
	release   chan struct{}
	requests  atomic.Uint32
	startOnce sync.Once
}

func (*blockedDoHDispatcher) Type() interface{} { return nil }
func (*blockedDoHDispatcher) Start() error      { return nil }
func (*blockedDoHDispatcher) Close() error      { return nil }

func (d *blockedDoHDispatcher) Dispatch(ctx context.Context, _ xnet.Destination) (*transport.Link, error) {
	d.requests.Add(1)
	client, server := stdnet.Pipe()
	go func() {
		d.startOnce.Do(func() { close(d.started) })
		<-d.release
		receipt := session.RouteOnlyReceiptFromContext(ctx)
		receipt.Offer(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Serial: 91, Tag: "blocked-dial"}})
		receipt.Commit()
		new(http2.Server).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			_, _ = w.Write(append([]byte("response:"), body...))
		})})
	}()
	return &transport.Link{Reader: buf.NewReader(client), Writer: buf.NewWriter(client)}, nil
}

func (*blockedDoHDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}

func TestRoutedDoHStopWhileWaitingForSharedDialFinishesRoot(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	dispatcher := &blockedDoHDispatcher{started: make(chan struct{}), release: make(chan struct{})}
	endpoint, err := url.Parse("https://blocked.invalid/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewDoHNameServer(endpoint, dispatcher, true, true, false, 0, nil)
	t.Cleanup(func() { resolver.httpClient.Transport.(*http2.Transport).CloseIdleConnections() })
	type result struct {
		body []byte
		err  error
	}
	request := func(payload string) <-chan result {
		resultCh := make(chan result, 1)
		go func() {
			body, requestErr := resolver.dohHTTPSContext(dnsTCPTestContext(instance), []byte(payload))
			resultCh <- result{body: body, err: requestErr}
		}()
		return resultCh
	}
	firstResult := request("first")
	select {
	case <-dispatcher.started:
	case <-time.After(5 * time.Second):
		t.Fatal("shared dial did not start")
	}
	var firstRef featurestats.FlowRef
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		if readErr == nil && len(live.Rows) == 1 {
			firstRef = live.Rows[0].Ref
		}
		return len(live.Rows), readErr
	}, 1)
	secondResult := request("second")
	var secondRef featurestats.FlowRef
	waitDNSTCPRows(t, func() (int, error) {
		live, readErr := view.ReadLive(context.Background())
		if readErr == nil && len(live.Rows) == 2 {
			for _, row := range live.Rows {
				if row.Ref != firstRef {
					secondRef = row.Ref
				}
			}
		}
		return len(live.Rows), readErr
	}, 2)
	if dispatcher.requests.Load() != 1 {
		close(dispatcher.release)
		<-firstResult
		<-secondResult
		t.Skip("Go 1.27 HTTP/2 wrapper started independent in-flight dials; legacy x/net pool coverage runs with http2legacy")
	}
	outcomes, err := view.CloseFlows(context.Background(), []featurestats.FlowRef{secondRef})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != featurestats.CloseCodeAccepted {
		t.Fatalf("close pooled waiter: outcomes=%+v err=%v", outcomes, err)
	}
	terminals, err := view.ReadTerminals(context.Background())
	if err != nil || len(terminals.Rows) != 1 || terminals.Rows[0].Flow.Ref != secondRef || terminals.Rows[0].Reason != featurestats.EndReasonLocalStop {
		t.Fatalf("pooled waiter did not finish immediately: rows=%+v err=%v", terminals.Rows, err)
	}
	close(dispatcher.release)
	select {
	case first := <-firstResult:
		if first.err != nil || string(first.body) != "response:first" {
			t.Fatalf("dial owner result: body=%q err=%v", first.body, first.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial owner did not complete")
	}
	select {
	case second := <-secondResult:
		if second.err == nil {
			t.Fatalf("stopped pooled waiter unexpectedly succeeded: %q", second.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stopped pooled waiter did not return after shared dial")
	}
	terminals, _ = view.ReadTerminals(context.Background())
	for _, row := range terminals.Rows {
		if row.Flow.Ref == secondRef && (len(row.Flow.Routes) != 0 || row.Flow.Uplink.Known != 0 || row.Flow.Downlink.Known != 0) {
			t.Fatalf("late GotConn mutated stopped waiter: %+v", row)
		}
	}
}

type stoppedBeginExchange struct {
	dnsTCPTestExchange
	live atomic.Bool
}

func (*stoppedBeginExchange) Ref() featurestats.FlowRef {
	return featurestats.FlowRef{ID: 1}
}

func (e *stoppedBeginExchange) Finish() {
	e.live.Store(false)
	e.dnsTCPTestExchange.Finish()
}

type stopDuringBeginStore struct{ exchange *stoppedBeginExchange }

func (*stopDuringBeginStore) Info() featurestats.InspectionInfo { return featurestats.InspectionInfo{} }

func (s *stopDuringBeginStore) Begin(_ featurestats.FlowKind, _ featurestats.TrafficOrigin, _, _ xnet.Destination, stop func() error) featurestats.Exchange {
	s.exchange.live.Store(true)
	s.exchange.SetEndReason(featurestats.EndReasonLocalStop)
	_ = stop()
	return s.exchange
}

func (s *stopDuringBeginStore) PrepareTCP(featurestats.TrafficOrigin, xnet.Destination, xnet.Destination, func() error) featurestats.Exchange {
	return s.exchange
}

func TestRoutedDoHStopDuringBeginReturnsCanceledNativeContext(t *testing.T) {
	flow := new(stoppedBeginExchange)
	var roundTrips atomic.Uint32
	server := &DoHNameServer{
		routed:      true,
		destination: xnet.TCPDestination(xnet.LocalHostIP, 443),
		dohURL:      "https://stopped.invalid/dns-query",
		httpClient: &http.Client{Transport: dohRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			roundTrips.Add(1)
			return nil, context.Canceled
		})},
	}
	_, observation, err := server.dohHTTPSContextWithStore(context.Background(), []byte("query"), &stopDuringBeginStore{exchange: flow})
	if err == nil || observation != nil || flow.finished.Load() != 1 || flow.live.Load() || featurestats.EndReason(flow.reason.Load()) != featurestats.EndReasonLocalStop || roundTrips.Load() != 0 {
		t.Fatalf("stopped Begin result: calls=%d err=%v finishes=%d live=%v reason=%v", roundTrips.Load(), err, flow.finished.Load(), flow.live.Load(), featurestats.EndReason(flow.reason.Load()))
	}
}

func TestDoHTLSHandshakeErrorClosesBeforeClassification(t *testing.T) {
	receipt := newDoHRouteReceipt()
	receipt.Offer(featurestats.RouteStep{Selection: featurestats.SelectionRejected, Outbound: featurestats.OutboundRef{Tag: "missing"}})
	receipt.Commit()
	conn := new(dnsTCPCloseCountingConn)
	err := classifyDoHTLSHandshakeError(context.Background(), conn, receipt, io.ErrUnexpectedEOF)
	if _, rejected := dohRejectedRoute(err); !rejected || conn.closed.Load() != 1 {
		t.Fatalf("rejected handshake classification: err=%v closed=%d", err, conn.closed.Load())
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledConn := new(dnsTCPCloseCountingConn)
	err = classifyDoHTLSHandshakeError(canceled, canceledConn, receipt, io.ErrUnexpectedEOF)
	if err != context.Canceled || canceledConn.closed.Load() != 1 {
		t.Fatalf("canceled handshake classification: err=%v closed=%d", err, canceledConn.closed.Load())
	}
}

func TestDoHRetryThenRejectedDialKeepsPerAttemptAttribution(t *testing.T) {
	instance, view, _ := newDNSTCPInspectionCore(t)
	store := instance.GetFeature(featurestats.ManagerType()).(featurestats.ObservationProvider).Observation()
	destination := dohDestination("127.0.0.1", "443")
	root := store.Begin(featurestats.FlowKindTCP, featurestats.TrafficOriginInternal, destination, destination, nil)
	observation := &dohRequestObservation{root: root, bodySize: 5, cancel: func() {}}
	route := newDoHRouteReceipt()
	route.Offer(featurestats.RouteStep{Selection: featurestats.SelectionDefault, Outbound: featurestats.OutboundRef{Serial: 81, Tag: "first"}})
	route.Commit()
	observation.gotConn(httptrace.GotConnInfo{Conn: &dohCarrierConn{Conn: new(dnsTCPCloseCountingConn), route: route}})
	observation.recordBodyRead(5)
	observation.reject(featurestats.RouteStep{Selection: featurestats.SelectionRejected, Outbound: featurestats.OutboundRef{Serial: 82, Tag: "rejected"}})
	observation.finish(false)

	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != 5 || page.Rows[0].Flow.AccountingRoute.Outbound.Serial != 82 || page.Rows[0].Reason != featurestats.EndReasonRejected {
		t.Fatalf("retry-rejection root: page=%+v err=%v", page, err)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var first, rejected bool
	for _, total := range totals.Rows {
		switch total.Outbound.Serial {
		case 81:
			first = total.Uplink.Known == 5 && total.Downlink.Known == 0 && total.Downlink.Incomplete
		case 82:
			rejected = total.Uplink.Known == 0 && total.Downlink.Known == 0 && total.Uplink.Incomplete && total.Downlink.Incomplete
		}
	}
	if !first || !rejected {
		t.Fatalf("retry-rejection totals: first=%v rejected=%v rows=%+v", first, rejected, totals.Rows)
	}
}

func newDoHLoopbackRejectionCore(t *testing.T) (*core.Instance, featurestats.FlowInspection, routing.Dispatcher) {
	t.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{
				{InboundTag: []string{"returned"}, TargetTag: &router.RoutingRule_Tag{Tag: "missing"}},
				{Networks: []xnet.Network{xnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "forward"}},
			}}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
			{Tag: "forward", ProxySettings: serial.ToTypedMessage(&loopback.Config{InboundTag: "returned"})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	view, err := core.EnableFlowInspection(instance, featurestats.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, view, instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
}

func TestRoutedDoHTLSLoopbackRejectionSurvivesHandshakeError(t *testing.T) {
	instance, view, routedDispatcher := newDoHLoopbackRejectionCore(t)
	endpoint, err := url.Parse("https://127.0.0.1:443/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewDoHNameServer(endpoint, routedDispatcher, false, true, false, 0, nil)
	ctx, cancel := context.WithTimeout(dnsTCPTestContext(instance), 10*time.Second)
	defer cancel()
	if response, requestErr := resolver.dohHTTPSContext(ctx, []byte("tls-rejected")); requestErr == nil || response != nil {
		t.Fatalf("TLS loopback rejection response=%q err=%v", response, requestErr)
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
	if row.Reason != featurestats.EndReasonRejected || row.Flow.AccountingRoute.Selection != featurestats.SelectionRejected || row.Flow.AccountingRoute.Outbound.Tag != "missing" || row.Flow.Uplink.Known != 0 || row.Flow.Downlink.Known != 0 || !row.Flow.Uplink.Incomplete || !row.Flow.Downlink.Incomplete {
		t.Fatalf("TLS loopback rejection facts: %+v", row)
	}
}
