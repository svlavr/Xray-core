package measurement_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
)

// Only the isolated B7 subprocess enables these test fixture hooks. The
// standalone profile suite retains its original setup and all its cases.
var (
	b7Enabled            bool
	b7ObservationOptions = fs.ObservationOptions{MaxLive: 64, MaxTerminals: 256, MaxBuckets: 16}
	b7Views              sync.Map // *core.Instance -> fs.FlowInspection
	b7UserMu             sync.Mutex
	b7UserObservation    *session.LogicalObservation
	b7UserRuntime        fs.RuntimeID
)

func b7View(v *core.Instance) fs.FlowInspection {
	if value, ok := b7Views.Load(v); ok {
		return value.(fs.FlowInspection)
	}
	return nil
}

func b7RememberOrdinary(ctx context.Context) {
	if !b7Enabled || session.TrafficOriginFromContext(ctx) != session.TrafficOriginUser {
		return
	}
	observation := session.LogicalObservationFromContext(ctx)
	if observation == nil || observation.Exchange == nil {
		return
	}
	b7UserMu.Lock()
	ref := observation.Exchange.Ref()
	if b7UserObservation == nil && ref.Runtime == b7UserRuntime && ref.ID != 0 {
		b7UserObservation = observation
	}
	b7UserMu.Unlock()
}

func b7InheritedOrdinary(t *testing.T) *session.LogicalObservation {
	t.Helper()
	b7UserMu.Lock()
	defer b7UserMu.Unlock()
	if b7UserObservation == nil {
		t.Fatal("native USER dispatch did not retain its real endpoint observation")
	}
	if ref := b7UserObservation.Exchange.Ref(); ref.Runtime != b7UserRuntime || ref.ID == 0 {
		t.Fatal("inherited USER observation belongs to another runtime")
	}
	return b7UserObservation
}

// The endpoint echo, rather than a dispatch count, supplies each expected
// decoded ordinary byte. DIRECT uses Go's net.Dialer and is excluded here.
type b7OrdinaryFacts struct {
	view          fs.FlowInspection
	want          fs.ClientTotals
	tags          map[string]fs.ClientTotals
	capture       fs.ObservationCapture
	lastAt        time.Duration
	minLiveUser   int
	nativeManager fs.Manager
	nativeStart   map[string]int64
	endpoints     []fs.FlowRecord
}

func b7BeginOrdinary(t *testing.T, v *core.Instance, exactUDP bool) *b7OrdinaryFacts {
	t.Helper()
	if !b7Enabled {
		return nil
	}
	view := b7View(v)
	if view == nil {
		t.Fatal("B7 instance lacks enabled inspection")
	}
	totals, err := view.ReadTotals()
	if err != nil || totals.User != (fs.ClientTotals{}) || len(totals.Rows) != 0 {
		t.Fatalf("cold Measurement contaminated USER totals: %+v %v", totals, err)
	}
	capture, err := view.CaptureObservations(2048)
	if err != nil {
		t.Fatal(err)
	}
	b7UserMu.Lock()
	b7UserObservation = nil
	b7UserRuntime = view.Runtime()
	b7UserMu.Unlock()
	b := &b7OrdinaryFacts{view: view, tags: make(map[string]fs.ClientTotals), capture: capture, lastAt: totals.At, minLiveUser: 2, nativeManager: v.GetFeature(fs.ManagerType()).(fs.Manager), nativeStart: make(map[string]int64)}
	if exactUDP {
		b.minLiveUser = 4
	}
	for _, tag := range []string{"exact", "second"} {
		for _, direction := range []string{"uplink", "downlink"} {
			name := "outbound>>>" + tag + ">>>traffic>>>" + direction
			counter := b.nativeManager.GetCounter(name)
			if counter == nil || counter.Value() <= 0 {
				t.Fatalf("cold controlled Measurement has no native %s bytes", name)
			}
			b.nativeStart[name] = counter.Value()
		}
	}
	return b
}

func (b *b7OrdinaryFacts) receipt(route measurement.Route, bytes int) {
	if b == nil || route.Kind == measurement.Direct {
		return
	}
	b.want.Uplink += uint64(bytes)
	b.want.Downlink += uint64(bytes)
	row := b.tags[route.Tag]
	row.Uplink += uint64(bytes)
	row.Downlink += uint64(bytes)
	b.tags[route.Tag] = row
}

func (b *b7OrdinaryFacts) endpoint(route measurement.Route, dest, source xnet.Destination) {
	if b != nil && route.Kind != measurement.Direct {
		b.endpoints = append(b.endpoints, fs.FlowRecord{Kind: dest.Network, Destination: dest, Source: source, Outbound: fs.OutboundRef{Tag: route.Tag}})
	}
}

func (b *b7OrdinaryFacts) checkUserEndpoint(t *testing.T, flow fs.FlowRecord, selected bool) {
	t.Helper()
	for _, want := range b.endpoints {
		if flow.Kind == want.Kind && flow.Destination == want.Destination && flow.Source == want.Source {
			if selected && flow.Outbound != want.Outbound {
				t.Fatalf("USER selection changed: want=%+v got=%+v", want, flow)
			}
			return
		}
	}
	t.Fatalf("USER source/destination did not match actual endpoint: %+v want=%+v", flow, b.endpoints)
}

func b7HTTPDestination(raw string) xnet.Destination {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	dest, err := xnet.ParseDestination("tcp:" + u.Host)
	if err != nil {
		panic(err)
	}
	return dest
}

func fsB7Expected(dest xnet.Destination, tag string) fs.FlowRecord {
	return fs.FlowRecord{Kind: dest.Network, Destination: dest, Outbound: fs.OutboundRef{Tag: tag}}
}

func (b *b7OrdinaryFacts) check(t *testing.T, held bool) {
	if b == nil {
		return
	}
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		totals, err := b.view.ReadTotals()
		if err != nil {
			t.Fatal(err)
		}
		if totals.At < b.lastAt || totals.BucketsOmitted != 0 {
			t.Fatalf("B7 freshness or bucket loss: %+v", totals)
		}
		b.lastAt = totals.At
		found := make(map[string]fs.ClientTotals)
		for _, row := range totals.Rows {
			if row.Origin != fs.TrafficOriginUser {
				t.Fatalf("selected total has non-USER origin: %+v", row)
			}
			found[row.Outbound.Tag] = fs.ClientTotals{Uplink: row.Uplink, Downlink: row.Downlink}
		}
		if totals.User == b.want {
			matched := len(found) == len(b.tags)
			for tag, want := range b.tags {
				matched = matched && found[tag] == want
			}
			if matched {
				if held {
					b.checkLive(t)
				}
				return
			}
		}
		if totals.User.Uplink > b.want.Uplink || totals.User.Downlink > b.want.Downlink || time.Now().After(deadline) {
			t.Fatalf("ordinary receipt/USER totals mismatch: want=%+v tags=%+v got=%+v", b.want, b.tags, totals)
		}
		time.Sleep(time.Millisecond)
	}
}

func (b *b7OrdinaryFacts) checkLive(t *testing.T, expected ...fs.FlowRecord) {
	t.Helper()
	live, err := b.view.ReadLiveInto(nil)
	if err != nil {
		t.Fatal(err)
	}
	var user, controlled int
	matched := len(expected) == 0
	for _, row := range live.Rows {
		if row.Ref.Runtime != b.view.Runtime() || row.Ref.ID == 0 {
			t.Fatalf("live row lacks exact local reference: %+v", row)
		}
		switch row.Origin {
		case fs.TrafficOriginUser:
			user++
			b.checkUserEndpoint(t, row, true)
			if row.Outbound.Tag != "exact" && row.Outbound.Tag != "second" {
				t.Fatalf("ordinary live row lost selected tag: %+v", row)
			}
			if !row.Destination.IsValid() {
				t.Fatalf("ordinary live row lost destination: %+v", row)
			}
		case fs.TrafficOriginControlledMeasurement:
			controlled++
			if row.Source.IsValid() {
				t.Fatalf("controlled operation inherited USER source: %+v", row)
			}
			for _, want := range expected {
				matched = matched || row.Kind == want.Kind && row.Destination == want.Destination && row.Outbound == want.Outbound
			}
		default:
			t.Fatalf("unexpected live origin: %+v", row)
		}
	}
	if user < b.minLiveUser || controlled == 0 || !matched {
		t.Fatalf("held Measurement/USER overlap absent: user=%d controlled=%d live=%+v", user, controlled, live)
	}
}

func (b *b7OrdinaryFacts) finish(t *testing.T, connections []net.Conn) {
	if b == nil {
		return
	}
	t.Helper()
	for _, c := range connections {
		c.Close()
	}
	b.check(t, false)
	for name, start := range b.nativeStart {
		counter := b.nativeManager.GetCounter(name)
		if counter == nil || counter.Value() <= start {
			t.Fatalf("mixed-origin native bytes did not advance for %s: initial=%d current=%v", name, start, counter)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		live, err := b.view.ReadLiveInto(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B7 residual live roots after caller flow close: %+v", live)
		}
		time.Sleep(time.Millisecond)
	}
	terminals, err := b.view.ReadTerminals()
	if err != nil || terminals.Overwritten != 0 {
		t.Fatalf("B7 terminal loss: %+v %v", terminals, err)
	}
	var user, controlled int
	for _, row := range terminals.Rows {
		switch row.Flow.Origin {
		case fs.TrafficOriginUser:
			user++
			b.checkUserEndpoint(t, row.Flow, true)
		case fs.TrafficOriginControlledMeasurement:
			controlled++
		default:
			t.Fatalf("terminal origin: %+v", row)
		}
	}
	if user < b.minLiveUser || controlled == 0 {
		t.Fatalf("B7 terminal origins user=%d controlled=%d", user, controlled)
	}
	if err := b.capture.Close(); err != nil {
		t.Fatal(err)
	}
	var seenUser, seenControlled bool
	for {
		batch := b.capture.ReadInto(nil)
		if batch.Dropped != 0 || !batch.ExistingPartial {
			t.Fatalf("B7 unexpected capture loss: %+v", batch)
		}
		for _, row := range batch.Rows {
			if row.Flow.Origin == fs.TrafficOriginUser {
				b.checkUserEndpoint(t, row.Flow, row.Selected)
			}
			seenUser = seenUser || row.Flow.Origin == fs.TrafficOriginUser
			seenControlled = seenControlled || row.Flow.Origin == fs.TrafficOriginControlledMeasurement
			if row.FlowID == 0 || row.Flow.Ref.Runtime != b.view.Runtime() {
				t.Fatalf("capture identity/runtime: %+v", row)
			}
		}
		if batch.Stopped && len(batch.Rows) == 0 {
			break
		}
	}
	if !seenUser || !seenControlled {
		t.Fatalf("capture missed mixed origin: user=%t controlled=%t", seenUser, seenControlled)
	}
}

func TestB7CombinedProfiles(t *testing.T) {
	if isolatedSystemDialer(t, 12*time.Minute) {
		return
	}
	b7Enabled = true
	defer func() { b7Enabled = false }()
	witness := &carrierDialWitness{sockets: make(map[string][]carrierDialRecord), muxSockets: make(map[string][]carrierDialRecord), uploads: make(map[string]map[string]int)}
	internet.UseAlternativeSystemDialer(witness)
	// Native and Vision have independent socket owners; no pooled-socket
	// assertion is appropriate for them.
	t.Run("native", TestNativeProtocolMeasurements)
	t.Run("additional", TestAdditionalProtocolMeasurements)
	t.Run("vision", TestVisionProfileMeasurements)
	t.Run("freedom", TestFreedomProtocolMeasurements)
	carrierDials = witness
	defer func() { carrierDials = nil }()
	t.Run("sender", TestSenderMUXProfileMeasurements)
	t.Run("transport", TestTransportProfileMeasurements)
	t.Run("grpc-multi", func(t *testing.T) {
		stream := func() *internet.StreamConfig {
			return &internet.StreamConfig{ProtocolName: "grpc", TransportSettings: []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&grpc.Config{ServiceName: "b7-multi", MultiMode: true})}}}
		}
		e, v, counters := plainProtocolExecutor(t, "vless", func(inbound *core.InboundHandlerConfig, outbound *core.OutboundHandlerConfig) {
			profileStreams(t, inbound, outbound, stream(), stream())
		})
		testProtocolMeasurements(t, e, v, counters)
	})
	t.Run("hysteria", TestHysteriaMeasurementSeriesAndUDPCancellation)
	t.Run("wireguard", TestWireGuardProtocolMeasurements)
}

// These modes use one native Freedom instance each. The no-store case relies
// on core's normal NoopManager installation when the stats app is omitted.
func TestB7ObservationModes(t *testing.T) {
	for _, mode := range []string{"no-store", "inspection-off", "enabled-sufficient", "enabled-constrained"} {
		t.Run(mode, func(t *testing.T) { b7ObservationMode(t, mode) })
	}
}

func b7ObservationMode(t *testing.T, mode string) {
	t.Helper()
	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	if mode != "no-store" {
		apps = append(apps, serial.ToTypedMessage(&appstats.Config{}))
	}
	v, err := core.New(&core.Config{App: apps, Outbound: []*core.OutboundHandlerConfig{config("trap", true), config("exact", false), config("second", false)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	manager := v.GetFeature(fs.ManagerType()).(fs.Manager)
	provider, hasStore := manager.(fs.ObservationProvider)
	if mode == "no-store" {
		if hasStore {
			t.Fatal("default no-store manager exposed an observation provider")
		}
	} else if !hasStore || provider.Observation() != nil {
		t.Fatal("stats manager before Start has an unexpected store state")
	}
	var view fs.FlowInspection
	if mode == "enabled-sufficient" || mode == "enabled-constrained" {
		options := fs.ObservationOptions{MaxLive: 16, MaxTerminals: 32, MaxBuckets: 4}
		if mode == "enabled-constrained" {
			options = fs.ObservationOptions{MaxLive: 1, MaxTerminals: 1, MaxBuckets: 1}
		}
		view, err = core.EnableFlowInspection(v, options)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	if mode == "inspection-off" && provider.Observation() != nil {
		t.Fatal("disabled inspection unexpectedly admitted a store")
	}
	var capture fs.ObservationCapture
	if view != nil {
		capacity := uint32(64)
		if mode == "enabled-constrained" {
			capacity = 1
		}
		capture, err = view.CaptureObservations(capacity)
		if err != nil {
			t.Fatal(err)
		}
		defer capture.Close()
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	var serverWorkers sync.WaitGroup
	go func() {
		defer close(serverDone)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			serverWorkers.Add(1)
			go func() { defer serverWorkers.Done(); defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	defer func() {
		listener.Close()
		<-serverDone
		joined := make(chan struct{})
		go func() { serverWorkers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("mode fixture retained TCP workers after caller close")
		}
	}()
	packet := udpFixture(t, func(pc net.PacketConn, payload []byte, addr net.Addr) { _, _ = pc.WriteTo(payload, addr) })
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var ordinary []net.Conn
	var want fs.ClientTotals
	for _, item := range []struct{ tag, network, address string }{
		{"exact", "tcp", listener.Addr().String()},
		{"second", "udp", packet.LocalAddr().String()},
	} {
		ctx := session.ContextWithTrafficOrigin(session.SetForcedOutboundTagToContext(ctx, item.tag), session.TrafficOriginUser)
		dest, err := xnet.ParseDestination(item.network + ":" + item.address)
		if err != nil {
			t.Fatal(err)
		}
		c, err := core.Dial(ctx, v, dest)
		if err != nil {
			t.Fatal(err)
		}
		ordinary = append(ordinary, c)
	}
	defer func() {
		for _, c := range ordinary {
			c.Close()
		}
	}()
	pulse := func() {
		t.Helper()
		for index, c := range ordinary {
			payload := []byte(fmt.Sprintf("ordinary-mode-%d-%d", index, want.Uplink))
			done := make(chan error, 1)
			go func() {
				n, err := c.Write(payload)
				if err == nil && n != len(payload) {
					err = io.ErrShortWrite
				}
				if err == nil {
					received := make([]byte, len(payload))
					_, err = io.ReadFull(c, received)
					if err == nil && string(received) != string(payload) {
						err = fmt.Errorf("wrong ordinary echo: %q", received)
					}
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				c.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("ordinary echo worker failed to join")
				}
				t.Fatal("ordinary mode echo stalled")
			}
			want.Uplink += uint64(len(payload))
			want.Downlink += uint64(len(payload))
		}
		if view != nil {
			deadline := time.Now().Add(2 * time.Second)
			for {
				totals, err := view.ReadTotals()
				if err != nil {
					t.Fatal(err)
				}
				if totals.User == want {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("mode USER bytes want=%+v got=%+v", want, totals)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	pulse()
	entered, release := make(chan struct{}), make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "12")
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		close(entered)
		select {
		case <-release:
			_, _ = io.WriteString(w, "suffix")
		case <-r.Context().Done():
		}
	}))
	defer peer.Close()
	e := executor(t, v)
	r := measurement.HTTPRequest{Route: measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"}, URL: peer.URL, Timeout: 5 * time.Second, MaxBodyBytes: 128, MaxHeaderBytes: 4096}
	measured, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { _, err := e.HTTP(measured, http.MethodGet, r); finished <- err }()
	select {
	case <-entered:
	case err := <-finished:
		t.Fatalf("mode measurement ended before overlap: %v", err)
	case <-ctx.Done():
		t.Fatal("mode measurement did not reach endpoint")
	}
	pulse()
	stop()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("mode measurement cancellation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("mode measurement cancellation did not join")
	}
	close(release)
	pulse()
	success := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "complete") }))
	defer success.Close()
	r.URL = success.URL
	if got, err := e.HTTP(ctx, http.MethodGet, r); err != nil || !got.BodyComplete || string(got.Body) != "complete" {
		t.Fatalf("mode successful Measurement: %+v %v", got, err)
	}
	pulse()
	udp := udpRequest(packet.LocalAddr(), measurement.ExactOutbound)
	udp.Route.Tag, udp.Count, udp.Interval = "second", 1, 0
	if got, err := e.UDPEcho(ctx, udp); err != nil || !got.WindowComplete || len(got.Replies) != 1 || got.Replies[0].Issue != measurement.UDPReplyValid {
		t.Fatalf("mode UDP Measurement: %+v %v", got, err)
	}
	pulse()
	if view != nil {
		totals, err := view.ReadTotals()
		if err != nil || totals.User != want {
			t.Fatalf("controlled mode traffic entered USER totals: %+v %v", totals, err)
		}
		batch := capture.ReadInto(nil)
		if !batch.ExistingPartial {
			t.Fatal("capture claimed a complete pre-start inventory")
		}
		if mode == "enabled-constrained" {
			terminals, err := view.ReadTerminals()
			if err != nil || batch.Dropped == 0 || totals.BucketsOmitted == 0 || terminals.Overwritten == 0 {
				t.Fatalf("constrained loss was hidden: capture=%+v totals=%+v terminals=%+v err=%v", batch, totals, terminals, err)
			}
		} else if batch.Dropped != 0 || totals.BucketsOmitted != 0 {
			t.Fatalf("sufficient mode lost facts: %+v %+v", batch, totals)
		}
	}
}
