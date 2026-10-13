package core_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	stdnet "net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	fs "github.com/xtls/xray-core/features/stats"
)

var controlStatsDiagnostics = flag.Bool("control-stats-diagnostics", false, "record outbound and echo errors in control/statistics fixtures")

func acceptanceCore(tb testing.TB, enabled bool) (*core.Instance, fs.FlowInspection) {
	tb.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&applog.Config{ErrorLogType: applog.LogType_None, AccessLogType: applog.LogType_None}),
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{inspectionFreedom("direct")},
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := instance.Close(); err != nil {
			tb.Error(err)
		}
	})
	var view fs.FlowInspection
	if enabled {
		view, err = core.EnableFlowInspection(instance, fs.ObservationOptions{})
		if err != nil {
			tb.Fatal(err)
		}
	}
	if err := instance.Start(); err != nil {
		tb.Fatal(err)
	}
	return instance, view
}

func acceptanceEcho(tb testing.TB) xnet.Destination {
	tb.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	accepted := make(chan struct{})
	var mu sync.Mutex
	var workers sync.WaitGroup
	connections := make(map[stdnet.Conn]struct{})
	closing := false
	var copyError error
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			connections[conn] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				_, err := io.Copy(conn, conn)
				_ = conn.Close()
				mu.Lock()
				if *controlStatsDiagnostics && err != nil && !closing && !errors.Is(err, stdnet.ErrClosed) && copyError == nil {
					copyError = err
				}
				delete(connections, conn)
				mu.Unlock()
			}()
		}
	}()
	tb.Cleanup(func() {
		mu.Lock()
		closing = true
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		_ = listener.Close()
		<-accepted
		workers.Wait()
		if copyError != nil {
			tb.Logf("echo copy error before fixture shutdown: %v", copyError)
		}
	})
	return xnet.DestinationFromAddr(listener.Addr())
}

type acceptanceOutboundError struct {
	mu  sync.Mutex
	err error
}

func (e *acceptanceOutboundError) SubmitError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err == nil {
		e.err = err
	}
}

func (e *acceptanceOutboundError) value() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

func acceptanceExchange(tb testing.TB, ctx context.Context, instance *core.Instance, dest xnet.Destination, payload, response []byte) stdnet.Conn {
	tb.Helper()
	var tracker *acceptanceOutboundError
	if *controlStatsDiagnostics {
		tracker = new(acceptanceOutboundError)
		ctx = session.TrackedConnectionError(ctx, tracker)
	}
	conn := controlNativeDialContext(tb, ctx, instance, dest)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		tb.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		_ = conn.Close()
		tb.Fatalf("write %d/%d to %v: %v; outbound=%v", n, len(payload), dest, err, tracker.value())
	}
	if n, err := io.ReadFull(conn, response); err != nil {
		_ = conn.Close()
		tb.Fatalf("read %d/%d from %v: %v; outbound=%v", n, len(response), dest, err, tracker.value())
	}
	if !bytes.Equal(payload, response) {
		_ = conn.Close()
		tb.Fatal("echo payload mismatch")
	}
	return conn
}

func TestControlStatsNativeTotalsBeyondLiveCapacity(t *testing.T) {
	destination := acceptanceEcho(t)
	instance, view := acceptanceCore(t, true)

	ctx := session.ContextWithTrafficOrigin(context.Background(), fs.TrafficOriginUser)
	payload := []byte("capacity")
	connections := make([]stdnet.Conn, 0, 257)
	t.Cleanup(func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	for range 257 {
		connections = append(connections, acceptanceExchange(t, ctx, instance, destination, payload, make([]byte, len(payload))))
	}
	inspectionWait(t, func() bool {
		totals, err := view.ReadTotals()
		return err == nil && totals.User == (fs.ClientTotals{Uplink: uint64(257 * len(payload)), Downlink: uint64(257 * len(payload))})
	})
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 256 {
		t.Fatalf("default live capacity: rows=%d err=%v", len(live.Rows), err)
	}

	refs := make([]fs.FlowRef, 0, len(live.Rows))
	for _, row := range live.Rows {
		refs = append(refs, row.Ref)
	}
	outcomes, err := view.CloseFlows(ctx, refs)
	if err != nil || len(outcomes) != len(refs) {
		t.Fatalf("indexed close: outcomes=%d err=%v", len(outcomes), err)
	}
	for _, err := range outcomes {
		if err != nil {
			t.Fatal(err)
		}
	}
	// The unindexed last connection remains usable after closing the saved set.
	last := connections[len(connections)-1]
	if n, err := last.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("unindexed sibling write: %d %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(last, response); err != nil || !bytes.Equal(payload, response) {
		t.Fatalf("unindexed sibling response: %v", err)
	}
	for _, conn := range connections {
		_ = conn.Close()
	}

	want := uint64(258 * len(payload))
	inspectionWait(t, func() bool {
		totals, err := view.ReadTotals()
		return err == nil && totals.User == (fs.ClientTotals{Uplink: want, Downlink: want})
	})
	totals, err := view.ReadTotals()
	if err != nil || totals.User != (fs.ClientTotals{Uplink: want, Downlink: want}) {
		t.Fatalf("capacity-independent general USER bytes: %+v err=%v", totals, err)
	}
}

func TestControlStatsP5DirectViewsResetAndNewRuntime(t *testing.T) {
	destination := acceptanceEcho(t)
	instance, view := acceptanceCore(t, true)
	ctx := context.Background()
	payload := []byte("direct-Go origin and total facts")
	origins := []fs.TrafficOrigin{fs.TrafficOriginUnknown, fs.TrafficOriginUser, fs.TrafficOriginInternal, fs.TrafficOriginControlledMeasurement}
	// Non-USER admission vocabulary is a store contract. USER byte/control
	// coverage comes from a real native ingress, not a direct API root.
	store := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation()
	var roots []fs.Exchange
	for _, origin := range origins {
		if origin == fs.TrafficOriginUser {
			continue
		}
		root := store.PrepareTCP(origin, xnet.Destination{}, destination, nil)
		root.Route(fs.OutboundRef{Tag: "direct"})
		root.AddUplink(uint64(len(payload)))
		root.AddDownlink(uint64(len(payload)))
		roots = append(roots, root)
	}
	t.Cleanup(func() {
		for _, root := range roots {
			root.Finish()
		}
	})
	connections := []stdnet.Conn{acceptanceExchange(t, ctx, instance, destination, payload, make([]byte, len(payload)))}
	inspectionWait(t, func() bool {
		totals, err := view.ReadTotals()
		return err == nil && totals.User == (fs.ClientTotals{Uplink: uint64(len(payload)), Downlink: uint64(len(payload))})
	})
	t.Cleanup(func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != len(origins) {
		t.Fatalf("live: %+v %v", live, err)
	}
	var userRef fs.FlowRef
	seen := make(map[fs.TrafficOrigin]bool)
	for _, row := range live.Rows {
		if row.Kind != xnet.Network_TCP || row.Destination != destination || row.Uplink != uint64(len(payload)) || row.Downlink != uint64(len(payload)) || row.Outbound.Tag != "direct" {
			t.Fatalf("live facts: %+v", row)
		}
		seen[row.Origin] = true
		if row.Origin == fs.TrafficOriginUser {
			userRef = row.Ref
		}
	}
	if len(seen) != len(origins) {
		t.Fatalf("origins collapsed: %+v", seen)
	}
	totals, err := view.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range origins {
		var up, down uint64
		for _, row := range totals.Rows {
			if row.Origin == origin {
				up += row.Uplink
				down += row.Downlink
			}
		}
		want := uint64(0)
		if origin == fs.TrafficOriginUser {
			want = uint64(len(payload))
		}
		if up != want || down != up {
			t.Fatalf("origin %v totals %d/%d", origin, up, down)
		}
	}
	if totals.User != (fs.ClientTotals{Uplink: uint64(len(payload)), Downlink: uint64(len(payload))}) || len(totals.Rows) != 1 {
		t.Fatalf("general USER total: %+v", totals)
	}
	manager := instance.GetFeature(fs.ManagerType()).(fs.Manager)
	native, err := manager.RegisterCounter("acceptance-native-reset")
	if err != nil {
		t.Fatal(err)
	}
	native.Add(77)
	// StatsService's native reset uses Counter.Set(0); it has no logical-store reset.
	if old := native.Set(0); old != 77 || native.Value() != 0 {
		t.Fatal("native reset failed")
	}
	after, err := view.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	if after.User != totals.User || after.BucketsOmitted != totals.BucketsOmitted {
		t.Fatal("native reset changed general USER totals/coverage")
	}
	keyed := func(rows []fs.TotalRecord) map[struct {
		tag    string
		origin fs.TrafficOrigin
	}]fs.TotalRecord {
		result := make(map[struct {
			tag    string
			origin fs.TrafficOrigin
		}]fs.TotalRecord)
		for _, row := range rows {
			result[struct {
				tag    string
				origin fs.TrafficOrigin
			}{row.Outbound.Tag, row.Origin}] = row
		}
		return result
	}
	beforeRows, afterRows := keyed(totals.Rows), keyed(after.Rows)
	if len(beforeRows) != len(afterRows) {
		t.Fatal("native reset changed logical buckets")
	}
	for key, row := range beforeRows {
		if afterRows[key] != row {
			t.Fatalf("native reset changed logical totals: %+v", key)
		}
	}
	outcomes, err := view.CloseFlows(ctx, []fs.FlowRef{userRef})
	if err != nil || outcomes[0] != nil {
		t.Fatalf("exact native stop: %+v %v", outcomes, err)
	}
	inspectionWait(t, func() bool { live, err := view.ReadLiveInto(nil); return err == nil && len(live.Rows) == 3 })
	remaining, err := view.ReadLiveInto(nil)
	if err != nil || len(remaining.Rows) != 3 {
		t.Fatalf("sibling live rows: %+v %v", remaining, err)
	}
	for _, conn := range connections {
		_ = conn.Close()
	}

	// Sequential instance construction avoids relying on process-global dialer selection.
	oldRuntime := view.Runtime()
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, newView := acceptanceCore(t, true)
	if newView.Runtime() == oldRuntime {
		t.Fatal("new runtime reused identity")
	}
	empty, err := newView.ReadLiveInto(nil)
	if err != nil || len(empty.Rows) != 0 {
		t.Fatal("new runtime inherited live data")
	}
	newTotals, err := newView.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	if newTotals.User != (fs.ClientTotals{}) || newTotals.BucketsOmitted != 0 {
		t.Fatal("new runtime inherited general totals/coverage")
	}
	for _, row := range newTotals.Rows {
		if row.Uplink != 0 || row.Downlink != 0 {
			t.Fatal("new runtime inherited totals")
		}
	}
	stale, err := newView.CloseFlows(ctx, []fs.FlowRef{userRef})
	if err != nil || stale[0] != nil {
		t.Fatalf("stale ref: %+v %v", stale, err)
	}
	_ = fresh
}

func TestControlStatsP5ClosedDirectSurface(t *testing.T) {
	instance, view := acceptanceCore(t, true)
	provider := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider)
	store := provider.Observation()
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := view.ReadLiveInto(nil); err == nil {
		t.Fatal("closed live read succeeded")
	}
	if _, err := view.ReadTotals(); err == nil {
		t.Fatal("closed totals read succeeded")
	}
	if _, err := view.CloseFlows(ctx, nil); err == nil {
		t.Fatal("closed flow control succeeded")
	}

	if provider.Observation() != nil {
		t.Fatal("closed provider still admits")
	}
	if store.Begin(xnet.Network_TCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil) != nil || store.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil) != nil {
		t.Fatal("retained store admitted after close")
	}
}

func TestControlStatsP5DisabledStaticFootprint(t *testing.T) {
	instance, _ := acceptanceCore(t, false)
	manager := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider)
	if manager.Observation() != nil {
		t.Fatal("disabled inspection allocated a store")
	}
	statsType := reflect.TypeOf(manager).Elem()
	inspection, ok := statsType.FieldByName("inspection")
	if !ok {
		t.Fatal("statistics owner field missing")
	}
	outboundType := reflect.TypeOf(instance.GetFeature(fout.ManagerType())).Elem()
	tagged, ok := outboundType.FieldByName("taggedHandler")
	if !ok {
		t.Fatal("native handler inventory missing")
	}
	if _, ok := outboundType.FieldByName("nextSerial"); ok {
		t.Fatal("removed handler serial counter retained")
	}
	if tagged.Type.Elem() != reflect.TypeFor[fout.Handler]() {
		t.Fatal("native handler inventory gained an entry wrapper")
	}
	originCtx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	t.Logf("disabled static fields: native handler interface=%d bytes, nullable inspection pointer=%d; origin context object=%d bytes (outside exchange timer)", tagged.Type.Elem().Size(), inspection.Type.Size(), reflect.TypeOf(originCtx).Elem().Size())
}

func BenchmarkControlStatsP5TCPExchange(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		if !b.Run(name, func(b *testing.B) {
			destination := acceptanceEcho(b)
			instance, _ := acceptanceCore(b, enabled)
			payload, response := bytes.Repeat([]byte{0x5a}, 1024), make([]byte, 1024)
			ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
			b.ReportAllocs()
			b.SetBytes(2048)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				conn := acceptanceExchange(b, ctx, instance, destination, payload, response)
				if err := conn.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		}) {
			b.Fail()
		}
	}
}
