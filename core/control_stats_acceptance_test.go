package core_test

import (
	"bytes"
	"context"
	"errors"
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

func acceptanceCore(tb testing.TB, enabled bool) (*core.Instance, fs.FlowInspection) {
	tb.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&applog.Config{ErrorLogType: applog.LogType_None, AccessLogType: applog.LogType_None}),
			serial.ToTypedMessage(&appstats.Config{}),
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
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
				mu.Lock()
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
	})
	return xnet.DestinationFromAddr(listener.Addr())
}

func acceptanceExchange(tb testing.TB, ctx context.Context, instance *core.Instance, dest xnet.Destination, payload, response []byte) stdnet.Conn {
	tb.Helper()
	conn, err := core.Dial(ctx, instance, dest)
	if err != nil {
		tb.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		tb.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		_ = conn.Close()
		tb.Fatalf("write %d: %v", n, err)
	}
	if _, err := io.ReadFull(conn, response); err != nil {
		_ = conn.Close()
		tb.Fatal(err)
	}
	if !bytes.Equal(payload, response) {
		_ = conn.Close()
		tb.Fatal("echo payload mismatch")
	}
	return conn
}

func TestControlStatsP5DirectViewsResetAndNewRuntime(t *testing.T) {
	destination := acceptanceEcho(t)
	instance, view := acceptanceCore(t, true)
	ctx := context.Background()
	payload := []byte("direct-Go origin and total facts")
	origins := []fs.TrafficOrigin{fs.TrafficOriginUnknown, fs.TrafficOriginUser, fs.TrafficOriginInternal, fs.TrafficOriginControlledMeasurement}
	var connections []stdnet.Conn
	for _, origin := range origins {
		connections = append(connections, acceptanceExchange(t, session.ContextWithTrafficOrigin(ctx, origin), instance, destination, payload, make([]byte, len(payload))))
	}
	t.Cleanup(func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	live, err := view.ReadLive(ctx)
	if err != nil || len(live.Rows) != len(origins) {
		t.Fatalf("live: %+v %v", live, err)
	}
	var userRef fs.FlowRef
	seen := make(map[fs.TrafficOrigin]bool)
	for _, row := range live.Rows {
		if row.State != fs.FlowStateOpen || row.Kind != fs.FlowKindTCP || row.InitialDestination != destination || row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) || row.AccountingRoute.Outbound.Tag != "direct" {
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
	totals, err := view.ReadTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range origins {
		var up, down uint64
		for _, row := range totals.Rows {
			if row.Origin == origin {
				up += row.Uplink.Known
				down += row.Downlink.Known
			}
		}
		if up != uint64(len(payload)) || down != up {
			t.Fatalf("origin %v totals %d/%d", origin, up, down)
		}
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
	after, err := view.ReadTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keyed := func(rows []fs.TotalRecord) map[[2]uint64]fs.TotalRecord {
		result := make(map[[2]uint64]fs.TotalRecord)
		for _, row := range rows {
			result[[2]uint64{row.Outbound.Serial, uint64(row.Origin)}] = row
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
	if err != nil || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("exact API stop: %+v %v", outcomes, err)
	}
	remaining, err := view.ReadLive(ctx)
	if err != nil || len(remaining.Rows) != 3 {
		t.Fatalf("sibling live rows: %+v %v", remaining, err)
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	ended, err := view.ReadTerminals(ctx)
	if err != nil || len(ended.Rows) != 4 {
		t.Fatalf("terminals: %+v %v", ended, err)
	}
	for _, row := range ended.Rows {
		if row.Flow.Uplink.Known != uint64(len(payload)) || row.Flow.Downlink.Known != uint64(len(payload)) {
			t.Fatalf("terminal facts: %+v", row)
		}
	}
	// Sequential instance construction avoids relying on process-global dialer selection.
	oldRuntime := view.Info().Runtime
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, newView := acceptanceCore(t, true)
	if newView.Info().Runtime == oldRuntime {
		t.Fatal("new runtime reused identity")
	}
	empty, err := newView.ReadLive(ctx)
	if err != nil || len(empty.Rows) != 0 {
		t.Fatal("new runtime inherited live data")
	}
	newTotals, err := newView.ReadTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range newTotals.Rows {
		if row.Uplink.Known != 0 || row.Downlink.Known != 0 {
			t.Fatal("new runtime inherited totals")
		}
	}
	stale, err := newView.CloseFlows(ctx, []fs.FlowRef{userRef})
	if err != nil || stale[0].Code != fs.CloseCodeStaleRuntime {
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
	_, liveErr := view.ReadLive(ctx)
	_, terminalErr := view.ReadTerminals(ctx)
	_, totalErr := view.ReadTotals(ctx)
	_, closeErr := view.CloseFlows(ctx, nil)
	for _, err := range []error{liveErr, terminalErr, totalErr, closeErr} {
		if !errors.Is(err, fs.ErrInspectionClosed) {
			t.Fatalf("closed API error: %v", err)
		}
	}
	if !view.Info().Closed || provider.Observation() != nil {
		t.Fatal("closed provider still admits")
	}
	if store.Begin(fs.FlowKindTCP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil) != nil || store.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil) != nil {
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
	serial, ok := outboundType.FieldByName("nextSerial")
	if !ok {
		t.Fatal("handler incarnation counter missing")
	}
	entryType := tagged.Type.Elem().Elem()
	originCtx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	t.Logf("disabled static fields: handler entry=%d bytes, inventory reference=%d, manager serial=%d, nullable inspection pointer=%d; origin context object=%d bytes (created outside exchange benchmark timer)", entryType.Size(), tagged.Type.Elem().Size(), serial.Type.Size(), inspection.Type.Size(), reflect.TypeOf(originCtx).Elem().Size())
}

func BenchmarkControlStatsP5TCPExchange(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
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
		})
	}
}
