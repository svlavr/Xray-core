package measurement_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
)

func TestM3LuaRoutingPreservesMeasurementExactDirectAndIsolation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint("inspection=", enabled), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "route.lua")
			if err := os.WriteFile(path, []byte(`function HandleRoute(...) error("ordinary Lua route trap") end`), 0o600); err != nil {
				t.Fatal(err)
			}
			apps := []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&router.Config{Script: path})}
			if enabled {
				apps = append(apps, serial.ToTypedMessage(&appstats.Config{}))
			}
			v, err := core.New(&core.Config{App: apps, Outbound: []*core.OutboundHandlerConfig{config("trap", true), config("exact", false)}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			var view fs.FlowInspection
			if enabled {
				view, err = core.EnableFlowInspection(v, fs.ObservationOptions{MaxLive: 16, MaxTerminals: 16, MaxBuckets: 8})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := v.Start(); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write([]byte("exact")) }))
			defer peer.Close()
			e := executor(t, v)
			ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
			ctx = session.ContextWithContent(ctx, &session.Content{Attributes: map[string]string{"forcedOutboundTag": "trap"}})
			for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
				r, err := e.HTTPS(ctx, request(peer, kind))
				if err != nil || string(r.Body) != "exact" {
					t.Fatalf("route %v under configured Lua: %+v %v", kind, r, err)
				}
			}
			missing := request(peer, measurement.ExactOutbound)
			missing.Route.Tag = "missing"
			if _, err := e.HTTPS(ctx, missing); err == nil {
				t.Fatal("missing exact tag fell back")
			}
			if calls.Load() != 2 {
				t.Fatalf("unexpected routing/fallback: peer requests=%d", calls.Load())
			}
			if view != nil {
				totals, err := view.ReadTotals()
				if err != nil || totals.User != (fs.ClientTotals{}) || len(totals.Rows) != 0 {
					t.Fatalf("controlled work entered USER totals: %+v %v", totals, err)
				}
			}
		})
	}
}
