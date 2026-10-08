package measurement_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
)

// This boundary regression uses the actual dispatcher and observation owner.
// Concurrent combined USER/Measurement acceptance remains a separate matrix.
func TestMeasurementInheritedObservationIsolation(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "measurement-payload")
	}))
	defer peer.Close()
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&appstats.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{config("trap", true), config("exact", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	view, err := core.EnableFlowInspection(v, fs.ObservationOptions{MaxLive: 8, MaxTerminals: 8, MaxBuckets: 8})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	store := v.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation()
	parent := store.PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.TCPDestination(xnet.DomainAddress("caller.invalid"), 443), nil)
	parent.Unassign()
	parent.AddUplink(11)
	parent.AddDownlink(13)
	defer parent.Finish()
	parentRef := parent.Ref()
	observation := &session.LogicalObservation{Exchange: parent, InputAtExecution: true}
	observation.ReturnedLink.Store(true)
	inbound := &session.Inbound{User: &protocol.MemoryUser{Email: "ordinary"}}
	outbound := &session.Outbound{Tag: "caller-tag"}
	content := &session.Content{Attributes: map[string]string{"forcedOutboundTag": "trap"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	ctx = session.ContextWithLogicalObservation(ctx, observation)
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	e := executor(t, v)
	r := measurement.HTTPRequest{Route: measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"},
		URL: peer.URL, Timeout: 5 * time.Second, MaxBodyBytes: 128, MaxHeaderBytes: 4096}
	got, err := e.HTTP(ctx, http.MethodGet, r)
	if err != nil || !got.BodyComplete || string(got.Body) != "measurement-payload" {
		t.Fatalf("exact native request: %+v %v", got, err)
	}
	var terminal fs.TerminalSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for {
		terminal, err = view.ReadTerminals()
		if err != nil {
			t.Fatal(err)
		}
		if len(terminal.Rows) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing independent measurement completion: %+v", terminal)
		}
		time.Sleep(time.Millisecond)
	}
	flow := terminal.Rows[0].Flow
	if flow.Ref == parentRef || flow.Origin != fs.TrafficOriginControlledMeasurement || flow.Outbound.Tag != "exact" || flow.Downlink == 0 {
		t.Fatalf("measurement continued caller exchange or lost its own facts: %+v", flow)
	}
	r.Route = measurement.Route{Kind: measurement.Direct}
	got, err = e.HTTP(ctx, http.MethodGet, r)
	if err != nil || string(got.Body) != "measurement-payload" {
		t.Fatalf("DIRECT request inherited caller route: %+v %v", got, err)
	}
	parent.Finish()
	terminal, err = view.ReadTerminals()
	if err != nil || len(terminal.Rows) != 2 {
		t.Fatalf("DIRECT created a core flow or parent was lost: %+v %v", terminal, err)
	}
	var found bool
	for _, row := range terminal.Rows {
		if row.Flow.Ref == parentRef {
			found = true
			if row.Flow.Origin != fs.TrafficOriginUser || row.Flow.Outbound.Tag != "" || row.Flow.Uplink != 11 || row.Flow.Downlink != 13 {
				t.Fatalf("caller exchange changed: %+v", row.Flow)
			}
		}
	}
	if !found {
		t.Fatal("caller exchange was not retained")
	}
	totals, err := view.ReadTotals()
	if err != nil || totals.User != (fs.ClientTotals{Uplink: 11, Downlink: 13}) || len(totals.Rows) != 0 {
		t.Fatalf("measurement contributed to USER totals: %+v %v", totals, err)
	}
	if session.LogicalObservationFromContext(ctx) != observation || !observation.ReturnedLink.Load() ||
		session.InboundFromContext(ctx) != inbound || session.OutboundsFromContext(ctx)[0] != outbound ||
		session.ContentFromContext(ctx) != content || content.Attribute("forcedOutboundTag") != "trap" ||
		outbound.Tag != "caller-tag" || session.TrafficOriginFromContext(ctx) != session.TrafficOriginUser || !session.TimeoutOnlyFromContext(ctx) {
		t.Fatal("measurement changed caller-owned context state")
	}
}
