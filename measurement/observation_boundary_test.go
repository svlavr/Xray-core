package measurement_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/transport"
)

type boundaryNativeObservation struct {
	fout.Handler
	observed chan *session.LogicalObservation
}

func (h *boundaryNativeObservation) Dispatch(ctx context.Context, link *transport.Link) {
	if session.TrafficOriginFromContext(ctx) == session.TrafficOriginUser {
		select {
		case h.observed <- session.LogicalObservationFromContext(ctx):
		default:
		}
	}
	h.Handler.Dispatch(ctx, link)
}

// This boundary regression uses the actual dispatcher and observation owner.
// Concurrent combined USER/Measurement acceptance remains a separate matrix.
func TestMeasurementInheritedObservationIsolation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "measurement-payload")
		if r.URL.Path == "/held" {
			w.(http.Flusher).Flush()
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	defer peer.Close()
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&router.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&appstats.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{config("trap", true), config("exact", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	view, err := core.EnableFlowInspection(v, fs.ObservationOptions{MaxLive: 8, MaxBuckets: 8})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	// Keep an actual native USER endpoint live throughout held Measurement.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	manager := v.GetFeature(fout.ManagerType()).(fout.Manager)
	wrapped := &boundaryNativeObservation{Handler: manager.GetHandler("exact"), observed: make(chan *session.LogicalObservation, 1)}
	if err := manager.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(context.Background(), wrapped); err != nil {
		t.Fatal(err)
	}
	user, source := nativeIngressDial(t, nativeIngressContext(context.Background(), "exact"), v, xnet.DestinationFromAddr(listener.Addr()))
	defer func() { _ = user.Close(); _ = listener.Close(); <-peerDone }()
	payload := []byte("native-user")
	_ = user.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := user.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("native USER write: %d %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(user, response); err != nil || string(response) != string(payload) {
		t.Fatalf("native USER echo: %q %v", response, err)
	}
	var observation *session.LogicalObservation
	select {
	case observation = <-wrapped.observed:
	case <-time.After(5 * time.Second):
		t.Fatal("native USER observation absent")
	}
	if observation == nil || observation.Exchange == nil {
		t.Fatal("native USER root missing")
	}
	parent := observation.Exchange
	parentRef := parent.Ref()
	claimed := observation.ReturnedLink.Load()
	want := uint64(len(payload))
	checkParent := func(flow fs.FlowRecord) {
		if flow.Ref != parentRef || flow.Origin != fs.TrafficOriginUser || flow.Source != source || flow.Outbound.Tag != "exact" || flow.Uplink != want || flow.Downlink != want {
			t.Fatalf("native caller exchange changed: %+v", flow)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		live, err := view.ReadLiveInto(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 && live.Rows[0].Uplink == want && live.Rows[0].Downlink == want {
			checkParent(live.Rows[0])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native USER facts incomplete: %+v", live)
		}
		time.Sleep(time.Millisecond)
	}
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
	r := measurement.HTTPRequest{
		Route: measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"},
		URL:   peer.URL, Timeout: 5 * time.Second, MaxBodyBytes: 128, MaxHeaderBytes: 4096,
	}
	r.URL += "/held"
	type result struct {
		receipt measurement.HTTPReceipt
		err     error
	}
	finished := make(chan result, 1)
	go func() { got, err := e.HTTP(ctx, http.MethodGet, r); finished <- result{got, err} }()
	select {
	case <-entered:
	case got := <-finished:
		t.Fatalf("measurement ended before inspection: %+v", got)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	liveHeld, err := view.ReadLiveInto(nil)
	if err != nil || len(liveHeld.Rows) != 1 {
		t.Fatalf("held Measurement admitted optional core API root: %+v %v", liveHeld, err)
	}
	checkParent(liveHeld.Rows[0])
	close(release)
	completed := <-finished
	got, err := completed.receipt, completed.err
	if err != nil || !got.BodyComplete || string(got.Body) != "measurement-payload" {
		t.Fatalf("exact native request: %+v %v", got, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		live, err := view.ReadLiveInto(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 && live.Rows[0].Ref == parentRef {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("exact measurement remained live after completion: %+v", live)
		}
		time.Sleep(time.Millisecond)
	}
	r.URL = peer.URL
	r.Route = measurement.Route{Kind: measurement.Direct}
	got, err = e.HTTP(ctx, http.MethodGet, r)
	if err != nil || string(got.Body) != "measurement-payload" {
		t.Fatalf("DIRECT request inherited caller route: %+v %v", got, err)
	}
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("DIRECT created a core flow or parent was lost: %+v %v", live, err)
	}
	var found bool
	for _, flow := range live.Rows {
		if flow.Ref == parentRef {
			found = true
			checkParent(flow)
		}
	}
	if !found {
		t.Fatal("caller live exchange was not retained")
	}
	_ = user.Close()
	totals, err := view.ReadTotals()
	if err != nil || totals.User != (fs.ClientTotals{Uplink: want, Downlink: want}) || len(totals.Rows) != 1 || totals.Rows[0].Outbound.Tag != "exact" || totals.Rows[0].Uplink != want || totals.Rows[0].Downlink != want {
		t.Fatalf("measurement contributed to USER totals: %+v %v", totals, err)
	}
	if session.LogicalObservationFromContext(ctx) != observation || observation.ReturnedLink.Load() != claimed ||
		session.InboundFromContext(ctx) != inbound || session.OutboundsFromContext(ctx)[0] != outbound ||
		session.ContentFromContext(ctx) != content || content.Attribute("forcedOutboundTag") != "trap" ||
		outbound.Tag != "caller-tag" || session.TrafficOriginFromContext(ctx) != session.TrafficOriginUser || !session.TimeoutOnlyFromContext(ctx) {
		t.Fatal("measurement changed caller-owned context state")
	}
}
