package proxy_test

import (
	"context"
	"net"
	"strings"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

func TestObserveFallbackDisabledPreservesReader(t *testing.T) {
	for _, manager := range []fs.Manager{nil, fs.NoopManager{}, new(appstats.Manager)} {
		reader := buf.NewReader(strings.NewReader("payload"))
		ctx := context.Background()
		observed, got, flow, cleanup := proxy.ObserveFallback(ctx, manager, nil, "malformed", "not a destination", reader)
		if observed != ctx || got != reader || flow != nil || cleanup != nil {
			t.Fatal("disabled fallback changed the native reader or allocated a receipt")
		}
	}
}

func TestObserveFallbackRetainsInputAndUnknownRoute(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	endpoint, peer := net.Pipe()
	t.Cleanup(func() { endpoint.Close(); peer.Close() })
	buffered := &buf.BufferedReader{
		Reader: buf.NewReader(strings.NewReader("tail")),
		Buffer: buf.MultiBuffer{buf.FromBytes([]byte("first"))},
	}
	ctx, reader, flow, cleanup := proxy.ObserveFallback(context.Background(), manager, endpoint, "tcp4", "configured.invalid:8443", buffered)
	if ctx == context.Background() || flow == nil || cleanup == nil || reader == buffered || buffered.Buffer != nil {
		t.Fatal("enabled fallback did not transfer first-read custody")
	}
	defer cleanup()
	for _, want := range []string{"first", "tail"} {
		mb, err := reader.ReadMultiBuffer()
		got := mb.String()
		buf.ReleaseMulti(mb)
		if err != nil || got != want {
			t.Fatalf("fallback input %q, want %q: %v", got, want, err)
		}
	}
	effective := cnet.TCPDestination(cnet.LocalHostIP, 8443)
	flow.Effective(effective)
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live fallback: %+v %v", live, err)
	}
	configured := cnet.TCPDestination(cnet.DomainAddress("configured.invalid"), 8443)
	row := live.Rows[0]
	if row.InitialDestination != configured || row.AccountingRoute.Selection != fs.SelectionUnknown || row.AccountingRoute.Outbound.Serial != 0 || row.AccountingRoute.Original != configured || row.AccountingRoute.RouteTarget != configured || row.AccountingRoute.SelectedTarget != configured || row.AccountingRoute.Effective != effective || row.Uplink.Known != 9 || row.Uplink.Incomplete {
		t.Fatalf("fallback facts: %+v", row)
	}
}

func TestObserveFallbackMalformedTargetIsUnknown(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	endpoint, peer := net.Pipe()
	t.Cleanup(func() { endpoint.Close(); peer.Close() })
	_, _, flow, cleanup := proxy.ObserveFallback(context.Background(), manager, endpoint, "tcp", "missing-port", buf.NewReader(strings.NewReader("")))
	if flow == nil || cleanup == nil {
		t.Fatal("malformed fallback target lost its admission")
	}
	defer cleanup()
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live fallback: %+v %v", live, err)
	}
	row := live.Rows[0]
	if row.InitialDestination.IsValid() || row.AccountingRoute.SelectedTarget.IsValid() || row.AccountingRoute.Effective.IsValid() {
		t.Fatalf("malformed fallback fabricated a target: %+v", row)
	}
}
