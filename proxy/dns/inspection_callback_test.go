package dns

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/miekg/dns"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	featuredns "github.com/xtls/xray-core/features/dns"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type blockedInspectionDNS struct {
	featuredns.Client
	entered chan struct{}
	release chan struct{}
}

func (c *blockedInspectionDNS) LookupIP(string, featuredns.IPOption) ([]cnet.IP, uint32, error) {
	close(c.entered)
	<-c.release
	return []cnet.IP{{127, 0, 0, 7}}, 60, nil
}

type unusedInspectionDialer struct{ internet.Dialer }

func TestInspectionDNSHijackLateCallbackAfterExactStop(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	local, peer := stdnet.Pipe()
	defer local.Close()
	defer peer.Close()
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	link := &transport.Link{Reader: buf.NewReader(local), Writer: buf.NewWriter(local)}
	target := cnet.UDPDestination(cnet.LocalHostIP, 53)
	ctx, finish := proxy.ObserveUDP(context.Background(), manager, local, target, link)
	defer finish()
	observation := session.LogicalObservationFromContext(ctx)
	observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "dns", Serial: 1}})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	lookup := &blockedInspectionDNS{entered: make(chan struct{}), release: make(chan struct{})}
	handler := &Handler{client: lookup, timeout: time.Minute}
	done := make(chan error, 1)
	go func() { done <- handler.Process(ctx, link, unusedInspectionDialer{}) }()
	go func() { _, _ = peer.Write(wire) }()
	select {
	case <-lookup.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("local lookup was not started")
	}
	ref := observation.Exchange.Ref()
	if _, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref}); err != nil {
		t.Fatal(err)
	}
	terminal, err := view.ReadTerminals(context.Background())
	if err != nil || len(terminal.Rows) != 1 || terminal.Rows[0].Flow.Uplink.Known != uint64(len(wire)) || terminal.Rows[0].Flow.Downlink.Known != 0 || terminal.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatalf("owner-close snapshot: %+v %v", terminal.Rows, err)
	}
	close(lookup.release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("DNS owner did not return after exact stop")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		totals, err := view.ReadTotals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range totals.Rows {
			if row.Outbound.Tag == "dns" && row.Downlink.Incomplete {
				again, err := view.ReadTerminals(context.Background())
				if err != nil || len(again.Rows) != 1 || again.Rows[0].Flow.Downlink.Known != 0 || again.Rows[0].Reason != fs.EndReasonLocalStop {
					t.Fatalf("late callback rewrote terminal: %+v %v", again.Rows, err)
				}
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("late callback result was not marked incomplete")
}
