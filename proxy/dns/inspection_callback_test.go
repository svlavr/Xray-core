package dns

import (
	"bytes"
	"context"
	go_errors "errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/miekg/dns"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	dnsproto "github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	featuredns "github.com/xtls/xray-core/features/dns"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
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

type unadaptedDNSWriter struct{ bytes int32 }

func (w *unadaptedDNSWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.bytes += mb.Len()
	buf.ReleaseMulti(mb)
	return nil
}

func TestInspectionDNSFallbackCreditsUnadaptedWriter(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	flow := manager.Observation().Begin(cnet.Network_TCP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
	flow.Route(fs.OutboundRef{Serial: 1, Tag: "dns"})
	flow.BindRoute()
	lower := new(unadaptedDNSWriter)
	writer, attached := buf.AttachWriterReceiptWithStatus(lower, flow)
	if attached {
		t.Fatal("unadapted writer reported a receipt")
	}
	if err := (&dnsproto.TCPWriter{Writer: &endpointReceiptWriter{Writer: writer, receipt: flow}}).WriteMessage(buf.FromBytes([]byte("dns"))); err != nil {
		t.Fatal(err)
	}
	flow.Finish()
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink != 5 || lower.bytes != 5 {
		t.Fatalf("DNS endpoint batch lost on unsupported writer: %+v %v, written=%d", page.Rows, err, lower.bytes)
	}
}

func TestInspectionDNSReturnedRouteBindsTotals(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	destination := cnet.UDPDestination(cnet.LocalHostIP, 53)
	flow := manager.Observation().Begin(cnet.Network_UDP, fs.TrafficOriginUser, cnet.Destination{}, destination, nil)
	flow.Route(fs.OutboundRef{Serial: 7, Tag: "dns"})
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	flow.AddUplink(uint64(len(wire))) // The returned XUDP link already credited its source packet.
	reader := buf.NewInspectionReader(buf.NewReader(bytes.NewReader(wire)), flow, func() {})
	reader.InputAlreadyObserved = true
	observation := &session.LogicalObservation{Exchange: flow}
	ctx := session.ContextWithLogicalObservation(context.Background(), observation)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: destination}})
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	link := &transport.Link{Reader: reader, Writer: buf.Discard}
	handler := &Handler{timeout: time.Second, rules: []*DNSRule{{action: RuleAction_Return, rCode: dnsmessage.RCodeRefused}}}
	if err := handler.Process(ctx, link, unusedInspectionDialer{}); err != nil && !go_errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	flow.Finish()
	totals, err := view.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	var selected, unassigned uint64
	for _, row := range totals.Rows {
		if row.Origin != fs.TrafficOriginUser {
			continue
		}
		switch row.Outbound.Serial {
		case 7:
			selected = row.Uplink
		case 0:
			unassigned = row.Uplink
		}
	}
	if selected != uint64(len(wire)) || unassigned != 0 {
		t.Fatalf("returned DNS route totals: selected=%d unassigned=%d", selected, unassigned)
	}
}

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
	observation.Exchange.Route(fs.OutboundRef{Tag: "dns", Serial: 1})
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
	terminal, err := view.ReadTerminals()
	if err != nil || len(terminal.Rows) != 1 || terminal.Rows[0].Flow.Uplink != uint64(len(wire)) || terminal.Rows[0].Flow.Downlink != 0 {
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
		totals, err := view.ReadTotals()
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range totals.Rows {
			if row.Outbound.Tag == "dns" {
				again, err := view.ReadTerminals()
				if err != nil || len(again.Rows) != 1 || again.Rows[0].Flow.Downlink != 0 {
					t.Fatalf("late callback rewrote terminal: %+v %v", again.Rows, err)
				}
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("late callback result was not marked incomplete")
}
