package core_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/loopback"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport"
)

func inspectionCore(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, string) {
	t.Helper()
	port := tcp.PickPort()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:           cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList:         &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
				SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http"}},
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH}),
		}},
		Outbound: []*core.OutboundHandlerConfig{inspectionFreedom("direct")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	var view fs.FlowInspection
	if enabled {
		view, err = core.EnableFlowInspection(instance, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, view, net.JoinHostPort("127.0.0.1", port.String())
}

func inspectionFreedom(tag string) *core.OutboundHandlerConfig {
	return &core.OutboundHandlerConfig{Tag: tag, ProxySettings: serial.ToTypedMessage(&freedom.Config{
		FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
	})}
}

func inspectionSOCKS(t *testing.T, address string, destination cnet.Destination, payload []byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(conn, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("greeting %v: %v", greeting, err)
	}
	ip := destination.Address.IP().To4()
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(destination.Port >> 8), byte(destination.Port)}
	request = append(request, payload...)
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 10)
	if _, err = io.ReadFull(conn, response); err != nil || response[1] != 0 {
		t.Fatalf("SOCKS response %v: %v", response, err)
	}
	if len(payload) > 0 {
		inspectionResponse(t, conn, payload)
	}
	return conn
}

func inspectionResponse(t *testing.T, conn net.Conn, request []byte) {
	t.Helper()
	got := make([]byte, len(request))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, transformOutboundStatsTCPPayload(request)) {
		t.Fatal("payload altered")
	}
}

func inspectionWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("inspection condition did not complete")
}

func TestFlowInspectionSOCKS(t *testing.T) {
	for _, sniff := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "sniff-retained"}[sniff], func(t *testing.T) {
			_, view, address := inspectionCore(t, true, sniff)
			destination := startOutboundStatsTCPServer(t)
			payload := []byte("GET / HTTP/1.1\r\nHost: p1.invalid\r\n\r\n")
			first := inspectionSOCKS(t, address, destination, payload)
			second := inspectionSOCKS(t, address, destination, payload)
			var rows []fs.FlowRecord
			inspectionWait(t, func() bool {
				live, err := view.ReadLive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				rows = live.Rows
				if len(rows) != 2 {
					return false
				}
				for _, r := range rows {
					if r.Uplink.Known != uint64(len(payload)) {
						return false
					}
				}
				return true
			})
			var selected fs.FlowRecord
			for _, r := range rows {
				if r.Origin != fs.TrafficOriginUser || r.AccountingRoute.Outbound.Serial == 0 || r.AccountingRoute.Outbound.Tag != "direct" {
					t.Fatalf("bad admission/route: %+v", r)
				}
				if r.Source.Port == cnet.Port(first.LocalAddr().(*net.TCPAddr).Port) {
					selected = r
				}
				if runtime.GOOS == "windows" && r.Downlink.Known != uint64(len(payload)) {
					t.Fatalf("missing incremental output: %+v", r.Downlink)
				}
				if sniff && r.AccountingRoute.RouteTarget.Address.Domain() != "p1.invalid" {
					t.Fatalf("missing route-only target: %+v", r.AccountingRoute)
				}
			}
			if selected.Ref.ID == 0 {
				t.Fatal("first source not addressable")
			}
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("close %+v %v", out, err)
			}
			var terminal fs.TerminalRecord
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range page.Rows {
					if r.Flow.Ref == selected.Ref {
						terminal = r
						return true
					}
				}
				return false
			})
			if terminal.Flow.Uplink.Known != uint64(len(payload)) || terminal.Flow.Downlink.Known != uint64(len(payload)) || terminal.Flow.State != fs.FlowStateEnded || terminal.Reason != fs.EndReasonLocalStop {
				t.Fatalf("final receipt: %+v", terminal)
			}
			out, err = view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || out[0].Code != fs.CloseCodeAlreadyEnded {
				t.Fatalf("repeat close %+v %v", out, err)
			}
			extra := []byte("sibling stays open")
			if _, err = second.Write(extra); err != nil {
				t.Fatal(err)
			}
			inspectionResponse(t, second, extra)
			second.Close()
			inspectionWait(t, func() bool { live, _ := view.ReadLive(context.Background()); return len(live.Rows) == 0 })
			totals, err := view.ReadTotals(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var up, down uint64
			for _, r := range totals.Rows {
				if r.Outbound.Serial != 0 && r.Origin == fs.TrafficOriginUser {
					up += r.Uplink.Known
					down += r.Downlink.Known
				}
			}
			want := uint64(2*len(payload) + len(extra))
			if up != want || down != want {
				t.Fatalf("totals up=%d down=%d want=%d", up, down, want)
			}
		})
	}
}

func TestFlowInspectionTagReuseAndShortExchange(t *testing.T) {
	instance, view, address := inspectionCore(t, true, false)
	destination := startOutboundStatsTCPServer(t)
	manager := instance.GetFeature(fout.ManagerType()).(fout.Manager)
	var serials []uint64
	for i := 0; i < 2; i++ {
		c := inspectionSOCKS(t, address, destination, []byte("short"))
		c.Close()
		inspectionWait(t, func() bool {
			page, _ := view.ReadTerminals(context.Background())
			if len(page.Rows) != i+1 {
				return false
			}
			row := page.Rows[i]
			if row.Flow.Uplink.Known != 5 || row.Flow.Downlink.Known != 5 {
				t.Fatalf("short final: %+v", row)
			}
			serials = append(serials, row.Flow.AccountingRoute.Outbound.Serial)
			return true
		})
		if i == 0 {
			old := manager.GetHandler("direct")
			if err := manager.RemoveHandler(context.Background(), "direct"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { old.Close() })
			if err := core.AddOutboundHandler(instance, inspectionFreedom("direct")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if serials[0] == 0 || serials[0] == serials[1] {
		t.Fatalf("incarnation reuse: %v", serials)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range totals.Rows {
		if r.Outbound.Serial != 0 {
			count++
			if r.Uplink.Known != 5 || r.Downlink.Known != 5 {
				t.Fatalf("bucket mixed: %+v", r)
			}
		}
	}
	if count != 2 {
		t.Fatalf("want two incarnation buckets, got %d", count)
	}
}

func TestFlowInspectionRejectedSniffAndDisabled(t *testing.T) {
	instance, view, address := inspectionCore(t, true, true)
	routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		RuleTag: "missing", Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "absent"},
	}}}), true)
	if err != nil {
		t.Fatal(err)
	}
	destination := cnet.TCPDestination(cnet.LocalHostIP, 1)
	c := inspectionSOCKS(t, address, destination, nil)
	request := []byte("GET / HTTP/1.1\r\nHost: p1.invalid\r\n\r\n")
	c.Write(request)
	var final fs.TerminalRecord
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		if len(page.Rows) != 1 {
			return false
		}
		final = page.Rows[0]
		return true
	})
	if final.Reason != fs.EndReasonRejected || final.Flow.Uplink.Known != uint64(len(request)) || final.Flow.AccountingRoute.Outbound.Serial != 0 {
		t.Fatalf("rejected receipt: %+v", final)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, r := range totals.Rows {
		if r.Origin == fs.TrafficOriginUser {
			if r.Outbound.Serial != 0 {
				t.Fatal("failed route credited outbound")
			}
			known += r.Uplink.Known
		}
	}
	if known != uint64(len(request)) {
		t.Fatalf("unassigned=%d", known)
	}

	disabled, _, disabledAddress := inspectionCore(t, false, false)
	provider := disabled.GetFeature(fs.ManagerType()).(fs.ObservationProvider)
	if provider.Observation() != nil {
		t.Fatal("disabled store allocated")
	}
	echo := startOutboundStatsTCPServer(t)
	inspectionSOCKS(t, disabledAddress, echo, []byte("collection off")).Close()
	if provider.Observation() != nil {
		t.Fatal("traffic enabled collection")
	}
	if _, err := core.EnableFlowInspection(disabled, fs.ObservationOptions{}); !errors.Is(err, fs.ErrInspectionTooLate) {
		t.Fatalf("late enable: %v", err)
	}
}

func TestFlowInspectionEnableBoundary(t *testing.T) {
	bare := new(core.Instance)
	if _, err := core.EnableFlowInspection(bare, fs.ObservationOptions{}); !errors.Is(err, fs.ErrInspectionUnavailable) {
		t.Fatalf("bare instance: %v", err)
	}
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&appstats.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if _, err = core.EnableFlowInspection(instance, fs.ObservationOptions{MaxLive: 257}); !errors.Is(err, fs.ErrInspectionLimit) {
		t.Fatalf("budget validation: %v", err)
	}
	view, err := core.EnableFlowInspection(instance, fs.ObservationOptions{MaxLive: 1})
	if err != nil {
		t.Fatal(err)
	}
	if view.Info().Limits.MaxLive != 1 {
		t.Fatal("effective options")
	}
	if _, err = core.EnableFlowInspection(instance, fs.ObservationOptions{}); !errors.Is(err, fs.ErrInspectionAlreadyEnabled) {
		t.Fatalf("second enable: %v", err)
	}
	if err = instance.Close(); err != nil {
		t.Fatal(err)
	}
	if !view.Info().Closed {
		t.Fatal("store not closed")
	}
}

type inspectionForcedDispatcher struct {
	frouting.Dispatcher
	tag string
}

func (d inspectionForcedDispatcher) DispatchLink(ctx context.Context, destination cnet.Destination, link *transport.Link) error {
	return d.Dispatcher.DispatchLink(session.SetForcedOutboundTagToContext(ctx, d.tag), destination, link)
}

func TestFlowInspectionForcedSelection(t *testing.T) {
	for _, tag := range []string{"direct", "missing"} {
		t.Run(tag, func(t *testing.T) {
			instance, view, _ := inspectionCore(t, true, false)
			object, err := core.CreateObject(instance, &socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			t.Cleanup(func() { listener.Close(); <-done })
			go func() {
				defer close(done)
				conn, err := listener.AcceptTCP()
				if err != nil {
					return
				}
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				ctx = context.WithValue(ctx, core.XrayKey(1), instance)
				ctx = session.ContextWithInbound(ctx, &session.Inbound{
					Source: cnet.DestinationFromAddr(conn.RemoteAddr()), Gateway: cnet.DestinationFromAddr(conn.LocalAddr()), Conn: conn,
				})
				ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
				ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{Enabled: true}})
				d := instance.GetFeature(frouting.DispatcherType()).(frouting.Dispatcher)
				object.(*socks.Server).Process(ctx, cnet.Network_TCP, conn, inspectionForcedDispatcher{Dispatcher: d, tag: tag})
			}()
			destination := startOutboundStatsTCPServer(t)
			payload := []byte("GET / HTTP/1.1\r\nHost: forced.invalid\r\n\r\n")
			var conn net.Conn
			if tag == "direct" {
				conn = inspectionSOCKS(t, listener.Addr().String(), destination, payload)
			} else {
				conn = inspectionSOCKS(t, listener.Addr().String(), destination, nil)
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if tag == "direct" {
				conn.Close()
			}
			var final fs.TerminalRecord
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				if len(page.Rows) != 1 {
					return false
				}
				final = page.Rows[0]
				return true
			})
			if final.Flow.Uplink.Known != uint64(len(payload)) {
				t.Fatalf("sniff credit: %+v", final)
			}
			if tag == "direct" {
				if final.Flow.AccountingRoute.Selection != fs.SelectionForced || final.Flow.AccountingRoute.Outbound.Serial == 0 {
					t.Fatalf("forced selection: %+v", final)
				}
			} else if final.Reason != fs.EndReasonRejected || final.Flow.AccountingRoute.Outbound.Serial != 0 || final.Flow.AccountingRoute.Outbound.Tag != "missing" {
				t.Fatalf("missing forced selection: %+v", final)
			}
		})
	}
}

func inspectionForwardRoute(t *testing.T, instance *core.Instance) {
	t.Helper()
	if err := core.AddOutboundHandler(instance, &core.OutboundHandlerConfig{Tag: "forward", ProxySettings: serial.ToTypedMessage(&loopback.Config{InboundTag: "returned"})}); err != nil {
		t.Fatal(err)
	}
	routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{
		{InboundTag: []string{"returned"}, TargetTag: &router.RoutingRule_Tag{Tag: "direct"}},
		{Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "forward"}},
	}}), true); err != nil {
		t.Fatal(err)
	}
}

func TestFlowInspectionNativeForwardingControl(t *testing.T) {
	instance, _, address := inspectionCore(t, false, true)
	inspectionForwardRoute(t, instance)
	destination := startOutboundStatsTCPServer(t)
	conn := inspectionSOCKS(t, address, destination, []byte("GET / HTTP/1.1\r\nHost: native.invalid\r\n\r\n"))
	conn.Close()
	if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
		t.Fatal("disabled forwarding allocated an observation store")
	}
}

func TestFlowInspectionForwardingAttribution(t *testing.T) {
	instance, view, address := inspectionCore(t, true, true)
	inspectionForwardRoute(t, instance)
	destination := startOutboundStatsTCPServer(t)
	payload := []byte("GET / HTTP/1.1\r\nHost: forwarding.invalid\r\n\r\n")
	conn := inspectionSOCKS(t, address, destination, payload)
	conn.Close()
	var final fs.TerminalRecord
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		if len(page.Rows) != 1 {
			return false
		}
		final = page.Rows[0]
		return true
	})
	if len(final.Flow.Routes) != 2 || final.Flow.Routes[0].Outbound.Tag != "forward" || final.Flow.AccountingRoute.Outbound.Tag != "direct" || final.Flow.Routes[0].Leg == final.Flow.AccountingRoute.Leg || final.Flow.Uplink.Known != uint64(len(payload)) || final.Flow.Downlink.Known != uint64(len(payload)) {
		t.Fatalf("forwarded flow: %+v", final)
	}
	totals, _ := view.ReadTotals(context.Background())
	var up, down uint64
	for _, row := range totals.Rows {
		if row.Outbound.Tag == "forward" {
			t.Fatalf("forwarding bucket created: %+v", row)
		}
		if row.Outbound.Tag == "direct" {
			up += row.Uplink.Known
			down += row.Downlink.Known
		}
	}
	if up != uint64(len(payload)) || down != up {
		t.Fatalf("consuming totals %d/%d", up, down)
	}
}

// Deliberately lacks the optional inspection owner receipt. Keep this negative
// case independent of which native outbounds gain P2 integration.
type inspectionUnclaimedHandler struct{}

func (inspectionUnclaimedHandler) Tag() string                               { return "unclaimed" }
func (inspectionUnclaimedHandler) Start() error                              { return nil }
func (inspectionUnclaimedHandler) Close() error                              { return nil }
func (inspectionUnclaimedHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (inspectionUnclaimedHandler) ProxySettings() *serial.TypedMessage       { return nil }
func (inspectionUnclaimedHandler) Dispatch(context.Context, *transport.Link) {}

func TestFlowInspectionUnclaimedOwnerUsesUnassigned(t *testing.T) {
	instance, view, address := inspectionCore(t, true, true)
	manager := instance.GetFeature(fout.ManagerType()).(fout.Manager)
	if err := manager.AddHandler(context.Background(), inspectionUnclaimedHandler{}); err != nil {
		t.Fatal(err)
	}
	routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "unclaimed"}}}}), true); err != nil {
		t.Fatal(err)
	}
	conn := inspectionSOCKS(t, address, cnet.TCPDestination(cnet.LocalHostIP, 1), nil)
	payload := []byte("GET / HTTP/1.1\r\nHost: unclaimed.invalid\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	var ended fs.FlowRecord
	inspectionWait(t, func() bool {
		snapshot, _ := view.ReadTerminals(context.Background())
		if len(snapshot.Rows) != 1 {
			return false
		}
		ended = snapshot.Rows[0].Flow
		return ended.Uplink.Incomplete && ended.Downlink.Incomplete
	})
	if len(ended.Routes) != 1 || ended.Routes[0].Outbound.Tag != "unclaimed" || ended.AccountingRoute.Outbound.Serial != 0 || ended.Uplink.Known != uint64(len(payload)) {
		t.Fatalf("unclaimed owner snapshot: %+v", ended)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, row := range totals.Rows {
		if row.Outbound.Serial != 0 {
			t.Fatalf("unclaimed outbound bucket: %+v", row)
		}
		if row.Origin == fs.TrafficOriginUser {
			known += row.Uplink.Known
			if !row.Uplink.Incomplete || !row.Downlink.Incomplete {
				t.Fatalf("unclaimed uncertainty: %+v", row)
			}
		}
	}
	if known != uint64(len(payload)) {
		t.Fatalf("unassigned known %d", known)
	}
}
