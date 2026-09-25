package core_test

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fin "github.com/xtls/xray-core/features/inbound"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
	rsession "github.com/xtls/xray-core/features/routing/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func controlExchange(t *testing.T, conn net.Conn, network net.Network) {
	t.Helper()
	payload := []byte("P3 native control payload")
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	want := transformOutboundStatsTCPPayload(payload)
	if network == net.Network_UDP {
		want = transformOutboundStatsPayload(payload, 0x37)
	}
	if !bytes.Equal(response, want) {
		t.Fatalf("response %x want %x", response, want)
	}
}

func controlOpen(t *testing.T, instance *core.Instance, view fs.FlowInspection, dest net.Destination) (net.Conn, fs.FlowRecord) {
	t.Helper()
	before, err := view.ReadLive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	known := make(map[fs.FlowRef]bool, len(before.Rows))
	for _, row := range before.Rows {
		known[row.Ref] = true
	}
	ctx := session.ContextWithTrafficOrigin(context.Background(), fs.TrafficOriginUser)
	conn, err := core.Dial(ctx, instance, dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	controlExchange(t, conn, dest.Network)
	var found fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range live.Rows {
			if !known[row.Ref] && row.AccountingRoute.Outbound.Serial != 0 && row.Downlink.Known > 0 {
				found = row
				return true
			}
		}
		return false
	})
	return conn, found
}

func controlRule(target string, network net.Network) *router.Config {
	return &router.Config{Rule: []*router.RoutingRule{{
		RuleTag: "p3-rule", Networks: []net.Network{network},
		TargetTag: &router.RoutingRule_Tag{Tag: target},
	}}}
}

func controlRoute(t *testing.T, row fs.FlowRecord, tag string, selection fs.SelectionKind) {
	t.Helper()
	if row.Origin != fs.TrafficOriginUser || row.AccountingRoute.Outbound.Tag != tag || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Selection != selection {
		t.Fatalf("unexpected route: %+v", row)
	}
	if selection == fs.SelectionRule && row.AccountingRoute.RuleTag != "p3-rule" {
		t.Fatalf("missing rule readback: %+v", row.AccountingRoute)
	}
}

func TestControlStatsP3CapturedSwitch(t *testing.T) {
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		for _, balanced := range []bool{false, true} {
			t.Run(network.String()+map[bool]string{false: "/rule", true: "/balancer"}[balanced], func(t *testing.T) {
				instance, view, _ := inspectionCore(t, true, false)
				var dest net.Destination
				if network == net.Network_UDP {
					dest = startOutboundStatsUDPServer(t, 0x37)
				} else {
					dest = startOutboundStatsTCPServer(t)
				}
				for _, tag := range []string{"p3-a", "p3-b"} {
					if err := core.AddOutboundHandler(instance, inspectionFreedom(tag)); err != nil {
						t.Fatal(err)
					}
				}
				unrelated, unrelatedRow := controlOpen(t, instance, view, dest)
				controlRoute(t, unrelatedRow, "direct", fs.SelectionDefault)
				r := instance.GetFeature(frouting.RouterType()).(frouting.Router)
				b := r.(frouting.BalancerOverrider)
				config := controlRule("p3-a", network)
				if balanced {
					config.Rule[0].TargetTag = &router.RoutingRule_BalancingTag{BalancingTag: "p3-balancer"}
					config.BalancingRule = []*router.BalancingRule{{Tag: "p3-balancer", OutboundSelector: []string{"p3-"}, Strategy: "roundRobin"}}
				}
				if err := r.AddRule(serial.ToTypedMessage(config), false); err != nil {
					t.Fatal(err)
				}
				if balanced {
					if err := b.SetOverrideTarget("p3-balancer", "p3-a"); err != nil {
						t.Fatal(err)
					}
				}
				first, firstRow := controlOpen(t, instance, view, dest)
				second, secondRow := controlOpen(t, instance, view, dest)
				controlRoute(t, firstRow, "p3-a", fs.SelectionRule)
				controlRoute(t, secondRow, "p3-a", fs.SelectionRule)

				// The caller captures exact refs BEFORE changing the route. Membership
				// is bounded and deliberately excludes unrelated and future admissions.
				live, err := view.ReadLive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				var captured []fs.FlowRef
				for _, row := range live.Rows {
					if row.AccountingRoute.Outbound == firstRow.AccountingRoute.Outbound {
						captured = append(captured, row.Ref)
					}
				}
				if len(captured) != 2 || len(captured) > int(view.Info().Limits.MaxClose) {
					t.Fatalf("invalid captured set: %+v", captured)
				}
				// Failed native publication is observable. The caller does not invoke
				// the optional close after failure, and no automatic stop occurs.
				invalid := controlRule("p3-b", network)
				invalid.Rule[0].TargetTag = &router.RoutingRule_BalancingTag{BalancingTag: "absent"}
				if err := r.AddRule(serial.ToTypedMessage(invalid), false); err == nil {
					t.Fatal("missing balancer accepted")
				}
				// This later admission still selects A after the failed update, but
				// is outside the already captured set despite using the same owner.
				uncaptured, uncapturedRow := controlOpen(t, instance, view, dest)
				controlRoute(t, uncapturedRow, "p3-a", fs.SelectionRule)
				controlExchange(t, first, network)
				if balanced {
					if err := b.SetOverrideTarget("absent", "p3-b"); err == nil {
						t.Fatal("unknown balancer accepted")
					}
					// Override validates the balancer, not the target handler.
					if err := b.SetOverrideTarget("p3-balancer", "absent"); err != nil {
						t.Fatal(err)
					}
					if target, err := b.GetOverrideTarget("p3-balancer"); err != nil || target != "absent" {
						t.Fatalf("missing target readback: %q %v", target, err)
					}
					if err := b.SetOverrideTarget("p3-balancer", "p3-b"); err != nil {
						t.Fatal(err)
					}
					if target, err := b.GetOverrideTarget("p3-balancer"); err != nil || target != "p3-b" {
						t.Fatalf("override readback: %q %v", target, err)
					}
				} else if err := r.AddRule(serial.ToTypedMessage(controlRule("p3-b", network)), false); err != nil {
					t.Fatal(err)
				}
				if !hasRuleTag(r.ListRule(), "p3-rule") {
					t.Fatal("published rule missing from inventory")
				}
				later, laterRow := controlOpen(t, instance, view, dest)
				controlRoute(t, laterRow, "p3-b", fs.SelectionRule)
				controlExchange(t, first, network)
				controlExchange(t, second, network)
				live, err = view.ReadLive(context.Background())
				if err != nil || len(live.Rows) != 5 {
					t.Fatalf("ordinary update changed established membership: %+v %v", live, err)
				}
				for _, row := range live.Rows {
					if row.Ref == firstRow.Ref || row.Ref == secondRow.Ref {
						controlRoute(t, row, "p3-a", fs.SelectionRule)
					}
				}
				outcomes, err := view.CloseFlows(context.Background(), captured)
				if err != nil || len(outcomes) != len(captured) {
					t.Fatalf("close captured set: %+v %v", outcomes, err)
				}
				for i, outcome := range outcomes {
					if outcome.Ref != captured[i] || outcome.Code != fs.CloseCodeAccepted {
						t.Fatalf("captured close outcome: %+v", outcome)
					}
				}
				for _, conn := range []net.Conn{first, second} {
					if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
						t.Fatalf("stopped endpoint still readable: %d %v", n, err)
					} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
						t.Fatal("captured stop timed out instead of closing the endpoint")
					}
				}
				terminals, err := view.ReadTerminals(context.Background())
				if err != nil || len(terminals.Rows) != 2 {
					t.Fatalf("captured ending snapshots: %+v %v", terminals, err)
				}
				for _, terminal := range terminals.Rows {
					if terminal.Reason != fs.EndReasonLocalStop || (terminal.Flow.Ref != firstRow.Ref && terminal.Flow.Ref != secondRow.Ref) {
						t.Fatalf("wrong endpoint ended: %+v", terminal)
					}
					controlRoute(t, terminal.Flow, "p3-a", fs.SelectionRule)
				}
				stale := laterRow.Ref
				stale.Runtime[0] ^= 0xff
				outcomes, err = view.CloseFlows(context.Background(), append(captured, stale))
				if err != nil || len(outcomes) != 3 || outcomes[0].Code != fs.CloseCodeAlreadyEnded || outcomes[1].Code != fs.CloseCodeAlreadyEnded || outcomes[2].Code != fs.CloseCodeStaleRuntime {
					t.Fatalf("repeat/stale results: %+v %v", outcomes, err)
				}
				controlExchange(t, unrelated, network)
				controlExchange(t, uncaptured, network)
				controlExchange(t, later, network)
				if err := r.RemoveRule("p3-rule"); err != nil {
					t.Fatal(err)
				}
				if hasRuleTag(r.ListRule(), "p3-rule") {
					t.Fatal("removed rule still listed")
				}
				if err := r.RemoveRule("p3-rule"); err != nil {
					t.Fatalf("native repeated removal: %v", err)
				}
				_, defaultRow := controlOpen(t, instance, view, dest)
				controlRoute(t, defaultRow, "direct", fs.SelectionDefault)
			})
		}
	}
}

func TestControlStatsP3HandlerReuseRedirectAndBlock(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	original := startOutboundStatsTCPServer(t)
	var redirectedBytes atomic.Int64
	server := &tcp.Server{MsgProcessor: func(payload []byte) []byte {
		redirectedBytes.Add(int64(len(payload)))
		return transformOutboundStatsTCPPayload(payload)
	}}
	redirected, err := server.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	r := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	m := instance.GetFeature(fout.ManagerType()).(fout.Manager)
	if err := core.AddOutboundHandler(instance, inspectionFreedom("p3-dynamic")); err != nil {
		t.Fatal(err)
	}
	old := m.GetHandler("p3-dynamic")
	// Removal does not close the old owner. Close it explicitly at test cleanup.
	removed := false
	t.Cleanup(func() {
		if removed {
			if err := old.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	if err := r.AddRule(serial.ToTypedMessage(controlRule("p3-dynamic", net.Network_TCP)), false); err != nil {
		t.Fatal(err)
	}
	established, oldRow := controlOpen(t, instance, view, original)
	controlRoute(t, oldRow, "p3-dynamic", fs.SelectionRule)
	if err := core.AddOutboundHandler(instance, inspectionFreedom("p3-dynamic")); err == nil || m.GetHandler("p3-dynamic") != old {
		t.Fatal("duplicate add replaced the current owner")
	}
	if err := m.RemoveHandler(context.Background(), "p3-dynamic"); err != nil {
		t.Fatal(err)
	}
	removed = true
	if m.GetHandler("p3-dynamic") != nil || hasOutboundTag(m.ListHandlers(context.Background()), "p3-dynamic") {
		t.Fatal("removed handler still visible")
	}
	controlExchange(t, established, net.Network_TCP)
	replacement := inspectionFreedom("p3-dynamic")
	replacement.ProxySettings = serial.ToTypedMessage(&freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(redirected.Address), Port: uint32(redirected.Port)}},
		FinalRules:          []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
	})
	if err := core.AddOutboundHandler(instance, replacement); err != nil {
		t.Fatal(err)
	}
	newConn, newRow := controlOpen(t, instance, view, original)
	controlRoute(t, newRow, "p3-dynamic", fs.SelectionRule)
	if newRow.AccountingRoute.Outbound.Serial == oldRow.AccountingRoute.Outbound.Serial {
		t.Fatal("tag reuse reused the old incarnation")
	}
	if newRow.InitialDestination != original || newRow.AccountingRoute.Original != original || newRow.AccountingRoute.RouteTarget != (net.Destination{}) || newRow.AccountingRoute.SelectedTarget != original || newRow.AccountingRoute.Effective != redirected || redirectedBytes.Load() == 0 {
		t.Fatalf("redirect facts: %+v", newRow)
	}
	if err := core.AddOutboundHandler(instance, &core.OutboundHandlerConfig{Tag: "p3-block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRule(serial.ToTypedMessage(controlRule("p3-block", net.Network_TCP)), false); err != nil {
		t.Fatal(err)
	}
	blocked, err := core.Dial(session.ContextWithTrafficOrigin(context.Background(), fs.TrafficOriginUser), instance, original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blocked.Close() })
	if err := blocked.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := blocked.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("BLOCK returned data/success: %d %v", n, err)
	} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		t.Fatal("BLOCK timed out instead of ending")
	}
	blocked.Close()
	terminals, err := view.ReadTerminals(context.Background())
	if err != nil || len(terminals.Rows) != 1 {
		t.Fatalf("BLOCK terminal: %+v %v", terminals, err)
	}
	controlRoute(t, terminals.Rows[0].Flow, "p3-block", fs.SelectionRule)
	if terminals.Rows[0].Reason != fs.EndReasonRejected {
		t.Fatalf("BLOCK reason: %+v", terminals.Rows[0])
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{oldRow.Ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("old incarnation exact stop: %+v %v", outcomes, err)
	}
	controlExchange(t, newConn, net.Network_TCP)
}

func TestControlStatsP3NativeDuplicateFailureSideEffect(t *testing.T) {
	instance, _, _ := inspectionCore(t, false, false)
	m := instance.GetFeature(fout.ManagerType()).(fout.Manager)
	if err := core.AddOutboundHandler(instance, inspectionFreedom("p3-dynamic")); err != nil {
		t.Fatal(err)
	}
	oldDefault := m.GetDefaultHandler()
	if err := m.RemoveHandler(context.Background(), "direct"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { oldDefault.Close() })
	tagged := m.GetHandler("p3-dynamic")
	if m.GetDefaultHandler() != nil {
		t.Fatal("removal did not clear default")
	}
	if err := core.AddOutboundHandler(instance, inspectionFreedom("p3-dynamic")); err == nil {
		t.Fatal("duplicate add succeeded")
	}
	rejectedDefault, id := m.(fout.HandlerResolver).ResolveHandler("", true)
	if rejectedDefault == nil || rejectedDefault == tagged || id != 0 || m.GetHandler("p3-dynamic") != tagged {
		t.Fatalf("native failed-add readback: default=%v serial=%d tagged=%v", rejectedDefault, id, m.GetHandler("p3-dynamic"))
	}
	// The rejected default is not in the manager's close inventory.
	t.Cleanup(func() { rejectedDefault.Close() })
	if err := m.RemoveHandler(context.Background(), "absent"); err != nil {
		t.Fatalf("native absent outbound removal: %v", err)
	}
}

func TestControlStatsP3InboundLifecycle(t *testing.T) {
	instance, view, survivorAddress := inspectionCore(t, true, false)
	port := tcp.PickPort()
	config := &core.InboundHandlerConfig{
		Tag: "p3-inbound",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   net.NewIPOrDomain(net.LocalHostIP),
			PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
		}),
		ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH}),
	}
	if err := core.AddInboundHandler(instance, config); err != nil {
		t.Fatal(err)
	}
	m := instance.GetFeature(fin.ManagerType()).(fin.Manager)
	if _, err := m.GetHandler(context.Background(), config.Tag); err != nil {
		t.Fatal(err)
	}
	dest := startOutboundStatsTCPServer(t)
	address := net.JoinHostPort("127.0.0.1", port.String())
	conn := inspectionSOCKS(t, address, dest, []byte("dynamic inbound"))
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		controlRoute(t, live.Rows[0], "direct", fs.SelectionDefault)
		return true
	})
	if err := m.RemoveHandler(context.Background(), config.Tag); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetHandler(context.Background(), config.Tag); err == nil {
		t.Fatal("removed inbound still visible")
	}
	if unexpected, err := stdnet.DialTimeout("tcp", address, time.Second); err == nil {
		unexpected.Close()
		t.Fatal("removed inbound listener still accepts")
	}
	// Unlike outbound removal, inbound removal closes its listener. It still
	// does not constitute an exact captured-flow stop or synchronous flow drain.
	controlExchange(t, conn, net.Network_TCP)
	inspectionSOCKS(t, survivorAddress, dest, []byte("unrelated inbound survives"))
	if err := m.RemoveHandler(context.Background(), config.Tag); err == nil {
		t.Fatal("native repeated inbound removal lost its not-found error")
	}
}

func TestControlStatsP3MissingProcessIdentity(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	r := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	config := controlRule("direct", net.Network_TCP)
	config.Rule = append([]*router.RoutingRule{{
		RuleTag: "process-only", Process: []string{"self/"},
		TargetTag: &router.RoutingRule_Tag{Tag: "must-not-select"},
	}}, config.Rule...)
	if err := r.AddRule(serial.ToTypedMessage(config), false); err != nil {
		t.Fatal(err)
	}
	// API admission has no platform source identity. Failure to match the
	// process rule falls through to a generic rule; it is not a fail-closed policy.
	_, row := controlOpen(t, instance, view, startOutboundStatsTCPServer(t))
	controlRoute(t, row, "direct", fs.SelectionRule)
	matcher := router.NewProcessNameMatcher([]string{"self/"})
	if matcher.Apply(&rsession.Context{Inbound: &session.Inbound{Source: net.TCPDestination(net.LocalHostIP, 1)}}) {
		t.Fatal("unknown network matched a process")
	}
}
