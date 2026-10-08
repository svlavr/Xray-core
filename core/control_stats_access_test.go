package core_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	featurepolicy "github.com/xtls/xray-core/features/policy"
	featurerouting "github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestCleanControlStatsPhase1(t *testing.T) {
	const (
		primaryTag   = "phase1-primary"
		dynamicTag   = "phase1-dynamic"
		balancerTag  = "phase1-balancer"
		dynamicRule  = "phase1-dynamic-rule"
		uplinkSuffix = ">>>traffic>>>uplink"
		downSuffix   = ">>>traffic>>>downlink"
	)

	freedomConfig := func() *freedom.Config {
		return &freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}
	}
	outboundConfig := func(tag string) *core.OutboundHandlerConfig {
		return &core.OutboundHandlerConfig{
			Tag:           tag,
			ProxySettings: serial.ToTypedMessage(freedomConfig()),
		}
	}

	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{
				BalancingRule: []*router.BalancingRule{{
					Tag:              balancerTag,
					OutboundSelector: []string{"phase1-"},
					Strategy:         "roundRobin",
				}},
			}),
		},
		Outbound: []*core.OutboundHandlerConfig{outboundConfig(primaryTag)},
	})
	if err != nil {
		t.Fatalf("create stock instance: %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close stock instance: %v", err)
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatalf("start stock instance: %v", err)
	}

	routerFeature, ok := instance.GetFeature(featurerouting.RouterType()).(featurerouting.Router)
	if !ok {
		t.Fatal("routing.Router is not available through Instance.GetFeature")
	}
	outboundFeature, ok := instance.GetFeature(featureoutbound.ManagerType()).(featureoutbound.Manager)
	if !ok {
		t.Fatal("outbound.Manager is not available through Instance.GetFeature")
	}
	statsFeature, ok := instance.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	if !ok {
		t.Fatal("stats.Manager is not available through Instance.GetFeature")
	}
	policyFeature, ok := instance.GetFeature(featurepolicy.ManagerType()).(featurepolicy.Manager)
	if !ok {
		t.Fatal("policy.Manager is not available through Instance.GetFeature")
	}
	if systemStats := policyFeature.ForSystem().Stats; !systemStats.OutboundUplink || !systemStats.OutboundDownlink {
		t.Fatalf("outbound statistics policy is not enabled: %+v", systemStats)
	}

	primaryUplink := statsFeature.GetCounter("outbound>>>" + primaryTag + uplinkSuffix)
	primaryDownlink := statsFeature.GetCounter("outbound>>>" + primaryTag + downSuffix)
	if primaryUplink == nil || primaryDownlink == nil {
		t.Fatal("configured outbound counters were not registered")
	}
	primaryUplink.Add(17)
	primaryDownlink.Add(31)
	for name, sample := range map[string]struct {
		counter featurestats.Counter
		want    int64
	}{
		"uplink":   {counter: primaryUplink, want: 17},
		"downlink": {counter: primaryDownlink, want: 31},
	} {
		first := sample.counter.Value()
		second := sample.counter.Value()
		if first != sample.want || second != sample.want {
			t.Fatalf("%s counter Value reads: first=%d second=%d want=%d", name, first, second, sample.want)
		}
	}

	if err := core.AddOutboundHandler(instance, outboundConfig(dynamicTag)); err != nil {
		t.Fatalf("add dynamic outbound: %v", err)
	}
	dynamicHandler := outboundFeature.GetHandler(dynamicTag)
	if dynamicHandler == nil {
		t.Fatal("dynamic outbound is not available through outbound.Manager")
	}
	// RemoveHandler does not close or retire a handler. This is explicit test cleanup
	// for the removed object, independent of the removal assertion below. If the
	// test fails before removal, the instance still owns and closes the handler.
	t.Cleanup(func() {
		if outboundFeature.GetHandler(dynamicTag) != nil {
			return
		}
		if err := dynamicHandler.Close(); err != nil {
			t.Errorf("close removed dynamic handler during test cleanup: %v", err)
		}
	})
	if !hasOutboundTag(outboundFeature.ListHandlers(context.Background()), dynamicTag) {
		t.Fatal("dynamic outbound is absent from handler inventory")
	}
	dynamicCounterNames := []string{
		"outbound>>>" + dynamicTag + uplinkSuffix,
		"outbound>>>" + dynamicTag + downSuffix,
	}
	for _, name := range dynamicCounterNames {
		if statsFeature.GetCounter(name) == nil {
			t.Fatalf("dynamic outbound counter %q was not registered", name)
		}
	}

	balancer, ok := routerFeature.(featurerouting.BalancerOverrider)
	if !ok {
		t.Fatal("configured stock router does not implement routing.BalancerOverrider")
	}
	if err := balancer.SetOverrideTarget(balancerTag, dynamicTag); err != nil {
		t.Fatalf("set balancer override: %v", err)
	}
	if target, err := balancer.GetOverrideTarget(balancerTag); err != nil {
		t.Fatalf("get balancer override: %v", err)
	} else if target != dynamicTag {
		t.Fatalf("unexpected balancer override: got %q want %q", target, dynamicTag)
	}

	ruleConfig := serial.ToTypedMessage(&router.Config{
		Rule: []*router.RoutingRule{{
			RuleTag:   dynamicRule,
			Networks:  []net.Network{net.Network_TCP},
			TargetTag: &router.RoutingRule_BalancingTag{BalancingTag: balancerTag},
		}},
	})
	if err := routerFeature.AddRule(ruleConfig, true); err != nil {
		t.Fatalf("add routing rule: %v", err)
	}
	if !hasRuleTag(routerFeature.ListRule(), dynamicRule) {
		t.Fatal("dynamic routing rule is absent from rule inventory")
	}

	routeContext := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("phase1.invalid"), 443),
	}})
	selected, err := routerFeature.PickRoute(routing_session.AsRoutingContext(routeContext))
	if err != nil {
		t.Fatalf("pick route after dynamic rule add: %v", err)
	}
	if selected.GetRuleTag() != dynamicRule || selected.GetOutboundTag() != dynamicTag {
		t.Fatalf("unexpected route: rule=%q outbound=%q", selected.GetRuleTag(), selected.GetOutboundTag())
	}

	if err := routerFeature.RemoveRule(dynamicRule); err != nil {
		t.Fatalf("remove routing rule: %v", err)
	}
	if hasRuleTag(routerFeature.ListRule(), dynamicRule) {
		t.Fatal("dynamic routing rule remains in rule inventory after removal")
	}
	if _, err := routerFeature.PickRoute(routing_session.AsRoutingContext(routeContext)); err == nil {
		t.Fatal("removed routing rule still affects a new route selection")
	}

	if err := outboundFeature.RemoveHandler(context.Background(), dynamicTag); err != nil {
		t.Fatalf("remove dynamic outbound: %v", err)
	}
	if outboundFeature.GetHandler(dynamicTag) != nil {
		t.Fatal("dynamic outbound remains addressable after removal")
	}
	if hasOutboundTag(outboundFeature.ListHandlers(context.Background()), dynamicTag) {
		t.Fatal("dynamic outbound remains in handler inventory after removal")
	}
	for _, name := range dynamicCounterNames {
		if statsFeature.GetCounter(name) == nil {
			t.Fatalf("handler removal unexpectedly unregistered counter %q", name)
		}
	}
}

func hasOutboundTag(handlers []featureoutbound.Handler, tag string) bool {
	for _, handler := range handlers {
		if handler.Tag() == tag {
			return true
		}
	}
	return false
}

func hasRuleTag(routes []featurerouting.Route, tag string) bool {
	for _, route := range routes {
		if route.GetRuleTag() == tag {
			return true
		}
	}
	return false
}
