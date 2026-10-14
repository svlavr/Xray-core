//go:build (linux && !android) || freebsd

package tun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	appoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	proxydns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	gatewaySource  = "192.0.2.1"
	gatewayAddress = "192.0.2.2"
	gatewayInbound = "system-dns-tun"
)

type gatewayUnknownClient struct{}

func (gatewayUnknownClient) Type() interface{} { return featuredns.ClientType() }
func (gatewayUnknownClient) Start() error      { return nil }
func (gatewayUnknownClient) Close() error      { return nil }
func (gatewayUnknownClient) LookupIP(string, featuredns.IPOption) ([]xnet.IP, uint32, error) {
	return nil, 0, errors.New("lookup is outside this admission test")
}

type gatewaySafeClient struct {
	gatewayUnknownClient
	system bool
}

func (c gatewaySafeClient) MayUseSystemResolver() bool { return c.system }
func (gatewaySafeClient) AcquireSystemDNS() (func(), error) {
	return func() {}, nil
}

// Only the proxy callback can prove serving; the handler and manager provide
// selection and expose the actual proxy through the existing GetOutbound seam.
type gatewayProxy struct {
	check func(context.Context, xnet.Destination) error
}

func (*gatewayProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
	return errors.New("message transport is covered by the core composition tests")
}

func (p *gatewayProxy) VerifySystemDNS(ctx context.Context, target xnet.Destination) error {
	return p.check(ctx, target)
}

type gatewayPlainProxy struct{}

func (gatewayPlainProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
	return nil
}

type gatewayHandlerWithoutGetter struct {
	tag      string
	settings *serial.TypedMessage
}

func (h *gatewayHandlerWithoutGetter) Tag() string                             { return h.tag }
func (*gatewayHandlerWithoutGetter) Start() error                              { return nil }
func (*gatewayHandlerWithoutGetter) Close() error                              { return nil }
func (*gatewayHandlerWithoutGetter) Dispatch(context.Context, *transport.Link) {}
func (*gatewayHandlerWithoutGetter) SenderSettings() *serial.TypedMessage      { return nil }
func (h *gatewayHandlerWithoutGetter) ProxySettings() *serial.TypedMessage     { return h.settings }

type gatewayHandler struct {
	gatewayHandlerWithoutGetter
	p proxy.Outbound
}

func (h *gatewayHandler) GetOutbound() proxy.Outbound { return h.p }

func gatewayRule(network xnet.Network, tag string) *router.RoutingRule {
	return &router.RoutingRule{
		InboundTag: []string{gatewayInbound},
		Networks:   []xnet.Network{network},
		SourceIp: []*geodata.IPRule{{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{
			Cidr: &geodata.CIDR{Ip: []byte{192, 0, 2, 1}, Prefix: 32},
		}}}},
		SourcePortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(probeSourcePort)}},
		PortList:       &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(53)}},
		TargetTag:      &router.RoutingRule_Tag{Tag: tag},
	}
}

func gatewayContext(t *testing.T, client featuredns.Client, rules []*router.RoutingRule, handlers ...outbound.Handler) context.Context {
	t.Helper()
	manager, err := appoutbound.New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range handlers {
		if err := manager.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	r := new(router.Router)
	if err := r.Init(context.Background(), &router.Config{Rule: rules}, client, manager, nil); err != nil {
		t.Fatal(err)
	}
	// Install the exact selected features before any default-client fallback.
	// No running core, OS mutation, global dialer or test registry is needed.
	instance := new(core.Instance)
	for _, f := range []features.Feature{client, manager, r} {
		if err := instance.AddFeature(f); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = instance.Close() })
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func readyGateway(t *testing.T, calls *[]xnet.Network) *gatewayProxy {
	t.Helper()
	return &gatewayProxy{check: func(ctx context.Context, target xnet.Destination) error {
		in := session.InboundFromContext(ctx)
		if target.Address.String() != gatewayAddress || target.Port != 53 {
			return errors.New("wrong advertised endpoint")
		}
		if in == nil || in.Source.Network != target.Network || in.Source.Address.String() != gatewaySource || in.Source.Port != probeSourcePort || in.Tag != gatewayInbound {
			t.Fatalf("protocol/source routing metadata = %+v, target = %v", in, target)
		}
		if session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal || session.LogicalObservationFromContext(ctx) != nil || in.User != nil || in.VlessRoute != 0 {
			t.Fatal("gateway inherited USER identity")
		}
		content := session.ContentFromContext(ctx)
		if content == nil || content.Protocol != "" || content.Attributes != nil || content.SkipDNSResolve || content.SniffingRequest.Enabled {
			t.Fatalf("gateway inherited content: %+v", content)
		}
		out := session.OutboundsFromContext(ctx)
		if len(out) != 1 || out[0].Target != target || out[0].Tag != "" || out[0].RouteTarget.IsValid() || out[0].OriginalTarget.IsValid() {
			t.Fatalf("gateway inherited outbound identity: %+v", out)
		}
		*calls = append(*calls, target.Network)
		return ctx.Err()
	}}
}

func TestSystemDNSGatewayRoutesAndUserFence(t *testing.T) {
	var calls []xnet.Network
	p := readyGateway(t, &calls)
	ctx := gatewayContext(t, gatewaySafeClient{}, []*router.RoutingRule{
		// An inherited USER identity would choose the missing handler first.
		{UserEmail: []string{"user@example.org"}, TargetTag: &router.RoutingRule_Tag{Tag: "wrong-user-route"}},
		gatewayRule(xnet.Network_UDP, "udp"), gatewayRule(xnet.Network_TCP, "tcp"),
	}, &gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "udp"}, p: p},
		&gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "tcp"}, p: p})
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	ctx = session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{})
	in := &session.Inbound{User: &protocol.MemoryUser{Email: "user@example.org"}, VlessRoute: 7}
	content := &session.Content{Protocol: "http", SkipDNSResolve: true, Attributes: map[string]string{"forcedOutboundTag": "wrong-user-route"}, SniffingRequest: session.SniffingRequest{Enabled: true}}
	out := &session.Outbound{Tag: "wrong-user-route", RouteTarget: xnet.TCPDestination(xnet.DomainAddress("user.example.org"), 443)}
	ctx = session.ContextWithInbound(ctx, in)
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{out})
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	baseCheck := p.check
	p.check = func(checkCtx context.Context, target xnet.Destination) error {
		if got, ok := checkCtx.Deadline(); !ok || !got.Equal(deadline) {
			t.Fatal("caller deadline was not preserved")
		}
		return baseCheck(checkCtx, target)
	}
	if err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != xnet.Network_UDP || calls[1] != xnet.Network_TCP {
		t.Fatalf("actual gateway checks = %v", calls)
	}
	if session.InboundFromContext(ctx) != in || session.ContentFromContext(ctx) != content || session.OutboundsFromContext(ctx)[0] != out || session.TrafficOriginFromContext(ctx) != session.TrafficOriginUser || content.Attribute("forcedOutboundTag") != "wrong-user-route" {
		t.Fatal("admission mutated its caller metadata")
	}
}

func TestSystemDNSGatewayRefusals(t *testing.T) {
	tests := []struct {
		name, want string
		configure  func(*gatewayHandler, *gatewayHandler, *gatewayProxy, *[]*router.RoutingRule)
	}{
		{"no UDP route", "no route", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) { *rules = (*rules)[1:] }},
		{"no TCP route", "no route", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) { *rules = (*rules)[:1] }},
		{"missing UDP handler", "does not exist", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) { u.tag = "other" }},
		{"missing TCP handler", "does not exist", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) { c.tag = "other" }},
		{"proxy has no serving capability", "does not handle DNS", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) { u.p = gatewayPlainProxy{} }},
		{"nil actual proxy", "does not handle DNS", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) { u.p = nil }},
		{"unready callback", "callback unavailable", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) {
			p.check = func(context.Context, xnet.Destination) error { return errors.New("callback unavailable") }
		}},
		{"wrong endpoint association", "wrong endpoint", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) {
			p.check = func(_ context.Context, target xnet.Destination) error {
				if target.Address.String() != "127.0.0.1" {
					return errors.New("wrong endpoint")
				}
				return nil
			}
		}},
		{"UDP only serving", "TCP unsupported", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) {
			p.check = func(_ context.Context, target xnet.Destination) error {
				if target.Network != xnet.Network_UDP {
					return errors.New("TCP unsupported")
				}
				return nil
			}
		}},
		{"custom UDP plus unrelated native TCP", "does not handle DNS", func(u, c *gatewayHandler, p *gatewayProxy, rules *[]*router.RoutingRule) {
			c.settings = serial.ToTypedMessage(&proxydns.Config{})
			c.p = gatewayPlainProxy{}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []xnet.Network
			p := readyGateway(t, &calls)
			u := &gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "udp"}, p: p}
			c := &gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "tcp"}, p: p}
			rules := []*router.RoutingRule{gatewayRule(xnet.Network_UDP, "udp"), gatewayRule(xnet.Network_TCP, "tcp")}
			tt.configure(u, c, p, &rules)
			ctx := gatewayContext(t, gatewaySafeClient{}, rules, u, c)
			if err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("admission error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestSystemDNSGatewayUnknownClientAndMissingGetter(t *testing.T) {
	for _, tt := range []struct {
		client featuredns.Client
		want   string
	}{
		{gatewayUnknownClient{}, "does not support safe system DNS takeover"},
		{gatewaySafeClient{system: true}, "system resolver"},
		{gatewaySafeClient{}, "does not expose"},
	} {
		ctx := gatewayContext(t, tt.client, []*router.RoutingRule{gatewayRule(xnet.Network_UDP, "udp")}, &gatewayHandlerWithoutGetter{tag: "udp"})
		err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("client %T admission = %v, want %q", tt.client, err, tt.want)
		}
	}
	var calls []xnet.Network
	p := readyGateway(t, &calls)
	ctx := gatewayContext(t, gatewaySafeClient{}, []*router.RoutingRule{gatewayRule(xnet.Network_UDP, "udp"), gatewayRule(xnet.Network_TCP, "tcp")},
		&gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "udp"}, p: p},
		&gatewayHandlerWithoutGetter{tag: "tcp"})
	if err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress); err == nil || !strings.Contains(err.Error(), "does not expose") || len(calls) != 1 {
		t.Fatalf("missing TCP getter admission = %v, checks = %v", err, calls)
	}
}

func TestSystemDNSGatewayWrongSourceAndAddress(t *testing.T) {
	var calls []xnet.Network
	p := readyGateway(t, &calls)
	ctx := gatewayContext(t, gatewaySafeClient{}, []*router.RoutingRule{gatewayRule(xnet.Network_UDP, "udp"), gatewayRule(xnet.Network_TCP, "tcp")},
		&gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "udp"}, p: p},
		&gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "tcp"}, p: p})
	for _, tt := range []struct{ tag, source, address, want string }{
		{"wrong-inbound", gatewaySource, gatewayAddress, "no route"},
		{gatewayInbound, "192.0.2.3", gatewayAddress, "no route"},
		{gatewayInbound, gatewaySource, "192.0.2.4", "wrong advertised endpoint"},
		{gatewayInbound, gatewaySource, "dns.example.org", "invalid DNS address"},
		{gatewayInbound, "not-an-address", gatewayAddress, "invalid source address"},
		{gatewayInbound, "2001:db8::1", gatewayAddress, "invalid source address"},
	} {
		if err := verifyDNSRouting(ctx, tt.tag, tt.source, tt.address); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("source/address %s/%s = %v, want %q", tt.source, tt.address, err, tt.want)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("wrong source/address reached ready callback: %v", calls)
	}
}

func TestSystemDNSGatewayPreservesNativeUDPRecognition(t *testing.T) {
	ctx := gatewayContext(t, gatewaySafeClient{}, []*router.RoutingRule{gatewayRule(xnet.Network_UDP, "native")},
		&gatewayHandlerWithoutGetter{tag: "native", settings: serial.ToTypedMessage(&proxydns.Config{})})
	if err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress); err != nil {
		t.Fatalf("native UDP recognition now requires custom serving capability/TCP: %v", err)
	}
}

func TestSystemDNSGatewayCancellation(t *testing.T) {
	for _, when := range []string{"before route", "during UDP", "during TCP"} {
		t.Run(when, func(t *testing.T) {
			var calls []xnet.Network
			p := readyGateway(t, &calls)
			ctx := gatewayContext(t, gatewaySafeClient{}, []*router.RoutingRule{gatewayRule(xnet.Network_UDP, "udp"), gatewayRule(xnet.Network_TCP, "tcp")},
				&gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "udp"}, p: p},
				&gatewayHandler{gatewayHandlerWithoutGetter: gatewayHandlerWithoutGetter{tag: "tcp"}, p: p})
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if when == "before route" {
				cancel()
			}
			baseCheck := p.check
			p.check = func(checkCtx context.Context, target xnet.Destination) error {
				if err := baseCheck(checkCtx, target); err != nil {
					return err
				}
				if when == "during UDP" && target.Network == xnet.Network_UDP || when == "during TCP" && target.Network == xnet.Network_TCP {
					cancel()
				}
				// Even an erroneously successful callback cannot admit a canceled caller.
				return nil
			}
			if err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled admission = %v", err)
			}
			if when == "before route" && len(calls) != 0 || when == "during UDP" && len(calls) != 1 || when == "during TCP" && len(calls) != 2 {
				t.Fatalf("callback count after cancellation = %v", calls)
			}
		})
	}
}

type gatewayNilRouter struct{ routing.DefaultRouter }

func (gatewayNilRouter) PickRoute(routing.Context) (routing.Route, error) { return nil, nil }

func TestSystemDNSGatewayMissingFeaturesAndNilRoute(t *testing.T) {
	for _, feature := range []string{"core", "router", "manager", "nil route"} {
		t.Run(feature, func(t *testing.T) {
			ctx := context.Background()
			if feature != "core" {
				instance := new(core.Instance)
				if err := instance.AddFeature(gatewaySafeClient{}); err != nil {
					t.Fatal(err)
				}
				if feature != "router" {
					if err := instance.AddFeature(gatewayNilRouter{}); err != nil {
						t.Fatal(err)
					}
				}
				if feature != "manager" {
					m, err := appoutbound.New(ctx, &proxyman.OutboundConfig{})
					if err != nil {
						t.Fatal(err)
					}
					if err := instance.AddFeature(m); err != nil {
						t.Fatal(err)
					}
				}
				t.Cleanup(func() { _ = instance.Close() })
				ctx = context.WithValue(ctx, core.XrayKey(1), instance)
			}
			if err := verifyDNSRouting(ctx, gatewayInbound, gatewaySource, gatewayAddress); err == nil {
				t.Fatal("missing feature/nil route admitted")
			}
		})
	}
}
