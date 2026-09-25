package internet

import (
	"context"
	go_errors "errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type contextTestDNSClient struct{ ip net.IP }

func (*contextTestDNSClient) Type() interface{} { return featuredns.ClientType() }
func (*contextTestDNSClient) Start() error      { return nil }
func (*contextTestDNSClient) Close() error      { return nil }
func (c *contextTestDNSClient) LookupIP(string, featuredns.IPOption) ([]net.IP, uint32, error) {
	return []net.IP{c.ip}, 1, nil
}

type bindingTestOutboundHandler struct {
	dispatches atomic.Int32
	contexts   chan context.Context
}

func (*bindingTestOutboundHandler) Start() error                         { return nil }
func (*bindingTestOutboundHandler) Close() error                         { return nil }
func (*bindingTestOutboundHandler) Tag() string                          { return "bound-proxy" }
func (*bindingTestOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*bindingTestOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *bindingTestOutboundHandler) Dispatch(ctx context.Context, _ *transport.Link) {
	h.dispatches.Add(1)
	if h.contexts != nil {
		h.contexts <- ctx
	}
}

type bindingTestOutboundManager struct{ handler outbound.Handler }

func (*bindingTestOutboundManager) Type() interface{} { return outbound.ManagerType() }

func (*bindingTestOutboundManager) Start() error { return nil }

func (*bindingTestOutboundManager) Close() error { return nil }

func (m *bindingTestOutboundManager) GetHandler(string) outbound.Handler { return m.handler }

func (m *bindingTestOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }

func (*bindingTestOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }

func (*bindingTestOutboundManager) RemoveHandler(context.Context, string) error { return nil }

func (*bindingTestOutboundManager) ListHandlers(context.Context) []outbound.Handler { return nil }

func TestLookupForIPContextUsesBindingBeforeProcessGlobalClient(t *testing.T) {
	previous := dnsClient
	t.Cleanup(func() { dnsClient = previous })
	dnsClient = &contextTestDNSClient{ip: net.IP{192, 0, 2, 2}}

	owner := featuredns.NewContextOwner()
	var valid atomic.Bool
	valid.Store(true)
	binding := featuredns.NewContextBinding(owner,
		func(context.Context, string, featuredns.IPOption) ([]net.IP, uint32, error) {
			return []net.IP{{192, 0, 2, 1}}, 1, nil
		}, nil, valid.Load)
	ctx := featuredns.ContextWithBinding(context.Background(), binding)

	ips, err := LookupForIPContext(ctx, "bound.test", DomainStrategy_USE_IP4, nil)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 1}) {
		t.Fatalf("lookup used changed global client: ips=%v err=%v", ips, err)
	}
	dnsClient = nil
	ips, err = LookupForIPContext(ctx, "bound.test", DomainStrategy_USE_IP4, nil)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 1}) {
		t.Fatalf("binding incorrectly required a global client: ips=%v err=%v", ips, err)
	}
	valid.Store(false)
	_, err = LookupForIPContext(ctx, "bound.test", DomainStrategy_USE_IP4, nil)
	var bindingErr *featuredns.CausalBindingError
	if !go_errors.As(err, &bindingErr) {
		t.Fatalf("invalid binding fell back instead of failing closed: %v", err)
	}
}

func TestDialSystemExpiredBindingRejectsDialerProxyBeforeDispatch(t *testing.T) {
	previousManager := obm
	t.Cleanup(func() { obm = previousManager })
	handler := new(bindingTestOutboundHandler)
	obm = &bindingTestOutboundManager{handler: handler}
	owner := featuredns.NewContextOwner()
	binding := featuredns.NewContextBinding(owner, nil, nil, func() bool { return false })
	ctx := featuredns.ContextWithBinding(context.Background(), binding)
	conn, err := DialSystem(ctx, net.TCPDestination(net.LocalHostIP, 443), &SocketConfig{DialerProxy: "bound-proxy"})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("expired binding returned redirected connection")
	}
	var bindingErr *featuredns.CausalBindingError
	if !go_errors.As(err, &bindingErr) {
		t.Fatalf("expired binding error: %v", err)
	}
	if got := handler.dispatches.Load(); got != 0 {
		t.Fatalf("handler dispatches=%d", got)
	}
}

func TestDialSystemDialerProxyPreservesReservedBindingAndOutboundTarget(t *testing.T) {
	previousManager := obm
	t.Cleanup(func() { obm = previousManager })
	handler := &bindingTestOutboundHandler{contexts: make(chan context.Context, 1)}
	obm = &bindingTestOutboundManager{handler: handler}
	owner := featuredns.NewContextOwner()
	var reservations atomic.Int32
	var binding *featuredns.ContextBinding
	binding = featuredns.NewContextBinding(owner, nil, func(ctx context.Context) (context.Context, func(), error) {
		reservations.Add(1)
		return featuredns.ContextWithBinding(ctx, binding), func() {}, nil
	}, func() bool { return true })
	ctx := featuredns.ContextWithBinding(context.Background(), binding)
	destination := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 9}), 443)
	conn, err := DialSystem(ctx, destination, &SocketConfig{DialerProxy: "bound-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var dispatchCtx context.Context
	select {
	case dispatchCtx = <-handler.contexts:
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched")
	}
	if reservations.Load() != 1 || !featuredns.HasContextBinding(dispatchCtx) {
		t.Fatalf("reservation=%d binding=%v", reservations.Load(), featuredns.HasContextBinding(dispatchCtx))
	}
	outbounds := session.OutboundsFromContext(dispatchCtx)
	if len(outbounds) == 0 || outbounds[len(outbounds)-1].Target != destination || outbounds[len(outbounds)-1].Tag != "bound-proxy" {
		t.Fatalf("redirect outbound metadata: %+v", outbounds)
	}
}
