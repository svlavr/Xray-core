package internet

import (
	"context"
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

type contextAwareTestDNSClient struct {
	contextTestDNSClient
	seen context.Context
}

func (c *contextAwareTestDNSClient) LookupIPContext(ctx context.Context, _ string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	c.seen = ctx
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

type dnsContextKey struct{}

func TestLookupForIPContextUsesContextClientAndCancellation(t *testing.T) {
	previous := dnsClient
	t.Cleanup(func() { dnsClient = previous })
	client := &contextAwareTestDNSClient{contextTestDNSClient: contextTestDNSClient{ip: net.IP{192, 0, 2, 1}}}
	dnsClient = client
	ctx := context.WithValue(context.Background(), dnsContextKey{}, "lookup")
	ips, err := LookupForIPContext(ctx, "example.test", DomainStrategy_USE_IP4, nil)
	if err != nil || len(ips) != 1 || client.seen.Value(dnsContextKey{}) != "lookup" {
		t.Fatalf("context lookup: ips=%v err=%v", ips, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := LookupForIPContext(canceled, "example.test", DomainStrategy_USE_IP4, nil); err != context.Canceled {
		t.Fatalf("canceled lookup: %v", err)
	}
}

func TestDialSystemCanceledContextRejectsDialerProxy(t *testing.T) {
	previousManager := obm
	t.Cleanup(func() { obm = previousManager })
	handler := new(bindingTestOutboundHandler)
	obm = &bindingTestOutboundManager{handler: handler}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := DialSystem(ctx, net.TCPDestination(net.LocalHostIP, 443), &SocketConfig{DialerProxy: "bound-proxy"})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("canceled dial returned connection")
	}
	if err != context.Canceled || handler.dispatches.Load() != 0 {
		t.Fatalf("canceled dial: err=%v dispatches=%d", err, handler.dispatches.Load())
	}
}

func TestDialSystemDialerProxyPreservesContextAndTarget(t *testing.T) {
	previousManager := obm
	t.Cleanup(func() { obm = previousManager })
	handler := &bindingTestOutboundHandler{contexts: make(chan context.Context, 1)}
	obm = &bindingTestOutboundManager{handler: handler}
	ctx := context.WithValue(context.Background(), dnsContextKey{}, "redirect")
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
	if dispatchCtx.Value(dnsContextKey{}) != "redirect" {
		t.Fatal("redirect context values lost")
	}
	outbounds := session.OutboundsFromContext(dispatchCtx)
	if len(outbounds) == 0 || outbounds[len(outbounds)-1].Target != destination || outbounds[len(outbounds)-1].Tag != "bound-proxy" {
		t.Fatalf("redirect outbound metadata: %+v", outbounds)
	}
}
