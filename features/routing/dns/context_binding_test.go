package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	featuredns "github.com/xtls/xray-core/features/dns"
	routingsession "github.com/xtls/xray-core/features/routing/session"
)

type bindingTestClient struct{ ip net.IP }

func (*bindingTestClient) Type() interface{} { return featuredns.ClientType() }
func (*bindingTestClient) Start() error      { return nil }
func (*bindingTestClient) Close() error      { return nil }
func (c *bindingTestClient) LookupIP(string, featuredns.IPOption) ([]net.IP, uint32, error) {
	return []net.IP{c.ip}, 1, nil
}

func TestResolvableContextUsesOriginatingDNSBinding(t *testing.T) {
	owner := featuredns.NewContextOwner()
	binding := featuredns.NewContextBinding(owner,
		func(context.Context, string, featuredns.IPOption) ([]net.IP, uint32, error) {
			return []net.IP{{192, 0, 2, 1}}, 1, nil
		}, nil, func() bool { return true })
	ctx := featuredns.ContextWithBinding(context.Background(), binding)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("bound.test"), 443),
	}})
	routingContext := routingsession.AsRoutingContext(ctx)
	resolved := ContextWithDNSClient(routingContext, &bindingTestClient{ip: net.IP{192, 0, 2, 2}})
	ips := resolved.GetTargetIPs()
	if len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 1}) {
		t.Fatalf("routing context dropped originating binding: %v", ips)
	}
}
