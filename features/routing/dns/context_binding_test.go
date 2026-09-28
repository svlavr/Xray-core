package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	featuredns "github.com/xtls/xray-core/features/dns"
	routingsession "github.com/xtls/xray-core/features/routing/session"
)

type contextTestClient struct {
	seen context.Context
}

func (*contextTestClient) Type() interface{} { return featuredns.ClientType() }
func (*contextTestClient) Start() error      { return nil }
func (*contextTestClient) Close() error      { return nil }
func (*contextTestClient) LookupIP(string, featuredns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, featuredns.ErrEmptyResponse
}

func (c *contextTestClient) LookupIPContext(ctx context.Context, _ string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	c.seen = ctx
	return []net.IP{{192, 0, 2, 1}}, 1, nil
}

type routingContextKey struct{}

func TestResolvableContextPreservesOriginatingDNSContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), routingContextKey{}, "origin")
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("owner.test"), 443)}})
	client := new(contextTestClient)
	resolved := ContextWithDNSClient(routingsession.AsRoutingContext(ctx), client)
	ips := resolved.GetTargetIPs()
	if len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 1}) || client.seen.Value(routingContextKey{}) != "origin" {
		t.Fatalf("originating DNS context lost: ips=%v context=%v", ips, client.seen)
	}
}
