//go:build (linux && !android) || freebsd

package tun

import (
	"context"
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/dns"
)

// probeSourcePort is a representative client port for the routing probe. A real
// query arrives from an ephemeral port that cannot be known in advance, so this
// only matters for a rule that matches on a source port.
const probeSourcePort = 49152

// verifyDNSRouting reports whether a DNS query to address would actually be
// handled. Redirecting the system resolver at an address nothing answers would
// break name resolution outright, so the takeover only proceeds when routing
// hands such a query to a DNS-capable outbound.
//
// Overridable for tests.
var verifyDNSRouting = func(ctx context.Context, inboundTag, source, address string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return errors.New("invalid DNS address ", address).Base(err)
	}
	src, err := netip.ParseAddr(source)
	if err != nil || src.Is4() != ip.Is4() {
		return errors.New("invalid source address ", source).Base(err)
	}

	instance := core.FromContext(ctx)
	if instance == nil {
		return errors.New("core instance unavailable")
	}

	// Any resolution path that could still reach the system resolver has to be
	// refused, because pointing the system resolver at the TUN would close a
	// loop through the DNS outbound. With no `dns` section Core installs such a
	// client; with a `dns` section that has no name servers app/dns falls back
	// to one; and a name server pointed at "localhost" is one even when
	// independent upstreams are configured alongside it, because name servers
	// are selected per domain.
	switch dnsFeature := instance.GetFeature(feature_dns.ClientType()).(type) {
	case *localdns.Client:
		return errors.New("DNS feature is the system resolver, takeover would loop")
	case feature_dns.SystemDNSClient:
		if dnsFeature.MayUseSystemResolver() {
			return errors.New("DNS configuration may resolve through the system resolver, takeover would loop")
		}
	default:
		return errors.New("DNS feature does not support safe system DNS takeover")
	}

	router, ok := instance.GetFeature(routing.RouterType()).(routing.Router)
	if !ok {
		return errors.New("router feature unavailable")
	}

	manager, ok := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return errors.New("outbound manager unavailable")
	}

	// Each protocol selects its own actual route with the interface's source.
	// Fresh metadata fences inherited USER identity and forced route/content
	// state while retaining the caller's cancellation and deadline.
	pick := func(network xnet.Network) (context.Context, outbound.Handler, xnet.Destination, error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, xnet.Destination{}, err
		}
		target := xnet.Destination{Network: network, Address: xnet.IPAddress(ip.AsSlice()), Port: 53}
		queryCtx := session.ContextWithTrafficOrigin(ctx, session.TrafficOriginInternal)
		queryCtx = session.ContextWithLogicalObservation(queryCtx, nil)
		queryCtx = session.ContextWithContent(queryCtx, &session.Content{})
		queryCtx = session.ContextWithInbound(queryCtx, &session.Inbound{
			Name: "tun", Tag: inboundTag,
			Source: xnet.Destination{Network: network, Address: xnet.IPAddress(src.AsSlice()), Port: probeSourcePort},
		})
		queryCtx = session.ContextWithOutbounds(queryCtx, []*session.Outbound{{Target: target}})
		route, err := router.PickRoute(routingsession.AsRoutingContext(queryCtx))
		if err != nil {
			return nil, nil, target, errors.New("no route for ", target).Base(err)
		}
		if err := queryCtx.Err(); err != nil {
			return nil, nil, target, err
		}
		if route == nil {
			return nil, nil, target, errors.New("no route for ", target)
		}
		handler := manager.GetHandler(route.GetOutboundTag())
		if handler == nil {
			return nil, nil, target, errors.New("outbound ", route.GetOutboundTag(), " does not exist")
		}
		return queryCtx, handler, target, nil
	}

	queryCtx, handler, target, err := pick(xnet.Network_UDP)
	if err != nil {
		return err
	}
	// Preserve native UDP DNS recognition. Only custom gateways require the
	// independent full-message UDP and TCP serving checks below.
	if settings := handler.ProxySettings(); settings != nil && settings.Type == serial.GetMessageType(&dns.Config{}) {
		return ctx.Err()
	}
	for _, network := range []xnet.Network{xnet.Network_UDP, xnet.Network_TCP} {
		if network == xnet.Network_TCP {
			queryCtx, handler, target, err = pick(network)
			if err != nil {
				return err
			}
		}
		getter, ok := handler.(proxy.GetOutbound)
		if !ok {
			return errors.New("outbound ", handler.Tag(), " does not expose its DNS gateway")
		}
		gateway, ok := getter.GetOutbound().(feature_dns.SystemDNSGateway)
		if !ok {
			return errors.New("outbound ", handler.Tag(), " does not handle DNS at ", target)
		}
		if err := queryCtx.Err(); err != nil {
			return err
		}
		if err := gateway.VerifySystemDNS(queryCtx, target); err != nil {
			return errors.New("outbound ", handler.Tag(), " does not serve DNS at ", target).Base(err)
		}
		if err := queryCtx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// acquireSystemDNS holds the selected nonrecursive resolver path through OS
// takeover and revert. Platform-only tests may omit a core instance.
func acquireSystemDNS(ctx context.Context) (func(), error) {
	instance := core.FromContext(ctx)
	if instance == nil {
		return nil, nil
	}
	client, ok := instance.GetFeature(feature_dns.ClientType()).(feature_dns.SystemDNSClient)
	if !ok {
		return nil, errors.New("DNS feature does not support safe system DNS takeover")
	}
	release, err := client.AcquireSystemDNS()
	if err != nil {
		return nil, err
	}
	if release == nil {
		return nil, errors.New("DNS feature returned no system DNS lease")
	}
	return release, nil
}
