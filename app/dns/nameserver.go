package dns

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// Server is the interface for Name Server.
type Server interface {
	// Name of the Client.
	Name() string

	IsDisableCache() bool

	// QueryIP sends IP queries to its configured server.
	QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error)
}

// Client is the interface for DNS client.
type Client struct {
	server        Server
	skipFallback  bool
	expectedIPs   geodata.IPMatcher
	unexpectedIPs geodata.IPMatcher
	actPrior      bool
	actUnprior    bool
	tag           string
	timeoutMs     time.Duration
	finalQuery    bool
	ipOption      *dns.IPOption
	checkSystem   bool
	policyID      uint32
}

// NewServer creates a name server object according to the network destination url.
func NewServer(ctx context.Context, dest net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (Server, error) {
	var fake dns.FakeDNSEngine
	if instance := core.FromContext(ctx); instance != nil {
		fake, _ = instance.GetFeature((*dns.FakeDNSEngine)(nil)).(dns.FakeDNSEngine)
	}
	return newServer(ctx, dest, dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP, fake)
}

func newServer(ctx context.Context, dest net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP, fake dns.FakeDNSEngine) (Server, error) {
	if dest.Address == nil {
		return nil, errors.New("missing nameserver address")
	}
	if address := dest.Address; address.Family().IsDomain() {
		u, err := url.Parse(address.Domain())
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(), nil
		case strings.EqualFold(u.Scheme, "https"): // DNS-over-HTTPS Remote mode
			if dispatcher == nil {
				return nil, &readyDependencyError{name: "dispatcher"}
			}
			return NewDoHNameServer(u, dispatcher, false, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "h2c"): // DNS-over-HTTPS h2c Remote mode
			if dispatcher == nil {
				return nil, &readyDependencyError{name: "dispatcher"}
			}
			return NewDoHNameServer(u, dispatcher, true, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "https+local"): // DNS-over-HTTPS Local mode
			return NewDoHNameServer(u, nil, false, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "h2c+local"): // DNS-over-HTTPS h2c Local mode
			return NewDoHNameServer(u, nil, true, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "quic+local"): // DNS-over-QUIC Local mode
			return NewQUICNameServer(u, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.Scheme, "tcp"): // DNS-over-TCP Remote mode
			if dispatcher == nil {
				return nil, &readyDependencyError{name: "dispatcher"}
			}
			return NewTCPNameServer(u, dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.Scheme, "tcp+local"): // DNS-over-TCP Local mode
			return NewTCPLocalNameServer(u, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.String(), "fakedns"):
			if fake == nil {
				return nil, &readyDependencyError{name: "FakeDNS engine"}
			}
			return NewFakeDNSServer(fake), nil
		}
	}
	if dest.Network == net.Network_Unknown {
		dest.Network = net.Network_UDP
	}
	if dest.Network == net.Network_UDP { // UDP classic DNS mode
		if dispatcher == nil {
			return nil, &readyDependencyError{name: "dispatcher"}
		}
		return NewClassicNameServer(dest, dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP), nil
	}
	return nil, errors.New("No available name server could be created from ", dest).AtWarning()
}

// NewClient creates a complete DNS client using already registered features.
// Dependency ordering during core bootstrap is handled once by DNS.New.
func NewClient(
	ctx context.Context,
	ns *NameServer,
	clientIP net.IP,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	tag string,
	ipOption dns.IPOption,
	updateRules func(bool),
) (*Client, error) {
	instance := core.FromContext(ctx)
	if instance == nil {
		return nil, errors.New("missing DNS instance")
	}
	dispatcher, _ := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	fake, _ := instance.GetFeature((*dns.FakeDNSEngine)(nil)).(dns.FakeDNSEngine)
	if ns == nil {
		return nil, errors.New("missing nameserver config")
	}
	client, err := newClient(ctx, proto.Clone(ns).(*NameServer), append(net.IP(nil), clientIP...), disableCache, serveStale, serveExpiredTTL, tag, ipOption, dispatcher, fake)
	if err == nil && updateRules != nil {
		_, local := client.server.(*LocalNameServer)
		updateRules(local)
	}
	return client, err
}

func newClient(
	ctx context.Context,
	ns *NameServer,
	clientIP net.IP,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	tag string,
	ipOption dns.IPOption,
	dispatcher routing.Dispatcher,
	fake dns.FakeDNSEngine,
) (*Client, error) {
	if ns == nil || ns.Address == nil || ns.Address.Address == nil {
		return nil, errors.New("missing nameserver address")
	}
	client := &Client{}
	// Create a new server for each client for now
	server, err := newServer(ctx, ns.Address.AsDestination(), dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP, fake)
	if err != nil {
		return nil, errors.New("failed to create nameserver").Base(err).AtWarning()
	}

	// Establish expected IPs
	var expectedMatcher geodata.IPMatcher
	if len(ns.ExpectedIp) > 0 {
		expectedMatcher, err = geodata.IPReg.BuildIPMatcher(ns.ExpectedIp)
		if err != nil {
			return nil, errors.New("failed to create expected ip matcher").Base(err).AtWarning()
		}
	}

	// Establish unexpected IPs
	var unexpectedMatcher geodata.IPMatcher
	if len(ns.UnexpectedIp) > 0 {
		unexpectedMatcher, err = geodata.IPReg.BuildIPMatcher(ns.UnexpectedIp)
		if err != nil {
			return nil, errors.New("failed to create unexpected ip matcher").Base(err).AtWarning()
		}
	}

	if len(clientIP) > 0 {
		switch ns.Address.Address.GetAddress().(type) {
		case *net.IPOrDomain_Domain:
			errors.LogInfo(ctx, "DNS: client ", ns.Address.Address.GetDomain(), " uses clientIP ", clientIP.String())
		case *net.IPOrDomain_Ip:
			errors.LogInfo(ctx, "DNS: client ", net.IP(ns.Address.Address.GetIp()), " uses clientIP ", clientIP.String())
		}
	}

	timeoutMs := 4000 * time.Millisecond
	if ns.TimeoutMs > 0 {
		timeoutMs = time.Duration(ns.TimeoutMs) * time.Millisecond
	}

	checkSystem := ns.QueryStrategy == QueryStrategy_USE_SYS

	client.server = server
	client.skipFallback = ns.SkipFallback
	client.expectedIPs = expectedMatcher
	client.unexpectedIPs = unexpectedMatcher
	client.actPrior = ns.ActPrior
	client.actUnprior = ns.ActUnprior
	client.tag = tag
	client.timeoutMs = timeoutMs
	client.finalQuery = ns.FinalQuery
	client.ipOption = &ipOption
	client.checkSystem = checkSystem
	client.policyID = ns.PolicyID
	return client, nil
}

// Name returns the server name the client manages.
func (c *Client) Name() string {
	return c.server.Name()
}

// QueryIP sends DNS query to the name server with the client's IP.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if c.checkSystem {
		supportIPv4, supportIPv6 := utils.CheckRoutes()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && c.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && c.ipOption.IPv6Enable
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeoutMs)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginInternal)
	ips, ttl, err := c.server.QueryIP(ctx, domain, option)
	cancel()

	if err != nil {
		return nil, 0, err
	}

	if len(ips) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}

	if c.expectedIPs != nil && !c.actPrior {
		ips, _ = c.expectedIPs.FilterIPs(ips)
		errors.LogDebug(context.Background(), "domain ", domain, " expectedIPs ", ips, " matched at server ", c.Name())
		if len(ips) == 0 {
			return nil, 0, dns.ErrEmptyResponse
		}
	}

	if c.unexpectedIPs != nil && !c.actUnprior {
		_, ips = c.unexpectedIPs.FilterIPs(ips)
		errors.LogDebug(context.Background(), "domain ", domain, " unexpectedIPs ", ips, " matched at server ", c.Name())
		if len(ips) == 0 {
			return nil, 0, dns.ErrEmptyResponse
		}
	}

	if c.expectedIPs != nil && c.actPrior {
		ipsNew, _ := c.expectedIPs.FilterIPs(ips)
		if len(ipsNew) > 0 {
			ips = ipsNew
			errors.LogDebug(context.Background(), "domain ", domain, " priorIPs ", ips, " matched at server ", c.Name())
		}
	}

	if c.unexpectedIPs != nil && c.actUnprior {
		_, ipsNew := c.unexpectedIPs.FilterIPs(ips)
		if len(ipsNew) > 0 {
			ips = ipsNew
			errors.LogDebug(context.Background(), "domain ", domain, " unpriorIPs ", ips, " matched at server ", c.Name())
		}
	}

	return ips, ttl, nil
}

func ResolveIpOptionOverride(queryStrategy QueryStrategy, ipOption dns.IPOption) dns.IPOption {
	switch queryStrategy {
	case QueryStrategy_USE_IP:
		return ipOption
	case QueryStrategy_USE_SYS:
		return ipOption
	case QueryStrategy_USE_IP4:
		return dns.IPOption{
			IPv4Enable: ipOption.IPv4Enable,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		return dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: ipOption.IPv6Enable,
			FakeEnable: false,
		}
	default:
		return ipOption
	}
}
