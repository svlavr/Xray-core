package dns

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
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
	mu            sync.RWMutex
	closed        bool
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
	if address := dest.Address; address.Family().IsDomain() {
		u, err := url.Parse(address.Domain())
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(), nil
		case strings.EqualFold(u.Scheme, "https"): // DNS-over-HTTPS Remote mode
			return NewDoHNameServerContext(ctx, u, dispatcher, false, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "h2c"): // DNS-over-HTTPS h2c Remote mode
			return NewDoHNameServerContext(ctx, u, dispatcher, true, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "https+local"): // DNS-over-HTTPS Local mode
			return NewDoHNameServerContext(ctx, u, nil, false, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "h2c+local"): // DNS-over-HTTPS h2c Local mode
			return NewDoHNameServerContext(ctx, u, nil, true, disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "quic+local"): // DNS-over-QUIC Local mode
			return NewQUICNameServerContext(ctx, u, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.Scheme, "tcp"): // DNS-over-TCP Remote mode
			return NewTCPNameServerContext(ctx, u, dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.Scheme, "tcp+local"): // DNS-over-TCP Local mode
			return NewTCPLocalNameServerContext(ctx, u, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.String(), "fakedns"):
			var fd dns.FakeDNSEngine
			err = core.RequireFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				fd = fdns
			})
			if err != nil {
				return nil, err
			}
			return NewFakeDNSServer(fd), nil
		}
	}
	if dest.Network == net.Network_Unknown {
		dest.Network = net.Network_UDP
	}
	if dest.Network == net.Network_UDP { // UDP classic DNS mode
		return NewClassicNameServerContext(ctx, dest, dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP), nil
	}
	return nil, errors.New("No available name server could be created from ", dest).AtWarning()
}

// NewClient creates a DNS client managing a name server with client IP, domain rules and expected IPs.
func NewClient(
	ctx context.Context,
	ns *NameServer,
	clientIP net.IP,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	tag string,
	ipOption dns.IPOption,
	updateRules func(bool),
) (*Client, error) {
	client := &Client{}
	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Create a new server for each client for now
		server, err := NewServer(ctx, ns.Address.AsDestination(), dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP)
		if err != nil {
			return errors.New("failed to create nameserver").Base(err).AtWarning()
		}
		adopted := false
		defer func() {
			if !adopted {
				if closer, ok := server.(interface{ Close() error }); ok {
					_ = closer.Close()
				}
			}
		}()

		_, isLocalDNS := server.(*LocalNameServer)
		updateRules(isLocalDNS)

		// Establish expected IPs
		var expectedMatcher geodata.IPMatcher
		if len(ns.ExpectedIp) > 0 {
			expectedMatcher, err = geodata.IPReg.BuildIPMatcher(ns.ExpectedIp)
			if err != nil {
				return errors.New("failed to create expected ip matcher").Base(err).AtWarning()
			}
		}

		// Establish unexpected IPs
		var unexpectedMatcher geodata.IPMatcher
		if len(ns.UnexpectedIp) > 0 {
			unexpectedMatcher, err = geodata.IPReg.BuildIPMatcher(ns.UnexpectedIp)
			if err != nil {
				return errors.New("failed to create unexpected ip matcher").Base(err).AtWarning()
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

		client.mu.Lock()
		if client.closed || ctx.Err() != nil {
			client.mu.Unlock()
			return errors.New("DNS client closed during construction")
		}
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
		client.mu.Unlock()
		adopted = true
		return nil
	})
	return client, err
}

// Name returns the server name the client manages.
func (c *Client) Name() string {
	c.mu.RLock()
	server := c.server
	c.mu.RUnlock()
	if server == nil {
		return "uninitialized DNS client"
	}
	return server.Name()
}

func (c *Client) IsDisableCache() bool {
	c.mu.RLock()
	server := c.server
	c.mu.RUnlock()
	return server == nil || server.IsDisableCache()
}

func (c *Client) SignalStop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	server := c.server
	c.mu.Unlock()
	if signaler, ok := server.(interface{ SignalStop() }); ok {
		signaler.SignalStop()
	}
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.SignalStop()
	c.mu.RLock()
	server := c.server
	c.mu.RUnlock()
	if closer, ok := server.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// QueryIP sends DNS query to the name server with the client's IP.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	c.mu.RLock()
	server := c.server
	closed := c.closed
	c.mu.RUnlock()
	if closed || server == nil {
		return nil, 0, errors.New("DNS client is not available")
	}
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
	ips, ttl, err := server.QueryIP(ctx, domain, option)
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
