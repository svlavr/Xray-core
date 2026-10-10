// Package dns is an implementation of core.DNS feature.
package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
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

// DNS is a DNS rely server.
type DNS struct {
	disableFallback        bool
	disableFallbackIfMatch bool
	enableParallelQuery    bool
	ipOption               *dns.IPOption
	hosts                  *StaticHosts
	clients                []*Client
	ctx                    context.Context
	domainMatcher          geodata.DomainMatcher
	matcherInfos           []*DomainMatcherInfo
	checkSystem            bool
	strictSelection        bool
	queries                sync.WaitGroup
	runtime                *dnsRuntime
	scriptMu               sync.RWMutex
	script                 *scriptEngine
	scriptPath             string
}

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher.
type DomainMatcherInfo struct {
	clientIdx  uint16
	domainRule string
}

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	config = proto.Clone(config).(*Config)
	needsFakeDNS := false
	for _, ns := range config.NameServer {
		needsFakeDNS = needsFakeDNS || strings.EqualFold(ns.Address.Address.GetDomain(), "fakedns")
	}
	if len(config.NameServer) == 0 {
		prepared, err := buildDNS(ctx, config, nil, nil)
		if err != nil {
			return nil, err
		}
		stable := &DNS{ctx: ctx}
		stable.initRuntime(prepared)
		return stable, nil
	}
	s := &DNS{ctx: ctx}
	build := func(dispatcher routing.Dispatcher, fake dns.FakeDNSEngine) error {
		prepared, err := buildDNS(ctx, config, dispatcher, fake)
		if err == nil {
			s.initRuntime(prepared)
		}
		return err
	}
	var err error
	if needsFakeDNS {
		err = core.RequireFeatures(ctx, build)
	} else {
		err = core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
			return build(dispatcher, nil)
		})
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// buildDNS consumes candidate-owned configuration and already resolved features.
// It never registers dependency callbacks or starts nameserver I/O or workers.
func buildDNS(ctx context.Context, config *Config, dispatcher routing.Dispatcher, fake dns.FakeDNSEngine) (*DNS, error) {
	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, errors.New("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption dns.IPOption
	checkSystem := false
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case QueryStrategy_USE_SYS:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
		checkSystem = true
	case QueryStrategy_USE_IP4:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	default:
		return nil, errors.New("unexpected query strategy ", config.QueryStrategy)
	}

	hosts, err := NewStaticHosts(config.StaticHosts)
	if err != nil {
		return nil, errors.New("failed to create hosts").Base(err)
	}

	defaultTag := config.Tag
	if len(config.Tag) == 0 {
		defaultTag = generateRandomTag()
	}

	clients := make([]*Client, 0, len(config.NameServer))
	matcherInfos := make([]*DomainMatcherInfo, 0)
	effectiveRules := make([]*geodata.DomainRule, 0)

	for _, ns := range config.NameServer {
		clientIdx := len(clients)
		updateRules := func(isLocalNameServer bool) {
			// Prioritize local domains with specific TLDs or those without any dot for the local DNS
			if isLocalNameServer {
				effectiveRules = append(effectiveRules, localTLDsAndDotlessDomainsRules...)
				for _, rule := range localTLDsAndDotlessDomainsRules {
					matcherInfos = append(matcherInfos, &DomainMatcherInfo{
						clientIdx:  uint16(clientIdx),
						domainRule: rule.String(),
					})
				}
			}

			effectiveRules = append(effectiveRules, ns.Domain...)
			for _, rule := range ns.Domain {
				matcherInfos = append(matcherInfos, &DomainMatcherInfo{
					clientIdx:  uint16(clientIdx),
					domainRule: rule.String(),
				})
			}
		}

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}

		disableCache := config.DisableCache
		if ns.DisableCache != nil {
			disableCache = *ns.DisableCache
		}

		serveStale := config.ServeStale
		if ns.ServeStale != nil {
			serveStale = *ns.ServeStale
		}

		serveExpiredTTL := config.ServeExpiredTTL
		if ns.ServeExpiredTTL != nil {
			serveExpiredTTL = *ns.ServeExpiredTTL
		}

		tag := defaultTag
		if len(ns.Tag) > 0 {
			tag = ns.Tag
		}

		clientIPOption := ResolveIpOptionOverride(ns.QueryStrategy, ipOption)
		if !clientIPOption.IPv4Enable && !clientIPOption.IPv6Enable {
			return nil, errors.New("no QueryStrategy available for ", ns.Address)
		}

		client, err := newClient(ctx, ns, myClientIP, disableCache, serveStale, serveExpiredTTL, tag, clientIPOption, dispatcher, fake)
		if err != nil {
			return nil, errors.New("failed to create client").Base(err)
		}
		_, isLocal := client.server.(*LocalNameServer)
		updateRules(isLocal)
		clients = append(clients, client)
	}

	var domainMatcher geodata.DomainMatcher
	if len(effectiveRules) > 0 {
		domainMatcher, err = geodata.DomainReg.BuildDomainMatcher(effectiveRules)
		if err != nil {
			return nil, err
		}
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient(ipOption))
	}

	return &DNS{
		hosts:                  hosts,
		ipOption:               &ipOption,
		clients:                clients,
		ctx:                    ctx,
		domainMatcher:          domainMatcher,
		matcherInfos:           matcherInfos,
		disableFallback:        config.DisableFallback,
		disableFallbackIfMatch: config.DisableFallbackIfMatch,
		enableParallelQuery:    config.EnableParallelQuery,
		checkSystem:            checkSystem,
		scriptPath:             config.Script,
	}, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	if s.runtime == nil {
		return s.startNativeScript()
	}
	return s.startRuntime()
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	if s.runtime == nil {
		if engine := s.getScript(); engine != nil {
			engine.close()
		}
		return nil
	}
	rt := s.runtime
	rt.mu.Lock()
	if rt.current != nil {
		rt.current.cancel()
	}
	if rt.closing != nil {
		rt.closing.cancel()
	}
	current, closing := rt.current, rt.closing
	rt.mu.Unlock()
	var errs []error
	if current != nil {
		current.startClose()
	}
	if closing != nil {
		closing.startClose()
	}
	if current != nil {
		errs = append(errs, current.closeOwned())
	}
	if closing != nil {
		errs = append(errs, closing.closeOwned())
	}
	rt.mu.Lock()
	rt.current, rt.closing = nil, nil
	rt.mu.Unlock()
	return go_errors.Join(errs...)
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return false
	}
	if s.runtime == nil {
		return false
	}
	s.runtime.mu.Lock()
	current, closing := s.runtime.current, s.runtime.closing
	s.runtime.mu.Unlock()
	for _, owner := range []*resolverOwner{current, closing} {
		if owner != nil {
			for _, client := range owner.resolver.clients {
				if inbound.Tag == client.tag {
					return true
				}
			}
		}
	}
	return false
}

// MayUseSystemResolver reports whether any name server configured here could
// still resolve through the system resolver. That is what happens when no name
// server is configured at all, and it is also what a name server pointed at
// "localhost" does. Callers that are about to redirect the system resolver need
// to know, because a resolution path that reaches it would then loop back to
// them.
//
// Any such server is enough: name servers can be selected per domain, so a
// single local one makes some query reach the system resolver even when
// independent upstreams are configured alongside it.
func (s *DNS) MayUseSystemResolver() bool {
	if s.runtime == nil {
		return resolverMayUseSystem(s)
	}
	rt := s.runtime
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.current == nil || rt.current.ctx.Err() != nil {
		return true
	}
	return resolverMayUseSystem(rt.current.resolver) || (rt.closing != nil && resolverMayUseSystem(rt.closing.resolver))
}

func resolverMayUseSystem(s *DNS) bool {
	if s == nil || len(s.clients) == 0 {
		return true
	}
	for _, client := range s.clients {
		switch server := client.server.(type) {
		case *LocalNameServer:
			return true
		case *TCPNameServer:
			if !server.routed && server.destination.Address.Family().IsDomain() {
				return true
			}
		case *DoHNameServer:
			if server.systemResolver {
				return true
			}
		case *QUICNameServer:
			if server.destination.Address.Family().IsDomain() {
				return true
			}
		}
	}
	return false
}

// AcquireSystemDNS keeps a safe published resolver in place while Linux owns
// per-link system DNS settings. The caller releases it after successful revert.
func (s *DNS) AcquireSystemDNS() (func(), error) {
	if s == nil || s.runtime == nil {
		return nil, fmt.Errorf("DNS resolver unavailable")
	}
	rt := s.runtime
	rt.systemDNSMu.RLock()
	rt.mu.Lock()
	unsafe := rt.current == nil || rt.current.ctx.Err() != nil || resolverMayUseSystem(rt.current.resolver) ||
		(rt.closing != nil && resolverMayUseSystem(rt.closing.resolver))
	rt.mu.Unlock()
	if unsafe {
		rt.systemDNSMu.RUnlock()
		return nil, fmt.Errorf("DNS configuration may resolve through the system resolver, takeover would loop or resolver is unavailable")
	}
	return rt.systemDNSMu.RUnlock, nil
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	return s.LookupIPContext(s.ctx, domain, option)
}

// LookupIPContext implements dns.ContextClient with caller cancellation.
func (s *DNS) LookupIPContext(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if s.runtime == nil {
		return s.lookupIP(ctx, domain, option)
	}
	rt := s.runtime
	rt.mu.Lock()
	owner := resolverFromContext(ctx, rt)
	if owner == nil {
		owner = rt.current
	}
	if owner == nil || owner.ctx.Err() != nil {
		rt.mu.Unlock()
		return nil, 0, context.Canceled
	}
	owner.resolver.queries.Add(1)
	rt.mu.Unlock()
	defer owner.resolver.queries.Done()

	base := context.Background()
	if core.FromContext(s.ctx) != nil {
		base = core.ToBackgroundDetachedContext(s.ctx)
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		base = session.ContextWithInbound(base, inbound)
	}
	if content := session.ContentFromContext(ctx); content != nil {
		base = session.ContextWithContent(base, content)
	}
	base = bindResolverContext(base, rt, owner)
	queryCtx, cancel := context.WithCancel(base)
	stopCaller := context.AfterFunc(ctx, cancel)
	stopOwner := context.AfterFunc(owner.ctx, cancel)
	defer stopCaller()
	defer stopOwner()
	defer cancel()
	return owner.resolver.lookupIP(queryCtx, domain, option)
}

func (s *DNS) lookupIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	// Normalize the FQDN form query
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil, 0, errors.New("empty domain name")
	}

	if s.checkSystem {
		supportIPv4, supportIPv6 := utils.CheckRoutes()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && s.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && s.ipOption.IPv6Enable
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	// Static host lookup
	switch addrs, err := s.hosts.Lookup(domain, option); {
	case err != nil:
		if go_errors.Is(err, dns.ErrEmptyResponse) {
			return nil, 0, dns.ErrEmptyResponse
		}
		return nil, 0, errors.New("returning nil for domain ", domain).Base(err)
	case addrs == nil: // Domain not recorded in static host
		break
	case len(addrs) == 0: // Domain recorded, but no valid IP returned (e.g. IPv4 address with only IPv6 enabled)
		return nil, 0, dns.ErrEmptyResponse
	case len(addrs) == 1 && addrs[0].Family().IsDomain(): // Domain replacement
		errors.LogInfo(s.ctx, "domain replaced: ", domain, " -> ", addrs[0].Domain())
		domain = addrs[0].Domain()
	default: // Successfully found ip records in static host
		errors.LogInfo(s.ctx, "returning ", len(addrs), " IP(s) for domain ", domain, " -> ", addrs)
		ips, err := toNetIP(addrs)
		if err != nil {
			return nil, 0, err
		}
		return ips, 10, nil // Hosts ttl is 10
	}

	// Name servers lookup
	if engine := s.getScript(); engine != nil {
		return engine.queryContext(ctx, domain, option)
	}
	if s.enableParallelQuery {
		return s.parallelQuery(ctx, domain, option)
	} else {
		return s.serialQuery(ctx, domain, option)
	}
}

func (s *DNS) sortClients(domain string) []*Client {
	clients := make([]*Client, 0, len(s.clients))
	clientUsed := make([]bool, len(s.clients))
	clientNames := make([]string, 0, len(s.clients))
	domainRules := []string{}

	// Priority domain matching
	hasMatch := false
	if s.domainMatcher != nil {
		matchSlice := s.domainMatcher.Match(strings.ToLower(domain))
		sort.Slice(matchSlice, func(i, j int) bool {
			return matchSlice[i] < matchSlice[j]
		})
		for _, match := range matchSlice {
			info := s.matcherInfos[match]
			client := s.clients[info.clientIdx]
			domainRule := info.domainRule
			domainRules = append(domainRules, fmt.Sprintf("%s(DNS idx:%d)", domainRule, info.clientIdx))
			if clientUsed[info.clientIdx] {
				continue
			}
			clientUsed[info.clientIdx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
			hasMatch = true
			if client.finalQuery {
				logDecision(s.ctx, domain, domainRules, clientNames)
				return clients
			}
		}
	}

	if !(s.disableFallback || s.disableFallbackIfMatch && hasMatch) {
		// Default round-robin query
		for idx, client := range s.clients {
			if clientUsed[idx] || client.skipFallback {
				continue
			}
			clientUsed[idx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
			if client.finalQuery {
				logDecision(s.ctx, domain, domainRules, clientNames)
				return clients
			}
		}
	}

	logDecision(s.ctx, domain, domainRules, clientNames)

	if len(clients) == 0 {
		if len(s.clients) > 0 && !s.strictSelection {
			clients = append(clients, s.clients[0])
			clientNames = append(clientNames, s.clients[0].Name())
			errors.LogWarning(s.ctx, "domain ", domain, " will use the first DNS: ", clientNames)
		} else {
			errors.LogError(s.ctx, "no DNS clients available for domain ", domain, " and no default clients configured")
		}
	}

	return clients
}

func logDecision(ctx context.Context, domain string, domainRules []string, clientNames []string) {
	if len(domainRules) > 0 {
		errors.LogDebug(ctx, "domain ", domain, " matches following rules: ", domainRules)
	}
	if len(clientNames) > 0 {
		errors.LogDebug(ctx, "domain ", domain, " will use DNS in order: ", clientNames)
	}
}

func mergeQueryErrors(domain string, errs []error) error {
	if len(errs) == 0 {
		return dns.ErrEmptyResponse
	}

	var noRNF error
	for _, err := range errs {
		if go_errors.Is(err, errRecordNotFound) {
			continue // server no response, ignore
		} else if noRNF == nil {
			noRNF = err
		} else if !go_errors.Is(err, noRNF) {
			return errors.New("returning nil for domain ", domain).Base(errors.Combine(errs...))
		}
	}
	if go_errors.Is(noRNF, dns.ErrEmptyResponse) {
		return dns.ErrEmptyResponse
	}
	if noRNF == nil {
		noRNF = errRecordNotFound
	}
	return errors.New("returning nil for domain ", domain).Base(noRNF)
}

func (s *DNS) serialQuery(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var errs []error
	for _, client := range s.sortClients(domain) {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(s.ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			continue
		}

		ips, ttl, err := client.QueryIP(ctx, domain, option)

		if len(ips) > 0 {
			return ips, ttl, nil
		}

		errors.LogInfoInner(s.ctx, err, "failed to lookup ip for domain ", domain, " at server ", client.Name(), " in serial query mode")
		if err == nil {
			err = dns.ErrEmptyResponse
		}
		errs = append(errs, err)
	}
	return nil, 0, mergeQueryErrors(domain, errs)
}

func (s *DNS) parallelQuery(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var errs []error
	clients := s.sortClients(domain)

	resultsChan := s.asyncQueryAll(domain, option, clients, ctx)

	groups, groupOf := makeGroups( /*s.ctx,*/ clients)
	results := make([]*queryResult, len(clients))
	pending := make([]int, len(groups))
	for gi, g := range groups {
		pending[gi] = g.end - g.start + 1
	}

	nextGroup := 0
	for range clients {
		result := <-resultsChan
		results[result.index] = &result

		gi := groupOf[result.index]
		pending[gi]--

		for nextGroup < len(groups) {
			g := groups[nextGroup]

			// group race, minimum rtt -> return
			for j := g.start; j <= g.end; j++ {
				r := results[j]
				if r != nil && r.err == nil && len(r.ips) > 0 {
					return r.ips, r.ttl, nil
				}
			}

			// current group is incomplete and no one success -> continue pending
			if pending[nextGroup] > 0 {
				break
			}

			// all failed -> log and continue next group
			for j := g.start; j <= g.end; j++ {
				r := results[j]
				e := r.err
				if e == nil {
					e = dns.ErrEmptyResponse
				}
				errors.LogInfoInner(s.ctx, e, "failed to lookup ip for domain ", domain, " at server ", clients[j].Name(), " in parallel query mode")
				errs = append(errs, e)
			}
			nextGroup++
		}
	}

	return nil, 0, mergeQueryErrors(domain, errs)
}

type queryResult struct {
	ips   []net.IP
	ttl   uint32
	err   error
	index int
}

func (s *DNS) asyncQueryAll(domain string, option dns.IPOption, clients []*Client, ctx context.Context) chan queryResult {
	if len(clients) == 0 {
		ch := make(chan queryResult)
		close(ch)
		return ch
	}

	ch := make(chan queryResult, len(clients))
	for i, client := range clients {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			ch <- queryResult{err: dns.ErrEmptyResponse, index: i}
			continue
		}

		s.queries.Add(1)
		go func(i int, c *Client, qctx context.Context) {
			defer s.queries.Done()
			if !c.server.IsDisableCache() {
				nctx, cancel := context.WithTimeout(qctx, c.timeoutMs*2)
				qctx = nctx
				defer cancel()
			}
			ips, ttl, err := c.QueryIP(qctx, domain, option)
			ch <- queryResult{ips: ips, ttl: ttl, err: err, index: i}
		}(i, client, ctx)
	}
	return ch
}

type group struct{ start, end int }

// merge only adjacent and rule-equivalent Client into a single group
func makeGroups( /*ctx context.Context,*/ clients []*Client) ([]group, []int) {
	n := len(clients)
	if n == 0 {
		return nil, nil
	}
	groups := make([]group, 0, n)
	groupOf := make([]int, n)

	s, e := 0, 0
	for i := 1; i < n; i++ {
		if clients[i-1].policyID == clients[i].policyID {
			e = i
		} else {
			for k := s; k <= e; k++ {
				groupOf[k] = len(groups)
			}
			groups = append(groups, group{start: s, end: e})
			s, e = i, i
		}
	}
	for k := s; k <= e; k++ {
		groupOf[k] = len(groups)
	}
	groups = append(groups, group{start: s, end: e})

	// var b strings.Builder
	// b.WriteString("dns grouping: total clients=")
	// b.WriteString(strconv.Itoa(n))
	// b.WriteString(", groups=")
	// b.WriteString(strconv.Itoa(len(groups)))

	// for gi, g := range groups {
	// 	b.WriteString("\n  [")
	// 	b.WriteString(strconv.Itoa(g.start))
	// 	b.WriteString("..")
	// 	b.WriteString(strconv.Itoa(g.end))
	// 	b.WriteString("] gid=")
	// 	b.WriteString(strconv.Itoa(gi))
	// 	b.WriteString(" pid=")
	// 	b.WriteString(strconv.FormatUint(uint64(clients[g.start].policyID), 10))
	// 	b.WriteString(" members: ")

	// 	for i := g.start; i <= g.end; i++ {
	// 		if i > g.start {
	// 			b.WriteString(", ")
	// 		}
	// 		b.WriteString(strconv.Itoa(i))
	// 		b.WriteByte(':')
	// 		b.WriteString(clients[i].Name())
	// 	}
	// }
	// errors.LogDebug(ctx, b.String())

	return groups, groupOf
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
