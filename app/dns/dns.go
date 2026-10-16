// Package dns is an implementation of core.DNS feature.
package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// resolver is one immutable native configuration with its own cancellation.
type resolver struct {
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
	owner                  *DNS
	cancel                 context.CancelFunc
	queries                sync.WaitGroup
	prepared               *scriptEngine
	script                 atomic.Pointer[scriptEngine]
	initialized            chan struct{}
	closeOnce              sync.Once
	done                   chan struct{}
	closeErr               error
}

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher.
type DomainMatcherInfo struct {
	clientIdx  uint16
	domainRule string
}

// New uses native RequireFeatures ordering once, before calling the unchanged
// native client construction pipeline with ready dependencies.
func New(ctx context.Context, config *Config) (*DNS, error) {
	config = proto.Clone(config).(*Config)
	var prepared *scriptEngine
	if config.Script != "" {
		var err error
		prepared, err = newScriptEngine(config.Script)
		if err != nil {
			return nil, errors.New("failed to prepare DNS script").Base(err)
		}
	}
	s := &DNS{ctx: ctx, pub: pubsub.NewService()}
	install := func() error {
		r, err := s.newResolver(config, prepared)
		if err == nil {
			s.mu.Lock()
			if s.closed {
				r.cancel()
				err = context.Canceled
			} else {
				s.active = r
			}
			s.mu.Unlock()
		}
		return err
	}
	if len(config.NameServer) == 0 {
		if err := install(); err != nil {
			return nil, err
		}
	} else if needsFakeDNS(config) {
		if err := core.RequireFeatures(ctx, func(routing.Dispatcher, dns.FakeDNSEngine) error { return install() }); err != nil {
			return nil, err
		}
	} else {
		if err := core.RequireFeatures(ctx, func(routing.Dispatcher) error { return install() }); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// New creates a new DNS server with given configuration.
func (s *DNS) newResolver(config *Config, prepared *scriptEngine) (*resolver, error) {
	ctx := s.ctx
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

		client, err := NewClient(ctx, ns, myClientIP, disableCache, serveStale, serveExpiredTTL, tag, clientIPOption, updateRules)
		if err != nil {
			return nil, errors.New("failed to create client").Base(err)
		}
		if cached, ok := client.server.(CachedNameserver); ok {
			cached.getCacheController().pub = s.pub
		}
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

	r := &resolver{
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
		prepared:               prepared,
		owner:                  s,
		initialized:            make(chan struct{}),
		done:                   make(chan struct{}),
	}
	base := context.Background()
	if core.FromContext(ctx) != nil {
		base = core.ToBackgroundDetachedContext(ctx)
	}
	r.ctx, r.cancel = context.WithCancel(base)
	r.ctx = context.WithValue(r.ctx, resolverContextKey{}, r)
	close(r.initialized)
	return r, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} { return dns.ClientType() }

func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range []*resolver{s.active, s.pending} {
		if r != nil {
			for _, client := range r.clients {
				if inbound.Tag == client.tag {
					return true
				}
			}
		}
	}
	return false
}

func (s *DNS) MayUseSystemResolver() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || resolverMayUseSystem(s.active) || (s.pending != nil && resolverMayUseSystem(s.pending))
}

func resolverMayUseSystem(s *resolver) bool {
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

func (s *DNS) AcquireSystemDNS() (func(), error) {
	s.systemDNSMu.RLock()
	if s.MayUseSystemResolver() {
		s.systemDNSMu.RUnlock()
		return nil, fmt.Errorf("DNS configuration may resolve through the system resolver, takeover would loop or resolver is unavailable")
	}
	return s.systemDNSMu.RUnlock, nil
}

func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	return s.LookupIPContext(s.ctx, domain, option)
}

func (s *DNS) LookupIPContext(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	r, queryCtx, finish, err := s.begin(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer finish()
	// Detach transport values from USER/carrier ownership while preserving real
	// inbound/content metadata, caller cancellation and this exact resolver.
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
	base = context.WithValue(base, resolverContextKey{}, r)
	if err := queryCtx.Err(); err != nil {
		return nil, 0, err
	}
	ips, ttl, err := r.lookupIP(&dnsRequestContext{Context: base, caller: queryCtx}, domain, option)
	if callerErr := ctx.Err(); callerErr != nil {
		return nil, 0, callerErr
	}
	return ips, ttl, err
}

func (s *resolver) lookupIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
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
	if engine := s.script.Load(); engine != nil {
		return engine.queryContext(ctx, domain, option)
	}
	if s.enableParallelQuery {
		return s.parallelQuery(ctx, domain, option)
	} else {
		return s.serialQuery(ctx, domain, option)
	}
}

func (s *resolver) sortClients(domain string) []*Client {
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

func (s *resolver) serialQuery(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
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

func (s *resolver) parallelQuery(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
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
		var result queryResult
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case result = <-resultsChan:
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
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

func (s *resolver) asyncQueryAll(domain string, option dns.IPOption, clients []*Client, ctx context.Context) chan queryResult {
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
