package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dns/fakedns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

type generationTestServer struct {
	started      chan struct{}
	proceed      chan struct{}
	once         sync.Once
	captured     context.Context
	closeMu      sync.Mutex
	closeErrs    []error
	closed       int
	ignoreCancel bool
	closeStarted chan struct{}
	closeProceed chan struct{}
	closeOnce    sync.Once
	wantCore     *core.Instance
}

func (s *generationTestServer) Name() string         { return "generation-test" }
func (s *generationTestServer) IsDisableCache() bool { return true }
func (s *generationTestServer) QueryIP(ctx context.Context, domain string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	if s.wantCore != nil && core.FromContext(ctx) != s.wantCore {
		return nil, 0, go_errors.New("foreign core context")
	}
	if domain == "outer.test" {
		s.captured = ctx
		s.once.Do(func() { close(s.started) })
		if s.ignoreCancel {
			<-s.proceed
		} else {
			select {
			case <-s.proceed:
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		return featuredns.LookupIPContext(ctx, nil, "nested.test", featuredns.IPOption{IPv4Enable: true})
	}
	return []net.IP{{10, 0, 0, 1}}, 30, nil
}

func TestBoundLookupUsesOwningCoreWithForeignCallerAndReceiver(t *testing.T) {
	ownerCore, foreignCore := new(core.Instance), new(core.Instance)
	server := &generationTestServer{started: make(chan struct{}), proceed: make(chan struct{}), wantCore: ownerCore}
	d := newGenerationTestDNS(server)
	d.ctx = context.WithValue(context.Background(), core.XrayKey(1), ownerCore)
	done := make(chan error, 1)
	go func() {
		_, _, err := d.LookupIPContext(context.Background(), "outer.test", featuredns.IPOption{IPv4Enable: true})
		done <- err
	}()
	<-server.started
	foreignCtx := context.WithValue(server.captured, core.XrayKey(1), foreignCore)
	foreignReceiver := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	ips, _, err := foreignReceiver.LookupIPContext(foreignCtx, "nested.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 {
		t.Fatalf("bound foreign call: ips=%v err=%v", ips, err)
	}
	close(server.proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func (s *generationTestServer) Close() error {
	if s.closeStarted != nil {
		s.closeOnce.Do(func() { close(s.closeStarted) })
	}
	if s.closeProceed != nil {
		<-s.closeProceed
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.closed++
	if len(s.closeErrs) == 0 {
		return nil
	}
	err := s.closeErrs[0]
	s.closeErrs = s.closeErrs[1:]
	return err
}

func newGenerationTestDNS(server Server) *DNS {
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		panic(err)
	}
	option := featuredns.IPOption{IPv4Enable: true, IPv6Enable: true}
	resolver := &DNS{
		hosts: hosts, ipOption: &option, ctx: context.Background(),
		clients: []*Client{{server: server, ipOption: &option, timeoutMs: 30 * time.Second}},
	}
	stable := &DNS{ctx: context.Background()}
	stable.initRuntime(nil, nil, resolver)
	return stable
}

func staticConfig(domain string, ip byte) *Config {
	return &Config{StaticHosts: []*Config_HostMapping{{
		Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: domain}}},
		Ip:     [][]byte{{192, 0, 2, ip}},
	}}}
}

func TestApplyConfigPreservesCausalGenerationAndFreshState(t *testing.T) {
	server := &generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})}
	d := newGenerationTestDNS(server)
	option := featuredns.IPOption{IPv4Enable: true}

	lookupDone := make(chan []net.IP, 1)
	go func() {
		ips, _, err := d.LookupIPContext(context.Background(), "outer.test", option)
		if err != nil {
			lookupDone <- nil
			return
		}
		lookupDone <- ips
	}()
	<-server.started

	config := staticConfig("new.test", 10)
	detached := featuredns.CopyContextBinding(context.Background(), server.captured)
	result := ApplyConfig(context.Background(), d, config)
	if result.Disposition != ApplyApplied || result.Generation != 2 || result.PreviousGeneration != 1 {
		t.Fatalf("unexpected apply result: %+v", result)
	}
	config.StaticHosts[0].Ip[0][3] = 99
	foreign := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	oldIPs, _, err := foreign.LookupIPContext(server.captured, "nested.test", option)
	if err != nil || len(oldIPs) != 1 || !oldIPs[0].Equal(net.IP{10, 0, 0, 1}) {
		t.Fatalf("direct foreign receiver escaped bound old generation: ips=%v err=%v", oldIPs, err)
	}
	if _, release, err := featuredns.ReserveSpeculativeContextBinding(server.captured); err == nil {
		release()
		t.Fatal("sealed generation admitted speculative work")
	}
	select {
	case <-detached.Done():
		t.Fatal("graceful seal canceled active old-generation context")
	default:
	}
	if wait := result.Retirement.Wait(contextWithTimeout(t, 10*time.Millisecond)); wait.Disposition != WaitIncomplete || wait.Terminal {
		t.Fatalf("old active lookup reported retired: %+v", wait)
	}

	ips, _, err := d.LookupIPContext(context.Background(), "new.test", option)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 10}) {
		t.Fatalf("new generation did not use cloned fresh state: ips=%v err=%v", ips, err)
	}

	close(server.proceed)
	if ips := <-lookupDone; len(ips) != 1 || !ips[0].Equal(net.IP{10, 0, 0, 1}) {
		t.Fatalf("nested causal lookup escaped old generation: %v", ips)
	}
	retired := result.Retirement.Wait(contextWithTimeout(t, time.Second))
	if !retired.Terminal || retired.Disposition != Retired {
		t.Fatalf("retirement did not complete: %+v", retired)
	}
	select {
	case <-detached.Done():
	case <-time.After(time.Second):
		t.Fatal("retirement did not cancel detached generation context")
	}
	if _, _, err := foreign.LookupIPContext(server.captured, "nested.test", option); err == nil {
		t.Fatal("expired binding unexpectedly fell back to current generation")
	} else {
		var bindingErr *featuredns.CausalBindingError
		if !go_errors.As(err, &bindingErr) {
			t.Fatalf("wrong expired-binding error: %v", err)
		}
	}
}

func TestApplyConfigRetirementFailureRetainsSlotAndRetries(t *testing.T) {
	closeFailure := go_errors.New("close failed")
	server := &generationTestServer{started: make(chan struct{}), proceed: make(chan struct{}), closeErrs: []error{closeFailure, nil}}
	d := newGenerationTestDNS(server)
	result := ApplyConfig(context.Background(), d, staticConfig("one.test", 1))
	if result.Disposition != ApplyApplied {
		t.Fatalf("apply failed: %+v", result)
	}
	failed := result.Retirement.Wait(contextWithTimeout(t, time.Second))
	if failed.Disposition != RetireFailed || failed.Terminal || failed.Failure != FailureCleanup {
		t.Fatalf("cleanup failure was hidden: %+v", failed)
	}
	if next := ApplyConfig(context.Background(), d, staticConfig("two.test", 2)); next.Disposition != ApplyRetiringLimit {
		t.Fatalf("failed retirement did not retain capacity: %+v", next)
	}
	retryDone := make(chan RetirementResult, 1)
	closeDone := make(chan error, 1)
	retryCtx, cancelRetry := context.WithTimeout(context.Background(), time.Second)
	defer cancelRetry()
	go func() { retryDone <- result.Retirement.Retry(retryCtx) }()
	go func() { closeDone <- d.Close() }()
	retried := <-retryDone
	if retried.Disposition != Retired || !retried.Terminal {
		t.Fatalf("retry did not retire retained generation: %+v", retried)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("concurrent close: %v", err)
	}
	if result.Retirement.retry != nil {
		t.Fatal("successful retry retained generation closure")
	}
	server.closeMu.Lock()
	closes := server.closed
	server.closeMu.Unlock()
	if closes != 2 {
		t.Fatalf("failed cleanup plus retry called lower Close %d times", closes)
	}
}

func TestDNSCloseCompletesPreviouslyFailedRetirementReceipt(t *testing.T) {
	server := &generationTestServer{started: make(chan struct{}), proceed: make(chan struct{}), closeErrs: []error{go_errors.New("first close failed"), nil}}
	d := newGenerationTestDNS(server)
	result := ApplyConfig(context.Background(), d, staticConfig("close-retry.test", 5))
	if failed := result.Retirement.Wait(contextWithTimeout(t, time.Second)); failed.Disposition != RetireFailed {
		t.Fatalf("initial retirement: %+v", failed)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("whole close retry: %v", err)
	}
	completed := result.Retirement.Wait(contextWithTimeout(t, time.Second))
	if !completed.Terminal || completed.Disposition != Retired {
		t.Fatalf("receipt after whole close: %+v", completed)
	}
	if result.Retirement.retry != nil {
		t.Fatal("whole-close success retained retry closure")
	}
}

func TestApplyConfigPostPublicationCancellationAndSlotClear(t *testing.T) {
	d := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	ctx, cancel := context.WithCancel(context.Background())
	first := ApplyConfig(ctx, d, staticConfig("first.test", 1))
	if first.Disposition != ApplyApplied {
		t.Fatalf("first apply: %+v", first)
	}
	cancel()
	if retired := first.Retirement.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal || retired.Disposition != Retired {
		t.Fatalf("first retirement: %+v", retired)
	}
	if first.Retirement.retry != nil {
		t.Fatal("terminal receipt retained generation retry closure")
	}
	ips, _, err := d.LookupIPContext(context.Background(), "first.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 1}) {
		t.Fatalf("post-publication caller cancellation killed new generation: ips=%v err=%v", ips, err)
	}
	second := ApplyConfig(context.Background(), d, staticConfig("second.test", 2))
	if second.Disposition != ApplyApplied {
		t.Fatalf("RETIRED receipt returned before slot clear: %+v", second)
	}
}

func TestApplyConfigUnsupportedNilClients(t *testing.T) {
	if result := ApplyConfig(context.Background(), nil, &Config{}); result.Disposition != ApplyUnsupportedClient {
		t.Fatalf("nil client: %+v", result)
	}
	var typedNil *DNS
	var client featuredns.Client = typedNil
	if result := ApplyConfig(context.Background(), client, &Config{}); result.Disposition != ApplyUnsupportedClient {
		t.Fatalf("typed nil client: %+v", result)
	}
}

func TestApplyConfigBusyCanceledAndClosedDispositions(t *testing.T) {
	d := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	d.runtime.mu.Lock()
	d.runtime.preparing = true
	d.runtime.mu.Unlock()
	if result := ApplyConfig(context.Background(), d, &Config{}); result.Disposition != ApplyBusy {
		t.Fatalf("busy apply: %+v", result)
	}
	d.runtime.mu.Lock()
	d.runtime.preparing = false
	d.runtime.mu.Unlock()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := ApplyConfig(canceled, d, &Config{}); result.Disposition != ApplyCanceled {
		t.Fatalf("canceled apply: %+v", result)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if result := ApplyConfig(context.Background(), d, &Config{}); result.Disposition != ApplyClosed {
		t.Fatalf("closed apply: %+v", result)
	}
}

func TestApplyConfigPreparationFailureClasses(t *testing.T) {
	d := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	invalidStrategy := &Config{QueryStrategy: QueryStrategy(99)}
	if result := ApplyConfig(context.Background(), d, invalidStrategy); result.Failure != FailureInvalid {
		t.Fatalf("invalid strategy class: %+v", result)
	}
	invalidPort := &Config{NameServer: []*NameServer{preparationServer("tcp+local://127.0.0.1:bad", "bad")}}
	if result := ApplyConfig(context.Background(), d, invalidPort); result.Failure != FailureInvalid {
		t.Fatalf("invalid port class: %+v", result)
	}
	invalidRegex := &Config{NameServer: []*NameServer{preparationServer("localhost", "bad")}}
	invalidRegex.NameServer[0].Domain = []*geodata.DomainRule{preparationDomain(geodata.Domain_Regex, "[")}
	if result := ApplyConfig(context.Background(), d, invalidRegex); result.Failure != FailureInvalid {
		t.Fatalf("invalid regex class: %+v", result)
	}
	missingDispatcher := &Config{NameServer: []*NameServer{preparationServer("tcp://127.0.0.1:53", "dependency")}}
	if result := ApplyConfig(context.Background(), d, missingDispatcher); result.Failure != FailureDependency {
		t.Fatalf("missing dispatcher class: %+v", result)
	}
}

func TestApplyConfigRejectsMalformedTypedInput(t *testing.T) {
	d := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	config := &Config{NameServer: []*NameServer{{
		Address:    &net.Endpoint{Address: net.NewIPOrDomain(net.LocalHostIP)},
		ExpectedIp: []*geodata.IPRule{{}},
	}}}
	result := ApplyConfig(context.Background(), d, config)
	if result.Disposition != ApplyPrepareFailed || result.Failure != FailureInvalid {
		t.Fatalf("malformed input was not rejected before builder: %+v", result)
	}
}

func TestApplyConfigSupportsEveryNativeServerForm(t *testing.T) {
	dispatcher := new(preparationDispatcher)
	fake, err := fakedns.NewFakeDNSHolder()
	if err != nil {
		t.Fatal(err)
	}
	d := newGenerationTestDNS(&generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})})
	d.runtime.dispatcher, d.runtime.fake = dispatcher, fake
	for _, tc := range []struct{ address, kind string }{
		{"localhost", "*dns.LocalNameServer"},
		{"https://resolver.example/dns-query", "*dns.DoHNameServer"},
		{"h2c://resolver.example/dns-query", "*dns.DoHNameServer"},
		{"https+local://resolver.example/dns-query", "*dns.DoHNameServer"},
		{"h2c+local://resolver.example/dns-query", "*dns.DoHNameServer"},
		{"quic+local://resolver.example", "*dns.QUICNameServer"},
		{"tcp://resolver.example", "*dns.TCPNameServer"},
		{"tcp+local://resolver.example", "*dns.TCPNameServer"},
		{"resolver.example", "*dns.ClassicNameServer"},
		{"fakedns", "*dns.FakeDNSServer"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			result := ApplyConfig(context.Background(), d, &Config{NameServer: []*NameServer{preparationServer(tc.address, "runtime")}})
			if result.Disposition != ApplyApplied {
				t.Fatalf("apply: %+v", result)
			}
			if retired := result.Retirement.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal {
				t.Fatalf("retire previous: %+v", retired)
			}
			server := d.runtime.current.resolver.clients[0].server
			if got := fmt.Sprintf("%T", server); got != tc.kind {
				t.Fatalf("kind %s want %s", got, tc.kind)
			}
			if cached, ok := server.(CachedNameserver); ok && len(cached.getCacheController().ips) != 0 {
				t.Fatal("published generation inherited cache entries")
			}
		})
	}
}

func TestApplyConfigFindsLateRegisteredFakeDNS(t *testing.T) {
	instance, err := preparationCore(&Config{}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	resolver := instance.GetFeature(featuredns.ClientType()).(*DNS)
	if len(resolver.clients) != 0 || resolver.hosts != nil {
		t.Fatal("stable DNS feature retained initial resolver state")
	}
	if resolver.runtime.fake != nil {
		t.Fatal("empty bootstrap unexpectedly captured late FakeDNS")
	}
	result := ApplyConfig(context.Background(), resolver, &Config{NameServer: []*NameServer{preparationServer("fakedns", "runtime")}})
	if result.Disposition != ApplyApplied {
		t.Fatalf("apply late FakeDNS: %+v", result)
	}
	if retired := result.Retirement.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal {
		t.Fatalf("retire: %+v", retired)
	}
	ips, _, err := resolver.LookupIP("runtime-fake.test", featuredns.IPOption{IPv4Enable: true, FakeEnable: true})
	if err != nil || len(ips) != 1 {
		t.Fatalf("late FakeDNS query: ips=%v err=%v", ips, err)
	}
}

func TestApplyConfigIgnoresForeignCallerCoreDependencies(t *testing.T) {
	owner, err := preparationCore(&Config{}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := preparationCore(&Config{}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(); _ = foreign.Close() })
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	resolver := owner.GetFeature(featuredns.ClientType()).(*DNS)
	ownerFake := owner.GetFeature((*featuredns.FakeDNSEngine)(nil)).(featuredns.FakeDNSEngine)
	foreignFake := foreign.GetFeature((*featuredns.FakeDNSEngine)(nil)).(featuredns.FakeDNSEngine)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), foreign)
	result := ApplyConfig(ctx, resolver, &Config{NameServer: []*NameServer{preparationServer("fakedns", "runtime")}})
	if result.Disposition != ApplyApplied {
		t.Fatalf("apply: %+v", result)
	}
	server := resolver.runtime.current.resolver.clients[0].server.(*FakeDNSServer)
	if server.fakeDNSEngine != ownerFake || server.fakeDNSEngine == foreignFake {
		t.Fatal("ApplyConfig used dependencies from foreign caller core")
	}
}

type coreContextCheckingServer struct{}

func (*coreContextCheckingServer) Name() string         { return "core-context" }
func (*coreContextCheckingServer) IsDisableCache() bool { return true }
func (*coreContextCheckingServer) Close() error         { return nil }
func (*coreContextCheckingServer) QueryIP(ctx context.Context, _ string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	_ = toDnsContext(ctx, "context-check")
	return []net.IP{{192, 0, 2, 9}}, 1, nil
}

func TestUnboundContextClientRetainsBootstrapCore(t *testing.T) {
	server := newGenerationTestDNS(new(coreContextCheckingServer))
	server.ctx = context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	ips, _, err := featuredns.LookupIPContext(context.Background(), server, "context.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 {
		t.Fatalf("unbound context lookup lost core: ips=%v err=%v", ips, err)
	}
}

func TestDNSCloseCancelsAndJoinsActiveGeneration(t *testing.T) {
	server := &generationTestServer{started: make(chan struct{}), proceed: make(chan struct{})}
	d := newGenerationTestDNS(server)
	done := make(chan error, 1)
	go func() {
		_, _, err := d.LookupIPContext(context.Background(), "outer.test", featuredns.IPOption{IPv4Enable: true})
		done <- err
	}()
	<-server.started
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("active lookup was not canceled")
		}
	default:
		t.Fatal("Close returned before active lookup joined")
	}
}

func TestDNSCloseImmediatelyInvalidatesBoundParentAndSerializesCleanup(t *testing.T) {
	server := &generationTestServer{
		started: make(chan struct{}), proceed: make(chan struct{}), ignoreCancel: true,
		closeStarted: make(chan struct{}), closeProceed: make(chan struct{}),
	}
	d := newGenerationTestDNS(server)
	lookupDone := make(chan error, 1)
	go func() {
		_, _, err := d.LookupIPContext(context.Background(), "outer.test", featuredns.IPOption{IPv4Enable: true})
		lookupDone <- err
	}()
	<-server.started
	apply := ApplyConfig(context.Background(), d, staticConfig("new.test", 4))
	if apply.Disposition != ApplyApplied {
		t.Fatalf("apply: %+v", apply)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- d.Close() }()
	<-server.closeStarted
	if d.IsOwnLink(server.captured) {
		t.Fatal("whole close left bound own-link identity valid")
	}
	_, _, err := d.LookupIPContext(server.captured, "nested.test", featuredns.IPOption{IPv4Enable: true})
	var bindingErr *featuredns.CausalBindingError
	if !go_errors.As(err, &bindingErr) {
		t.Fatalf("whole close admitted bound child: %v", err)
	}
	close(server.closeProceed)
	close(server.proceed)
	<-lookupDone
	if err := <-closeDone; err != nil {
		t.Fatalf("close: %v", err)
	}
	if retired := apply.Retirement.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal {
		t.Fatalf("retirement: %+v", retired)
	}
	server.closeMu.Lock()
	closes := server.closed
	server.closeMu.Unlock()
	if closes != 1 {
		t.Fatalf("serialized cleanup called resource Close %d times", closes)
	}
}

type silentCachedServer struct{ cache *CacheController }

func (s *silentCachedServer) getCacheController() *CacheController                               { return s.cache }
func (*silentCachedServer) sendQuery(context.Context, chan<- error, string, featuredns.IPOption) {}
func (*silentCachedServer) Name() string                                                         { return "silent-cache" }

func (s *silentCachedServer) IsDisableCache() bool { return s.cache.disableCache }

func (s *silentCachedServer) QueryIP(ctx context.Context, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
func (s *silentCachedServer) Close() error { return s.cache.Close() }

func TestCacheCloseWakesPendingDualStackSubscribers(t *testing.T) {
	cache := NewCacheController("pending", false, false, 0)
	server := &silentCachedServer{cache: cache}
	done := make(chan error, 1)
	go func() {
		_, _, err := queryIP(context.Background(), server, "pending.test", featuredns.IPOption{IPv4Enable: true, IPv6Enable: true})
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		cache.RLock()
		count := len(cache.subs)
		cache.RUnlock()
		if count == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("subscribers were not registered")
		}
		time.Sleep(time.Millisecond)
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pending query reported success after cache close")
		}
	case <-time.After(time.Second):
		t.Fatal("pending subscribers were not woken by close")
	}
}

func TestGenerationSealStopsCacheSpeculationBeforeRetirement(t *testing.T) {
	cache := NewCacheController("sealed", false, false, 0)
	cache.ips["live.test."] = &record{A: &IPRecord{Expire: time.Now().Add(time.Hour)}}
	if err := cache.cacheCleanup.Start(); err != nil {
		t.Fatal(err)
	}
	d := newGenerationTestDNS(&silentCachedServer{cache: cache})
	result := ApplyConfig(context.Background(), d, staticConfig("new.test", 3))
	if result.Disposition != ApplyApplied {
		t.Fatalf("apply: %+v", result)
	}
	if !cache.sealed.Load() {
		t.Fatal("old cache was not sealed at publication")
	}
	cache.cacheCleanup.mu.Lock()
	stopped := cache.cacheCleanup.closed && !cache.cacheCleanup.running
	cache.cacheCleanup.mu.Unlock()
	if !stopped {
		t.Fatal("sealed cache periodic work remained scheduled")
	}
}

func TestOwnedPeriodicCloseJoinsExecutionAndStateBookkeeping(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	periodic := newOwnedPeriodic(time.Hour, func() error { close(started); <-proceed; return nil })
	startDone := make(chan error, 1)
	go func() { startDone <- periodic.Start() }()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- periodic.Close() }()
	select {
	case <-closeDone:
		t.Fatal("Close returned before Execute completed")
	default:
	}
	close(proceed)
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	periodic.mu.Lock()
	closed, running, timer := periodic.closed, periodic.running, periodic.timer
	periodic.mu.Unlock()
	if !closed || running || timer != nil {
		t.Fatalf("periodic state after join: closed=%v running=%v timer=%v", closed, running, timer)
	}
}

type retryPacketConn struct {
	mu       sync.Mutex
	closeErr []error
	closed   int
}

type scriptedCloseConn struct {
	stdnet.Conn
	mu      sync.Mutex
	calls   int
	errs    []error
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (c *scriptedCloseConn) Close() error {
	c.mu.Lock()
	c.calls++
	var err error
	if len(c.errs) != 0 {
		err, c.errs = c.errs[0], c.errs[1:]
	}
	c.mu.Unlock()
	if c.entered != nil {
		c.once.Do(func() { close(c.entered) })
	}
	if c.proceed != nil {
		<-c.proceed
	}
	return err
}

func (c *scriptedCloseConn) callCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

func TestTrackedTCPAndDoHCloseJoinAndRetry(t *testing.T) {
	for _, kind := range []string{"tcp", "doh"} {
		t.Run(kind+"-join-success", func(t *testing.T) {
			left, right := stdnet.Pipe()
			defer left.Close()
			defer right.Close()
			lower := &scriptedCloseConn{Conn: left, entered: make(chan struct{}), proceed: make(chan struct{})}
			var conn interface{ Close() error }
			if kind == "tcp" {
				conn = &tcpTrackedConn{Conn: lower}
			} else {
				conn = &dohTrackedConn{Conn: lower}
			}
			results := make(chan error, 2)
			go func() { results <- conn.Close() }()
			<-lower.entered
			go func() { results <- conn.Close() }()
			time.Sleep(time.Millisecond)
			if calls := lower.callCount(); calls != 1 {
				t.Fatalf("concurrent lower closes=%d", calls)
			}
			close(lower.proceed)
			if err := <-results; err != nil {
				t.Fatal(err)
			}
			if err := <-results; err != nil {
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if calls := lower.callCount(); calls != 1 {
				t.Fatalf("successful close replay called lower %d times", calls)
			}
		})
		t.Run(kind+"-retry-failure", func(t *testing.T) {
			failure := go_errors.New("close failed")
			left, right := stdnet.Pipe()
			defer left.Close()
			defer right.Close()
			lower := &scriptedCloseConn{Conn: left, errs: []error{failure, nil}}
			var conn interface{ Close() error }
			if kind == "tcp" {
				conn = &tcpTrackedConn{Conn: lower}
			} else {
				conn = &dohTrackedConn{Conn: lower}
			}
			if err := conn.Close(); !go_errors.Is(err, failure) {
				t.Fatalf("first close: %v", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("replay: %v", err)
			}
			if calls := lower.callCount(); calls != 2 {
				t.Fatalf("retry lower closes=%d", calls)
			}
		})
	}
}

func TestTCPAndDoHCloseCaptureLateDialPublication(t *testing.T) {
	for _, kind := range []string{"tcp", "doh"} {
		t.Run(kind, func(t *testing.T) {
			left, right := stdnet.Pipe()
			defer left.Close()
			defer right.Close()
			lower := &scriptedCloseConn{Conn: left}
			closeDone := make(chan error, 1)
			if kind == "tcp" {
				server := &TCPNameServer{cacheController: NewCacheController("tcp", false, false, 0), connections: make(map[net.Conn]struct{})}
				if !server.beginDial() {
					t.Fatal("dial rejected before close")
				}
				go func() { closeDone <- server.Close() }()
				for {
					server.mu.Lock()
					closed := server.closed
					server.mu.Unlock()
					if closed {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if _, accepted := server.trackConnection(lower); accepted {
					t.Fatal("late TCP connection accepted")
				}
				server.dialing.Done()
			} else {
				server := &DoHNameServer{cacheController: NewCacheController("doh", false, false, 0), httpClient: &http.Client{Transport: &http2.Transport{}}, connections: make(map[net.Conn]struct{})}
				if !server.beginDial() {
					t.Fatal("dial rejected before close")
				}
				go func() { closeDone <- server.Close() }()
				for {
					server.mu.Lock()
					closed := server.closed
					server.mu.Unlock()
					if closed {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if _, accepted := server.trackConnection(lower); accepted {
					t.Fatal("late DoH connection accepted")
				}
				server.dialing.Done()
			}
			if err := <-closeDone; err != nil {
				t.Fatal(err)
			}
			if calls := lower.callCount(); calls != 1 {
				t.Fatalf("late connection lower closes=%d", calls)
			}
		})
	}
}

func (*retryPacketConn) ReadFrom([]byte) (int, stdnet.Addr, error) { return 0, nil, context.Canceled }
func (*retryPacketConn) WriteTo([]byte, stdnet.Addr) (int, error)  { return 0, context.Canceled }
func (*retryPacketConn) LocalAddr() stdnet.Addr                    { return &stdnet.UDPAddr{} }
func (*retryPacketConn) SetDeadline(time.Time) error               { return nil }
func (*retryPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*retryPacketConn) SetWriteDeadline(time.Time) error          { return nil }
func (c *retryPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	if len(c.closeErr) == 0 {
		return nil
	}
	err := c.closeErr[0]
	c.closeErr = c.closeErr[1:]
	return err
}

func TestQUICResourceCloseRetainsFailedSocketForRetry(t *testing.T) {
	closeFailure := go_errors.New("packet close failed")
	packet := &retryPacketConn{closeErr: []error{closeFailure, nil}}
	server := &QUICNameServer{cacheController: NewCacheController("quic", false, false, 0), packetConn: packet}
	if err := server.Close(); !go_errors.Is(err, closeFailure) {
		t.Fatalf("first socket close failure lost: %v", err)
	}
	if server.packetConn == nil {
		t.Fatal("failed socket was removed from retry inventory")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("socket retry: %v", err)
	}
	if server.packetConn != nil || packet.closed != 2 {
		t.Fatalf("socket retry inventory not cleared exactly once: retained=%v closes=%d", server.packetConn != nil, packet.closed)
	}
}

func TestQUICCanceledResolutionAllocatesNoSocket(t *testing.T) {
	destination := net.UDPDestination(net.DomainAddress("resolver.invalid"), 853)
	server := &QUICNameServer{cacheController: NewCacheController("quic", false, false, 0), destination: &destination}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.openConnection(ctx); err == nil {
		t.Fatal("canceled resolution succeeded")
	}
	if server.packetConn != nil || server.transport != nil {
		t.Fatal("canceled resolution allocated a QUIC socket")
	}
}

func TestQUICResolutionPreservesNativeIPv4Preference(t *testing.T) {
	ipv6 := stdnet.ParseIP("2001:db8::1")
	ipv4 := stdnet.ParseIP("192.0.2.1")
	if got := selectQUICRemoteIP([]stdnet.IP{ipv6, ipv4}); got == nil || !got.Equal(ipv4) {
		t.Fatalf("mixed family selected %v", got)
	}
	if got := selectQUICRemoteIP([]stdnet.IP{ipv6}); got == nil || !got.Equal(ipv6) {
		t.Fatalf("IPv6 fallback selected %v", got)
	}
}

func TestDoHResourceCloseRejectsLateConnectionPublication(t *testing.T) {
	server := &DoHNameServer{
		cacheController: NewCacheController("doh", false, false, 0),
		httpClient:      &http.Client{Transport: &http2.Transport{}},
		connections:     make(map[net.Conn]struct{}),
	}
	client, peer := stdnet.Pipe()
	tracked, ok := server.trackConnection(client)
	if !ok {
		t.Fatal("initial connection was rejected")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close tracked connection: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("tracked connection remained open")
	}
	late, latePeer := stdnet.Pipe()
	defer late.Close()
	defer latePeer.Close()
	if _, ok := server.trackConnection(late); ok {
		t.Fatal("late connection published after close")
	}
	_ = tracked.Close()
}

type dnsUDPSink struct{}

func (dnsUDPSink) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }

type dnsUDPContextDispatcher struct {
	routing.Dispatcher
	mu      sync.Mutex
	lookups []net.IP
}

func (*dnsUDPContextDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dnsUDPContextDispatcher) Start() error      { return nil }
func (*dnsUDPContextDispatcher) Close() error      { return nil }
func (d *dnsUDPContextDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	ips, _, err := featuredns.LookupIPContext(ctx, nil, "nested.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.lookups = append(d.lookups, ips[0])
	d.mu.Unlock()
	reader, writer := pipe.New()
	_ = writer
	return &transport.Link{Reader: reader, Writer: dnsUDPSink{}}, nil
}

func (d *dnsUDPContextDispatcher) DispatchLink(ctx context.Context, dest net.Destination, _ *transport.Link) error {
	_, err := d.Dispatch(ctx, dest)
	return err
}

func boundLookupContext(ip byte) context.Context {
	owner := featuredns.NewContextOwner()
	var binding *featuredns.ContextBinding
	binding = featuredns.NewContextBinding(owner,
		func(context.Context, string, featuredns.IPOption) ([]net.IP, uint32, error) {
			return []net.IP{{192, 0, 2, ip}}, 1, nil
		},
		func(ctx context.Context) (context.Context, func(), error) {
			return featuredns.ContextWithBinding(ctx, binding), func() {}, nil
		}, func() bool { return true })
	base := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	return featuredns.ContextWithBinding(base, binding)
}

func TestUDPCollectionOffSuccessiveQueriesDoNotReuseFirstBinding(t *testing.T) {
	dispatcher := new(dnsUDPContextDispatcher)
	server := NewClassicNameServer(net.UDPDestination(net.DomainAddress("resolver.test"), 53), dispatcher, false, false, 0, nil)
	server.sendQuery(boundLookupContext(1), nil, "first.test.", featuredns.IPOption{IPv4Enable: true})
	server.sendQuery(boundLookupContext(2), nil, "second.test.", featuredns.IPOption{IPv4Enable: true})
	dispatcher.mu.Lock()
	lookups := append([]net.IP(nil), dispatcher.lookups...)
	dispatcher.mu.Unlock()
	if len(lookups) != 2 || !lookups[0].Equal(net.IP{192, 0, 2, 1}) || !lookups[1].Equal(net.IP{192, 0, 2, 2}) {
		t.Fatalf("successive DNS queries reused a stale ray binding: %v", lookups)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func truncatedUDPResponse(t *testing.T, id uint16) *udp_proto.Packet {
	t.Helper()
	message := new(mdns.Msg)
	message.Id = id
	message.Response = true
	message.Truncated = true
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &udp_proto.Packet{Payload: buf.FromBytes(wire)}
}

func TestUDPTruncatedRetryClosedHandoffRetiresExactlyOnce(t *testing.T) {
	for _, observed := range []bool{false, true} {
		t.Run(map[bool]string{false: "resource", true: "observed"}[observed], func(t *testing.T) {
			server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dnsUDPNoopDispatcher{}, true, false, 0, nil)
			const id uint16 = 77
			var releases atomic.Int32
			req := &udpDnsRequest{dnsRequest: dnsRequest{msg: &dnsmessage.Message{Header: dnsmessage.Header{ID: id}}}, release: func() { releases.Add(1) }}
			var resource *dnsUDPResourceOwner
			if observed {
				owner := &dnsUDPQueryOwner{server: server, exchange: new(dnsTCPTestExchange), dispatcher: udp.NewDispatcher(dnsUDPNoopDispatcher{}, nil), requests: make(map[uint16]*udpDnsRequest), unresolved: 1}
				req.owner = owner
				owner.requests[id] = req
			} else {
				resource = server.newResourceOwner(1)
				req.resource = resource
			}
			server.requests[id] = req
			server.closed = true // closes between extraction and retry insertion
			server.handleResponse(context.Background(), truncatedUDPResponse(t, id), req.owner)
			if releases.Load() != 1 {
				t.Fatalf("release count=%d", releases.Load())
			}
			if server.requests[id] != nil {
				t.Fatal("failed retry remained pending")
			}
			if req.owner != nil && req.owner.unresolved != 0 {
				t.Fatalf("observed unresolved=%d", req.owner.unresolved)
			}
			if resource != nil && resource.unresolved != 0 {
				t.Fatalf("resource unresolved=%d", resource.unresolved)
			}
		})
	}
}

func TestDoHDialsUseEachRequestBinding(t *testing.T) {
	dispatcher := new(dnsUDPContextDispatcher)
	u, err := url.Parse("h2c://resolver.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	server := NewDoHNameServer(u, dispatcher, true, false, false, 0, nil)
	dial := server.httpClient.Transport.(*http2.Transport).DialTLSContext
	for _, ip := range []byte{1, 2} {
		conn, err := dial(boundLookupContext(ip), "tcp", "resolver.example:443", nil)
		if err != nil {
			t.Fatalf("dial %d: %v", ip, err)
		}
		_ = conn.Close()
	}
	dispatcher.mu.Lock()
	lookups := append([]net.IP(nil), dispatcher.lookups...)
	dispatcher.mu.Unlock()
	if len(lookups) != 2 || !lookups[0].Equal(net.IP{192, 0, 2, 1}) || !lookups[1].Equal(net.IP{192, 0, 2, 2}) {
		t.Fatalf("DoH redial reused first request binding: %v", lookups)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func startLoopbackTCPDNS(t *testing.T, answer string, gate bool) (string, <-chan struct{}, func()) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	server := &mdns.Server{Listener: listener, Net: "tcp", Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
		if gate {
			started <- struct{}{}
			<-release
		}
		response := new(mdns.Msg)
		response.SetReply(request)
		record, recordErr := mdns.NewRR(request.Question[0].Name + " 60 IN A " + answer)
		if recordErr != nil {
			return
		}
		response.Answer = append(response.Answer, record)
		_ = w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	stop := func() {
		releaseOnce.Do(func() { close(release) })
		_ = server.Shutdown()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("TCP DNS server did not stop")
		}
	}
	t.Cleanup(stop)
	return listener.Addr().String(), started, func() { releaseOnce.Do(func() { close(release) }) }
}

func TestTCPResolverReplacementKeepsOldQueryAndClosesOldResources(t *testing.T) {
	oldAddr, oldStarted, releaseOld := startLoopbackTCPDNS(t, "192.0.2.10", true)
	newAddr, _, _ := startLoopbackTCPDNS(t, "192.0.2.20", false)
	configFor := func(address string) *Config {
		disable := true
		return &Config{NameServer: []*NameServer{{Address: &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("tcp+local://" + address))}, DisableCache: &disable}}}
	}
	oldResolver, err := buildDNS(context.Background(), configFor(oldAddr), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stable := &DNS{ctx: context.Background()}
	stable.initRuntime(nil, nil, oldResolver)
	oldTCP := oldResolver.clients[0].server.(*TCPNameServer)
	type lookupResult struct {
		ips []net.IP
		err error
	}
	oldResult := make(chan lookupResult, 1)
	go func() {
		ips, _, lookupErr := stable.LookupIPContext(context.Background(), "replace.test", featuredns.IPOption{IPv4Enable: true})
		oldResult <- lookupResult{ips: ips, err: lookupErr}
	}()
	<-oldStarted
	apply := ApplyConfig(context.Background(), stable, configFor(newAddr))
	if apply.Disposition != ApplyApplied {
		t.Fatalf("apply: %+v", apply)
	}
	newIPs, _, err := stable.LookupIPContext(context.Background(), "replace.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(newIPs) != 1 || !newIPs[0].Equal(net.IP{192, 0, 2, 20}) {
		t.Fatalf("new resolver: ips=%v err=%v", newIPs, err)
	}
	if wait := apply.Retirement.Wait(contextWithTimeout(t, 10*time.Millisecond)); wait.Disposition != WaitIncomplete {
		t.Fatalf("old query reported retired while gated: %+v", wait)
	}
	releaseOld()
	old := <-oldResult
	if old.err != nil || len(old.ips) != 1 || !old.ips[0].Equal(net.IP{192, 0, 2, 10}) {
		t.Fatalf("old resolver: ips=%v err=%v", old.ips, old.err)
	}
	if retired := apply.Retirement.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal || retired.Disposition != Retired {
		t.Fatalf("retirement: %+v", retired)
	}
	oldTCP.mu.Lock()
	closed, connections := oldTCP.closed, len(oldTCP.connections)
	oldTCP.mu.Unlock()
	if !closed || connections != 0 {
		t.Fatalf("old TCP resources at RETIRED: closed=%v connections=%d", closed, connections)
	}
	if err := stable.Close(); err != nil {
		t.Fatal(err)
	}
}

func startLoopbackH2CDNS(t *testing.T, answer string, gatedName string) (string, <-chan struct{}, func(), *atomic.Uint32) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	accepts := new(atomic.Uint32)
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepts.Add(1)
			go new(http2.Server).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				payload, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					return
				}
				message := new(mdns.Msg)
				if unpackErr := message.Unpack(payload); unpackErr != nil || len(message.Question) == 0 {
					return
				}
				if message.Question[0].Name == gatedName {
					started <- struct{}{}
					<-release
				}
				response := new(mdns.Msg)
				response.SetReply(message)
				record, recordErr := mdns.NewRR(message.Question[0].Name + " 60 IN A " + answer)
				if recordErr != nil {
					return
				}
				response.Answer = append(response.Answer, record)
				wire, packErr := response.Pack()
				if packErr != nil {
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			})})
		}
	}()
	stop := func() {
		releaseOnce.Do(func() { close(release) })
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("h2c DNS accept loop did not stop")
		}
	}
	t.Cleanup(stop)
	return listener.Addr().String(), started, func() { releaseOnce.Do(func() { close(release) }) }, accepts
}

func TestH2CPooledResolverReplacementClosesOldPool(t *testing.T) {
	oldAddr, oldStarted, releaseOld, accepts := startLoopbackH2CDNS(t, "192.0.2.30", "hold.test.")
	newAddr, _, _, _ := startLoopbackH2CDNS(t, "192.0.2.40", "")
	configFor := func(address string) *Config {
		disable := true
		return &Config{NameServer: []*NameServer{{Address: &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("h2c+local://" + address + "/dns-query"))}, DisableCache: &disable}}}
	}
	oldResolver, err := buildDNS(context.Background(), configFor(oldAddr), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stable := &DNS{ctx: context.Background()}
	stable.initRuntime(nil, nil, oldResolver)
	oldDoH := oldResolver.clients[0].server.(*DoHNameServer)
	option := featuredns.IPOption{IPv4Enable: true}
	if _, _, err := stable.LookupIPContext(context.Background(), "warm.test", option); err != nil {
		t.Fatal(err)
	}
	type lookupResult struct {
		ips []net.IP
		err error
	}
	oldResult := make(chan lookupResult, 1)
	go func() {
		ips, _, lookupErr := stable.LookupIPContext(context.Background(), "hold.test", option)
		oldResult <- lookupResult{ips, lookupErr}
	}()
	<-oldStarted
	if accepts.Load() != 1 {
		t.Fatalf("old DoH requests did not share one HTTP/2 carrier: accepts=%d", accepts.Load())
	}
	apply := ApplyConfig(context.Background(), stable, configFor(newAddr))
	if apply.Disposition != ApplyApplied {
		t.Fatalf("apply: %+v", apply)
	}
	newIPs, _, err := stable.LookupIPContext(context.Background(), "new.test", option)
	if err != nil || len(newIPs) != 1 || !newIPs[0].Equal(net.IP{192, 0, 2, 40}) {
		t.Fatalf("new DoH: ips=%v err=%v", newIPs, err)
	}
	releaseOld()
	old := <-oldResult
	if old.err != nil || len(old.ips) != 1 || !old.ips[0].Equal(net.IP{192, 0, 2, 30}) {
		t.Fatalf("old DoH: ips=%v err=%v", old.ips, old.err)
	}
	if retired := apply.Retirement.Wait(contextWithTimeout(t, time.Second)); !retired.Terminal {
		t.Fatalf("retirement: %+v", retired)
	}
	oldDoH.mu.Lock()
	closed, connections := oldDoH.closed, len(oldDoH.connections)
	oldDoH.mu.Unlock()
	if !closed || connections != 0 {
		t.Fatalf("old DoH resources at RETIRED: closed=%v connections=%d", closed, connections)
	}
	if err := stable.Close(); err != nil {
		t.Fatal(err)
	}
}

func contextWithTimeout(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}
