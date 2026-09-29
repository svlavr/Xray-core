package dns

import (
	"context"
	go_errors "errors"
	"io"
	stdnet "net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

type silentCachedServer struct{ cache *CacheController }

func (s *silentCachedServer) getCacheController() *CacheController                               { return s.cache }
func (*silentCachedServer) sendQuery(context.Context, chan<- error, string, featuredns.IPOption) {}
func (*silentCachedServer) Name() string                                                         { return "silent-cache" }

func (s *silentCachedServer) IsDisableCache() bool { return s.cache.disableCache }

func (s *silentCachedServer) QueryIP(ctx context.Context, domain string, option featuredns.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

func stageBTCPResolver(t *testing.T, answer string, records map[string]bool) (string, *atomic.Int32) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	calls := new(atomic.Int32)
	server := &mdns.Server{Listener: listener, Net: "tcp", Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
		calls.Add(1)
		response := new(mdns.Msg)
		response.SetReply(request)
		if len(request.Question) == 0 || !records[request.Question[0].Name] {
			response.SetRcode(request, mdns.RcodeNameError)
		} else {
			record, err := mdns.NewRR(request.Question[0].Name + " 60 IN A " + answer)
			if err != nil {
				return
			}
			response.Answer = append(response.Answer, record)
		}
		_ = w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("TCP DNS server did not stop")
		}
	})
	return listener.Addr().String(), calls
}

func stageBConfig(servers ...*NameServer) *Config {
	return &Config{NameServer: servers, DisableFallbackIfMatch: true}
}

func stageBServer(address, tag string, domains ...string) *NameServer {
	server := preparationServer("tcp+local://"+address, tag)
	server.DisableCache = new(bool)
	*server.DisableCache = true
	for _, domain := range domains {
		server.Domain = append(server.Domain, preparationDomain(geodata.Domain_Full, domain))
	}
	server.SkipFallback = len(domains) != 0
	return server
}

func stageBLookup(t *testing.T, client *DNS, domain string, want net.IP) {
	t.Helper()
	ips, _, err := client.LookupIPContext(context.Background(), domain, featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup %s: ips=%v err=%v, want %v", domain, ips, err, want)
	}
}

func TestStageBPreparedGroupsAndExplicitCandidates(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(map[bool]string{false: "serial", true: "parallel"}[parallel], func(t *testing.T) {
			defaultAddr, defaultCalls := stageBTCPResolver(t, "192.0.2.30", map[string]bool{"other.test.": true})
			firstAddr, firstCalls := stageBTCPResolver(t, "192.0.2.10", map[string]bool{"alpha.test.": true})
			secondAddr, secondCalls := stageBTCPResolver(t, "192.0.2.20", map[string]bool{"beta.test.": true, "overlap.test.": true})
			client, err := New(context.Background(), &Config{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			cfg := stageBConfig(stageBServer(defaultAddr, "default"), stageBServer(firstAddr, "alpha", "alpha.test", "failed.test", "overlap.test"), stageBServer(secondAddr, "beta", "beta.test", "overlap.test"))
			cfg.EnableParallelQuery = parallel
			if result := ApplyConfig(context.Background(), client, cfg); !result.Applied || result.Err != nil {
				t.Fatalf("apply: %+v", result)
			}
			stageBLookup(t, client, "alpha.test", net.IP{192, 0, 2, 10})
			stageBLookup(t, client, "beta.test", net.IP{192, 0, 2, 20})
			stageBLookup(t, client, "other.test", net.IP{192, 0, 2, 30})
			defaultBefore := defaultCalls.Load()
			if _, _, err := client.LookupIPContext(context.Background(), "failed.test", featuredns.IPOption{IPv4Enable: true}); err == nil {
				t.Fatal("selected resolver failure returned success")
			}
			if defaultCalls.Load() != defaultBefore {
				t.Fatal("selected failure escaped to default resolver")
			}
			stageBLookup(t, client, "overlap.test", net.IP{192, 0, 2, 20})
			if defaultCalls.Load() != defaultBefore || firstCalls.Load() == 0 || secondCalls.Load() == 0 {
				t.Fatalf("overlap escaped selected set: default=%d alpha=%d beta=%d", defaultCalls.Load(), firstCalls.Load(), secondCalls.Load())
			}
		})
	}
}

func TestStageBExplicitEmptyAndNoCandidate(t *testing.T) {
	addr, calls := stageBTCPResolver(t, "192.0.2.40", map[string]bool{"active.test.": true})
	client, err := New(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	active := stageBConfig(stageBServer(addr, "active", "active.test"))
	if result := ApplyConfig(context.Background(), client, active); !result.Applied || result.Err != nil {
		t.Fatalf("initial apply: %+v", result)
	}
	stageBLookup(t, client, "active.test", net.IP{192, 0, 2, 40})
	before := calls.Load()
	if result := ApplyConfig(context.Background(), client, &Config{}); result.Applied || result.Err == nil {
		t.Fatalf("empty explicit apply: %+v", result)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := ApplyConfig(canceled, client, active); result.Applied || !go_errors.Is(result.Err, context.Canceled) {
		t.Fatalf("canceled preparation changed publication: %+v", result)
	}
	stageBLookup(t, client, "active.test", net.IP{192, 0, 2, 40})
	if calls.Load() != before+1 {
		t.Fatalf("failed preparation changed active resolver: calls=%d", calls.Load())
	}
	before = calls.Load()
	if _, _, err := client.LookupIPContext(context.Background(), "unmatched.test", featuredns.IPOption{IPv4Enable: true}); err == nil {
		t.Fatal("empty explicit candidate set resolved")
	}
	if calls.Load() != before {
		t.Fatal("empty explicit candidate set dispatched")
	}
}

func TestStageBPreparedNativeBlockAndException(t *testing.T) {
	addr, calls := stageBTCPResolver(t, "192.0.2.50", map[string]bool{"safe.ads.test.": true})
	client, err := New(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cfg := stageBConfig(stageBServer(addr, "default"))
	cfg.StaticHosts = []*Config_HostMapping{{Domain: preparationDomain(geodata.Domain_Full, "blocked.ads.test"), ProxiedDomain: "#3"}}
	if result := ApplyConfig(context.Background(), client, cfg); !result.Applied || result.Err != nil {
		t.Fatalf("apply: %+v", result)
	}
	if _, _, err := client.LookupIPContext(context.Background(), "blocked.ads.test", featuredns.IPOption{IPv4Enable: true}); err == nil {
		t.Fatal("prepared block returned success")
	}
	if calls.Load() != 0 {
		t.Fatal("blocked domain reached upstream")
	}
	stageBLookup(t, client, "safe.ads.test", net.IP{192, 0, 2, 50})
	if calls.Load() != 1 {
		t.Fatalf("prepared exception did not reach allowed upstream: %d", calls.Load())
	}
}

func TestStageBSameCoreReplacementKeepsUnrelatedConnection(t *testing.T) {
	oldAddr, _ := stageBTCPResolver(t, "192.0.2.61", map[string]bool{"mapped.test.": true})
	newAddr, _ := stageBTCPResolver(t, "192.0.2.62", map[string]bool{"mapped.test.": true})
	oldConfig := stageBConfig(stageBServer(oldAddr, "old"))
	oldConfig.NameServer[0].DisableCache = new(bool)
	instance, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(oldConfig)},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	client := instance.GetFeature(featuredns.ClientType()).(*DNS)
	stageBLookup(t, client, "mapped.test", net.IP{192, 0, 2, 61})
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		_, _ = io.Copy(peer, peer)
	}()
	port := net.Port(listener.Addr().(*stdnet.TCPAddr).Port)
	conn, err := core.Dial(context.Background(), instance, net.TCPDestination(net.LocalHostIP, port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	newConfig := stageBConfig(stageBServer(newAddr, "new"))
	newConfig.NameServer[0].DisableCache = new(bool)
	if result := ApplyConfig(context.Background(), client, newConfig); !result.Applied || result.Err != nil {
		t.Fatalf("apply in running core: %+v", result)
	}
	stageBLookup(t, client, "mapped.test", net.IP{192, 0, 2, 62})
	if _, err := conn.Write([]byte("alive")); err != nil {
		t.Fatalf("existing core connection write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("existing core connection read: %q %v", buf, err)
	}
	_ = conn.Close()
	select {
	case <-peerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("echo peer did not close")
	}
}

type stageBBlockingServer struct {
	started    chan struct{}
	once       sync.Once
	closeBlock chan struct{}
	mu         sync.Mutex
	closeErrs  []error
	closes     int
}

func (s *stageBBlockingServer) Name() string       { return "stage-b-old" }
func (*stageBBlockingServer) IsDisableCache() bool { return true }
func (s *stageBBlockingServer) QueryIP(ctx context.Context, _ string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

func (s *stageBBlockingServer) Close() error {
	if s.closeBlock != nil {
		<-s.closeBlock
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	if len(s.closeErrs) == 0 {
		return nil
	}
	err := s.closeErrs[0]
	s.closeErrs = s.closeErrs[1:]
	return err
}

func stageBManualFeature(t *testing.T, server Server) *DNS {
	t.Helper()
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	option := featuredns.IPOption{IPv4Enable: true, IPv6Enable: true}
	resolver := &DNS{hosts: hosts, ipOption: &option, ctx: context.Background(), clients: []*Client{{server: server, ipOption: &option, timeoutMs: time.Second}}}
	feature := &DNS{ctx: context.Background()}
	feature.initRuntime(resolver)
	return feature
}

func TestStageBReplacementCancelsOldWorkAndRetainsFailedClose(t *testing.T) {
	closeFailure := go_errors.New("old resource close failed")
	old := &stageBBlockingServer{started: make(chan struct{}), closeErrs: []error{closeFailure, nil}}
	feature := stageBManualFeature(t, old)
	t.Cleanup(func() { _ = feature.Close() })
	lookupDone := make(chan error, 1)
	go func() {
		_, _, err := feature.LookupIPContext(context.Background(), "old.test", featuredns.IPOption{IPv4Enable: true})
		lookupDone <- err
	}()
	<-old.started
	addr, _ := stageBTCPResolver(t, "192.0.2.70", map[string]bool{"new.test.": true})
	cfg := stageBConfig(stageBServer(addr, "new"))
	result := ApplyConfig(context.Background(), feature, cfg)
	if !result.Applied || !go_errors.Is(result.Err, closeFailure) {
		t.Fatalf("published cleanup failure: %+v", result)
	}
	if err := <-lookupDone; !go_errors.Is(err, context.Canceled) {
		t.Fatalf("old query was not canceled: %v", err)
	}
	stageBLookup(t, feature, "new.test", net.IP{192, 0, 2, 70})
	if next := ApplyConfig(context.Background(), feature, cfg); next.Applied || next.Err == nil {
		t.Fatalf("overwrote unfinished close: %+v", next)
	}
	if err := feature.Close(); err != nil {
		t.Fatalf("feature Close did not retry old owner: %v", err)
	}
	old.mu.Lock()
	closes := old.closes
	old.mu.Unlock()
	if closes != 2 {
		t.Fatalf("old resource close calls=%d", closes)
	}
	if _, _, err := feature.LookupIPContext(context.Background(), "new.test", featuredns.IPOption{IPv4Enable: true}); err == nil {
		t.Fatal("lookup admitted after feature Close")
	}
}

func TestStageBTimedCleanupKeepsBoundedOwner(t *testing.T) {
	block := make(chan struct{})
	old := &stageBBlockingServer{started: make(chan struct{}), closeBlock: block}
	feature := stageBManualFeature(t, old)
	feature.runtime.current.resolver.clients[0].tag = "old"
	t.Cleanup(func() {
		select {
		case <-block:
		default:
			close(block)
		}
		_ = feature.Close()
	})
	addr, _ := stageBTCPResolver(t, "192.0.2.71", map[string]bool{"new.test.": true})
	cfg := stageBConfig(stageBServer(addr, "new"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := ApplyConfig(ctx, feature, cfg)
	if !result.Applied || !go_errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("timed publication: %+v", result)
	}
	if !feature.IsOwnLink(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "old"})) ||
		!feature.IsOwnLink(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "new"})) {
		t.Fatal("published and closing resolver tags must both be recognized")
	}
	stageBLookup(t, feature, "new.test", net.IP{192, 0, 2, 71})
	if next := ApplyConfig(context.Background(), feature, cfg); next.Applied || next.Err == nil {
		t.Fatalf("second update displaced closing owner: %+v", next)
	}
	close(block)
	deadline := time.Now().Add(time.Second)
	for {
		feature.runtime.mu.Lock()
		pending := feature.runtime.closing != nil
		feature.runtime.mu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing owner did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if feature.IsOwnLink(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "old"})) {
		t.Fatal("closed resolver tag remained active")
	}
}

type stageBUDPDispatcher struct {
	routing.Dispatcher
	dispatches    atomic.Int32
	first         chan struct{}
	once          sync.Once
	wrongFirst    bool
	truncateFirst bool
	writes        atomic.Int32
}

func (*stageBUDPDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*stageBUDPDispatcher) Start() error      { return nil }
func (*stageBUDPDispatcher) Close() error      { return nil }
func (d *stageBUDPDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.dispatches.Add(1)
	reader, input := pipe.New()
	return &transport.Link{Reader: reader, Writer: &stageBUDPWriter{owner: d, input: input}}, nil
}

func (d *stageBUDPDispatcher) DispatchLink(ctx context.Context, dest net.Destination, _ *transport.Link) error {
	_, err := d.Dispatch(ctx, dest)
	return err
}

type stageBUDPWriter struct {
	owner *stageBUDPDispatcher
	input *pipe.Writer
}

func (w *stageBUDPWriter) respond(req *mdns.Msg, ip string, wrong bool, truncated bool) {
	response := new(mdns.Msg)
	response.SetReply(req)
	response.Question = append([]mdns.Question(nil), req.Question...)
	if wrong {
		response.Question[0].Name = "wrong.test."
	}
	if truncated {
		response.Truncated = true
	} else {
		record, err := mdns.NewRR(req.Question[0].Name + " 60 IN A " + ip)
		if err != nil {
			return
		}
		response.Answer = append(response.Answer, record)
	}
	packed, err := response.Pack()
	if err != nil {
		return
	}
	b := buf.New()
	_, _ = b.Write(packed)
	_ = w.input.WriteMultiBuffer(buf.MultiBuffer{b})
}

func (w *stageBUDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		request := new(mdns.Msg)
		err := request.Unpack(b.Bytes())
		b.Release()
		if err != nil || len(request.Question) == 0 {
			continue
		}
		w.owner.writes.Add(1)
		switch request.Question[0].Name {
		case "first.test.":
			w.owner.once.Do(func() { close(w.owner.first) })
		case "second.test.":
			w.respond(request, "192.0.2.82", false, false)
		case "valid.test.":
			if w.owner.wrongFirst {
				w.respond(request, "192.0.2.99", true, false)
			}
			w.respond(request, "192.0.2.80", false, false)
		case "truncated.test.":
			if w.owner.truncateFirst && len(request.Extra) == 0 {
				w.respond(request, "", false, true)
			} else {
				w.respond(request, "192.0.2.81", false, false)
			}
		}
	}
	return nil
}
func (w *stageBUDPWriter) Close() error { return w.input.Close() }
func (w *stageBUDPWriter) Interrupt()   { w.input.Interrupt() }

func stageBUDPServer(t *testing.T, dispatcher routing.Dispatcher) *ClassicNameServer {
	t.Helper()
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dispatcher, true, false, 0, nil)
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestStageBUDPSharedRaySurvivesFirstCallerCancellation(t *testing.T) {
	dispatcher := &stageBUDPDispatcher{first: make(chan struct{})}
	server := stageBUDPServer(t, dispatcher)
	base := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	ctx, cancel := context.WithCancel(base)
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := server.QueryIP(ctx, "first.test", featuredns.IPOption{IPv4Enable: true})
		firstDone <- err
	}()
	select {
	case <-dispatcher.first:
	case <-time.After(time.Second):
		t.Fatal("first query did not dispatch")
	}
	cancel()
	if err := <-firstDone; err == nil {
		t.Fatal("first canceled query succeeded")
	}
	ips, _, err := server.QueryIP(base, "second.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 82}) {
		t.Fatalf("sibling query: ips=%v err=%v", ips, err)
	}
	if dispatcher.dispatches.Load() != 1 {
		t.Fatalf("shared ray dispatches=%d", dispatcher.dispatches.Load())
	}
}

func TestStageBUDPTruncationAndWrongQuestion(t *testing.T) {
	dispatcher := &stageBUDPDispatcher{first: make(chan struct{}), wrongFirst: true, truncateFirst: true}
	server := stageBUDPServer(t, dispatcher)
	base := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	for domain, want := range map[string]net.IP{"valid.test": {192, 0, 2, 80}, "truncated.test": {192, 0, 2, 81}} {
		ips, _, err := server.QueryIP(base, domain, featuredns.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(want) {
			t.Fatalf("%s: ips=%v err=%v", domain, ips, err)
		}
	}
	if dispatcher.writes.Load() != 3 {
		t.Fatalf("expected normal plus EDNS retry, writes=%d", dispatcher.writes.Load())
	}
}

func TestStageBUDPRequestIDCollisionKeepsFirstPending(t *testing.T) {
	dispatcher := &stageBUDPDispatcher{first: make(chan struct{})}
	server := stageBUDPServer(t, dispatcher)
	msg := &dnsmessage.Message{Header: dnsmessage.Header{ID: 42}}
	first := &udpDnsRequest{dnsRequest: dnsRequest{msg: msg}, ctx: context.Background()}
	second := &udpDnsRequest{dnsRequest: dnsRequest{msg: msg}, ctx: context.Background()}
	if err := server.addPendingRequest(first); err != nil {
		t.Fatal(err)
	}
	if err := server.addPendingRequest(second); err == nil || go_errors.Is(err, context.Canceled) {
		t.Fatalf("request ID collision must be a non-cancellation error: %v", err)
	}
	server.RLock()
	current := server.requests[42]
	server.RUnlock()
	if current != first {
		t.Fatal("collision displaced first pending request")
	}
	server.reqID = 41
	result := make(chan error, 1)
	server.sendQuery(context.Background(), result, "collision.test.", featuredns.IPOption{IPv4Enable: true})
	if err := <-result; err == nil || go_errors.Is(err, context.Canceled) {
		t.Fatalf("sendQuery lost collision error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second.ctx = ctx
	if err := server.addPendingRequest(second); err != context.Canceled {
		t.Fatalf("actual cancellation: %v", err)
	}
}

type stageBBlockedDispatcher struct {
	routing.Dispatcher
	started chan struct{}
	once    sync.Once
}

func (*stageBBlockedDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*stageBBlockedDispatcher) Start() error      { return nil }
func (*stageBBlockedDispatcher) Close() error      { return nil }
func (d *stageBBlockedDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *stageBBlockedDispatcher) DispatchLink(ctx context.Context, dest net.Destination, _ *transport.Link) error {
	_, err := d.Dispatch(ctx, dest)
	return err
}

func TestStageBUDPCloseCancelsBlockedDispatch(t *testing.T) {
	dispatcher := &stageBBlockedDispatcher{started: make(chan struct{})}
	server := stageBUDPServer(t, dispatcher)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	queryDone := make(chan error, 1)
	go func() {
		_, _, err := server.QueryIP(ctx, "blocked.test", featuredns.IPOption{IPv4Enable: true})
		queryDone <- err
	}()
	select {
	case <-dispatcher.started:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not begin")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel blocked Dispatch")
	}
	select {
	case err := <-queryDone:
		if err == nil {
			t.Fatal("blocked query succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked query did not terminate")
	}
}

func TestStageBDNSNoInternalRowsOffOn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[enabled], func(t *testing.T) {
			addr, _ := stageBTCPResolver(t, "192.0.2.90", map[string]bool{"fact.test.": true})
			cfg := stageBConfig(stageBServer(addr, "resolver"))
			instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&appstats.Config{}), serial.ToTypedMessage(cfg),
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = instance.Close() })
			provider := instance.GetFeature(featurestats.ManagerType()).(featurestats.ObservationProvider)
			var inspection featurestats.FlowInspection
			if enabled {
				inspection, err = provider.EnableInspection(featurestats.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			client := instance.GetFeature(featuredns.ClientType()).(*DNS)
			stageBLookup(t, client, "fact.test", net.IP{192, 0, 2, 90})
			if enabled {
				live, err := inspection.ReadLive()
				if err != nil {
					t.Fatal(err)
				}
				terminal, err := inspection.ReadTerminals()
				if err != nil {
					t.Fatal(err)
				}
				if len(live.Rows) != 0 || len(terminal.Rows) != 0 {
					t.Fatalf("DNS query produced INTERNAL inspection rows: live=%d terminal=%d", len(live.Rows), len(terminal.Rows))
				}
			} else if provider.Observation() != nil {
				t.Fatal("inspection enabled in OFF mode")
			}
		})
	}
}

func TestStageBNativeOwnLinkTag(t *testing.T) {
	client := stageBManualFeature(t, &stageBBlockingServer{started: make(chan struct{})})
	client.runtime.current.resolver.clients[0].tag = "resolver"
	ctx := session.ContextWithInbound(context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance)), &session.Inbound{Tag: "resolver"})
	if !client.IsOwnLink(ctx) || !client.IsOwnLink(toDnsContext(ctx, ctx, "resolver.test")) {
		t.Fatal("native resolver tag lost from routed DNS context")
	}
	if client.IsOwnLink(session.ContextWithInbound(ctx, &session.Inbound{Tag: "foreign"})) || client.IsOwnLink(context.Background()) {
		t.Fatal("foreign or missing inbound tag accepted")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if client.IsOwnLink(ctx) {
		t.Fatal("closed resolver tag remained active")
	}
}
func (s *silentCachedServer) Close() error { s.cache.Close(); return nil }

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
	cache.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pending query reported success after cache close")
		}
	case <-time.After(time.Second):
		t.Fatal("pending subscribers were not woken by close")
	}
}

func TestOwnedPeriodicCloseJoinsExecutionAndStateBookkeeping(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	periodic := newOwnedPeriodic(time.Hour, func() error { close(started); <-proceed; return nil })
	startDone := make(chan error, 1)
	go func() { startDone <- periodic.Start() }()
	<-started
	closeDone := make(chan error, 1)
	go func() { periodic.Close(); closeDone <- nil }()
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
	t.Run("concurrent-native-close", func(t *testing.T) {
		left, right := stdnet.Pipe()
		defer right.Close()
		server := &TCPNameServer{cacheController: NewCacheController("tcp", false, false, 0)}
		conn, ok := server.lifetime.trackConnection(server.cacheController, left)
		if !ok {
			t.Fatal("initial connection rejected")
		}
		results := make(chan error, 8)
		for range 8 {
			go func() { results <- conn.Close() }()
		}
		for range 8 {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		server.lifetime.mu.Lock()
		remaining := len(server.lifetime.connections)
		server.lifetime.mu.Unlock()
		if remaining != 0 {
			t.Fatal("closed connection retained")
		}
		if _, err := right.Write([]byte{1}); err == nil {
			t.Fatal("closed connection still writable")
		}
	})
	t.Run("retry-failure", func(t *testing.T) {
		failure := go_errors.New("close failed")
		left, right := stdnet.Pipe()
		defer left.Close()
		defer right.Close()
		lower := &scriptedCloseConn{Conn: left, errs: []error{failure, nil}}
		var retired atomic.Bool
		conn := &trackedConn{Conn: lower, done: func() { retired.Store(true) }}
		if err := conn.Close(); !go_errors.Is(err, failure) || retired.Load() {
			t.Fatalf("first close: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("retry: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("replay: %v", err)
		}
		if calls := lower.callCount(); calls != 3 || !retired.Load() {
			t.Fatalf("retry lower closes=%d", calls)
		}
	})
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
				server := &TCPNameServer{cacheController: NewCacheController("tcp", false, false, 0)}
				if !server.lifetime.beginDial(server.cacheController) {
					t.Fatal("dial rejected before close")
				}
				go func() { closeDone <- server.Close() }()
				<-server.cacheController.ctx.Done()
				if _, accepted := server.lifetime.trackConnection(server.cacheController, lower); accepted {
					t.Fatal("late TCP connection accepted")
				}
				server.lifetime.dialing.Done()
			} else {
				server := &DoHNameServer{cacheController: NewCacheController("doh", false, false, 0), httpClient: &http.Client{Transport: &http2.Transport{}}}
				if !server.lifetime.beginDial(server.cacheController) {
					t.Fatal("dial rejected before close")
				}
				go func() { closeDone <- server.Close() }()
				<-server.cacheController.ctx.Done()
				if _, accepted := server.lifetime.trackConnection(server.cacheController, lower); accepted {
					t.Fatal("late DoH connection accepted")
				}
				server.lifetime.dialing.Done()
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

func TestTCPAndDoHRejectedConnectionCloseFailureRetried(t *testing.T) {
	for _, kind := range []string{"tcp", "doh"} {
		t.Run(kind, func(t *testing.T) {
			failure := go_errors.New("lower close failed")
			left, right := stdnet.Pipe()
			defer left.Close()
			defer right.Close()
			lower := &scriptedCloseConn{Conn: left, errs: []error{failure, failure, nil}}
			var cache *CacheController
			var lifetime *connectionLifetime
			var closeServer func() error
			if kind == "tcp" {
				server := &TCPNameServer{cacheController: NewCacheController("tcp", false, false, 0)}
				cache, lifetime, closeServer = server.cacheController, &server.lifetime, server.Close
			} else {
				server := &DoHNameServer{cacheController: NewCacheController("doh", false, false, 0)}
				cache, lifetime, closeServer = server.cacheController, &server.lifetime, server.Close
			}
			cache.cancel()
			tracked, accepted := lifetime.trackConnection(cache, lower)
			if accepted {
				t.Fatal("connection accepted after cancellation")
			}
			if err := tracked.Close(); !go_errors.Is(err, failure) {
				t.Fatalf("rejected connection close: %v", err)
			}
			if err := closeServer(); !go_errors.Is(err, failure) {
				t.Fatalf("first owner close: %v", err)
			}
			lifetime.mu.Lock()
			remaining := len(lifetime.connections)
			lifetime.mu.Unlock()
			if remaining != 1 {
				t.Fatalf("failed connection lost from retry inventory: %d", remaining)
			}
			if err := closeServer(); err != nil {
				t.Fatalf("retry owner close: %v", err)
			}
			lifetime.mu.Lock()
			remaining = len(lifetime.connections)
			lifetime.mu.Unlock()
			if remaining != 0 || lower.callCount() != 3 {
				t.Fatalf("connection retry: retained=%d closes=%d", remaining, lower.callCount())
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
	server := &QUICNameServer{cacheController: NewCacheController("quic", false, false, 0), transport: &quic.Transport{Conn: packet}}
	if err := server.Close(); !go_errors.Is(err, closeFailure) {
		t.Fatalf("first socket close failure lost: %v", err)
	}
	if server.transport == nil || server.transport.Conn != packet {
		t.Fatal("failed socket was removed from retry inventory")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("socket retry: %v", err)
	}
	if server.transport != nil || packet.closed != 2 {
		t.Fatalf("socket retry inventory not cleared exactly once: retained=%v closes=%d", server.transport != nil, packet.closed)
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
	if server.transport != nil {
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
	}
	client, peer := stdnet.Pipe()
	tracked, ok := server.lifetime.trackConnection(server.cacheController, client)
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
	if _, ok := server.lifetime.trackConnection(server.cacheController, late); ok {
		t.Fatal("late connection published after close")
	}
	_ = tracked.Close()
}

type stageBPausedPreparationContext struct {
	context.Context
	paused  atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (c *stageBPausedPreparationContext) Value(key any) any {
	if key == core.XrayKey(1) && c.paused.CompareAndSwap(false, true) {
		close(c.entered)
		<-c.resume
	}
	return c.Context.Value(key)
}

func TestStageBCloseDuringInertPreparation(t *testing.T) {
	old := &stageBBlockingServer{started: make(chan struct{})}
	feature := stageBManualFeature(t, old)
	paused := &stageBPausedPreparationContext{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{})}
	feature.ctx = paused
	var resume sync.Once
	defer resume.Do(func() { close(paused.resume) })
	result := make(chan ApplyResult, 1)
	config := stageBConfig(preparationServer("localhost", "new"))
	go func() { result <- ApplyConfig(context.Background(), feature, config) }()
	select {
	case <-paused.entered:
	case <-time.After(time.Second):
		t.Fatal("preparation did not pause")
	}
	if other := ApplyConfig(context.Background(), feature, config); !other.Applied || other.Err != nil {
		t.Fatalf("independent preparation could not publish: %+v", other)
	}
	closed := make(chan error, 1)
	go func() { closed <- feature.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for resource-free preparation")
	}
	resume.Do(func() { close(paused.resume) })
	select {
	case applied := <-result:
		if applied.Applied || !go_errors.Is(applied.Err, context.Canceled) {
			t.Fatalf("published after close: %+v", applied)
		}
	case <-time.After(time.Second):
		t.Fatal("preparation did not return after close")
	}
	if _, _, err := feature.LookupIPContext(context.Background(), "closed.test", featuredns.IPOption{IPv4Enable: true}); !go_errors.Is(err, context.Canceled) {
		t.Fatalf("lookup after close: %v", err)
	}
}

func TestCacheCloseAndRepeatedUnsubscribePreserveSibling(t *testing.T) {
	cache := NewCacheController("subscriber", false, false, 0)
	defer cache.Close()
	first, sibling := cache.subscribe("host4"), cache.subscribe("host4")
	first.close()
	first.close()
	record := &IPRecord{IP: []net.IP{{192, 0, 2, 1}}}
	cache.publish("host4", record)
	select {
	case got := <-sibling.buffer:
		if got != record {
			t.Fatal("sibling received another record")
		}
	default:
		t.Fatal("unsubscribing one query removed its sibling")
	}
	cache.Close()
	sibling.close()
	sibling.close()
	server := &silentCachedServer{cache: cache}
	_, _, err := queryIP(context.Background(), server, "closed.test", featuredns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err == nil {
		t.Fatal("query after cache close reported success")
	}
}

func TestStageBQUICCloseDuringHandshake(t *testing.T) {
	peer, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	server, err := NewQUICNameServer(&url.URL{Scheme: "quic+local", Host: peer.LocalAddr().String()}, false, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	result := make(chan error, 1)
	go func() {
		_, _, err := server.QueryIP(context.Background(), "blocked.test", featuredns.IPOption{IPv4Enable: true})
		result <- err
	}()
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peer.ReadFrom(make([]byte, 2048)); err != nil {
		t.Fatalf("handshake did not start: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close could not cancel the in-progress handshake")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("unanswered query reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("query did not leave after close")
	}
}
