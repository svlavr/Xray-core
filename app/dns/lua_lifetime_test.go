package dns

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

func m3DNSFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dns.lua")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustM3Engine(t *testing.T, script string) *scriptEngine {
	t.Helper()
	program, err := newScriptEngine(script)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func m3DNSFeature(t *testing.T) *DNS {
	t.Helper()
	s, err := New(dnsTestContext(t), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func m3DNSReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("owned DNS work did not finish")
		var zero T
		return zero
	}
}

func TestM3DNSActivationNativeQueriesAndPublication(t *testing.T) {
	address, calls := stageBTCPResolver(t, "192.0.2.31", map[string]bool{"init.example.": true, "query.example.": true})
	s := m3DNSFeature(t)
	path := m3DNSFile(t, `
local server = require("xray.dns").Servers[1]
assert(server.ID == "exact")
local ips, ttl, err = server:Query("init.example", true, false, false)
assert(not err and #ips == 1)
function HandleDNSQuery(domain, ipv4, ipv6, fake)
  return server:Query(domain, ipv4, ipv6, fake)
end`)
	config := stageBConfig(stageBServer(address, "candidate"))
	config.NameServer[0].Id, config.Script = "exact", path
	if result := ApplyConfig(context.Background(), s, config); result.Applied || result.Err == nil {
		t.Fatalf("script activation before Start: %+v", result)
	}
	if calls.Load() != 0 {
		t.Fatal("pre-Start rejection executed Lua")
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := ApplyConfig(ctx, s, config)
	if !result.Applied || result.Err != nil {
		t.Fatalf("activation: %+v", result)
	}
	cancel()
	ips, _, err := s.LookupIP("query.example", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IP{192, 0, 2, 31}) {
		t.Fatalf("caller canceled published owner: %v %v", ips, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("initialization plus query count=%d", calls.Load())
	}
	config.Script = m3DNSFile(t, `local dns = require("xray.dns"); dns.Servers[1]:Query("init.example", true, false, false); error("after external action")`)
	before := s.active
	result = ApplyConfig(context.Background(), s, config)
	if result.Applied || result.Err == nil || s.active != before {
		t.Fatalf("failed activation: %+v", result)
	}
	if calls.Load() != 3 {
		t.Fatal("native initialization side effect was silently removed")
	}
	ips, _, err = s.LookupIP("query.example", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 {
		t.Fatalf("rejected candidate changed publication: %v", err)
	}
}

type m3BlockedServer struct {
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	closeOnce   sync.Once
	closeSignal chan struct{}
	waitClose   <-chan struct{}
}

func (*m3BlockedServer) Name() string         { return "blocked" }
func (*m3BlockedServer) IsDisableCache() bool { return true }
func (s *m3BlockedServer) QueryIP(ctx context.Context, _ string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	s.once.Do(func() { close(s.entered) })
	// Deliberately models an arbitrary Go callback which needs resource Close.
	<-s.release
	return []net.IP{{192, 0, 2, 44}}, 1, nil
}

func (s *m3BlockedServer) Close() error {
	s.closeOnce.Do(func() {
		if s.closeSignal != nil {
			close(s.closeSignal)
		}
		if s.waitClose != nil {
			<-s.waitClose
		}
		close(s.release)
	})
	return nil
}

func TestM3DNSCloseStartsAllResourceClosuresBeforeInitJoin(t *testing.T) {
	s := m3DNSFeature(t)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	otherClosed := make(chan struct{})
	first := &m3BlockedServer{entered: make(chan struct{}), release: make(chan struct{}), waitClose: otherClosed}
	second := &m3BlockedServer{entered: make(chan struct{}), release: make(chan struct{}), closeSignal: otherClosed}
	option := featuredns.IPOption{IPv4Enable: true}
	path := m3DNSFile(t, `local s=require("xray.dns").Servers[1]; s:Query("init.example",true,false,false); function HandleDNSQuery(...) return s:Query(...) end`)
	r := &resolver{ctx: context.Background(), prepared: mustM3Engine(t, path), clients: []*Client{
		{server: first, ipOption: &option, timeoutMs: time.Hour, tag: "activating"},
		{server: second, ipOption: &option, timeoutMs: time.Hour},
	}}
	owner := dnsTestResolver(s, r)
	r.ctx = owner.ctx
	owner.initialized = make(chan struct{})
	s.mu.Lock()
	s.pending = owner
	s.mu.Unlock()
	initialized := owner.initialize()
	m3DNSReceive(t, first.entered)
	if !s.IsOwnLink(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "activating"})) {
		t.Fatal("activation tag absent")
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	if err := m3DNSReceive(t, done); err != nil {
		t.Fatal(err)
	}
	if err := m3DNSReceive(t, initialized); err == nil {
		t.Fatal("late engine installed into canceled owner")
	}
	if r.script.Load() != nil {
		t.Fatal("late engine escaped disposal")
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("close returned before terminal disposal")
	}
}

func TestM3DNSBoundCallbacksRejectRetiredOwnerAndKeepIDs(t *testing.T) {
	option := featuredns.IPOption{IPv4Enable: true}
	clients := []*Client{}
	for _, id := range []string{"", "same", "same"} {
		clients = append(clients, &Client{id: id, server: &scriptNameServer{name: "exact", answers: map[string]net.IP{"good.example": {192, 0, 2, 51}}, ttl: 7}, ipOption: &option, timeoutMs: time.Second})
	}
	r := &resolver{ctx: context.Background(), clients: clients, ipOption: &option, hosts: new(StaticHosts)}
	s := dnsTestFeature(t, r)
	t.Cleanup(func() { s.Close() })
	L := lua.NewState()
	defer L.Close()
	L.SetContext(context.Background())
	RegisterLua(L, s)
	if err := L.DoString(`
local dns=require("xray.dns")
assert(#dns.Servers==3 and dns.Servers[1].ID=="" and dns.Servers[2].ID=="same" and dns.Servers[3].ID=="same")
saved=dns.Servers[2]; query=saved.Query; general=dns.Query
local ips,_,err=query(saved,"good.example",true,false,false);assert(not err and #ips==1)`); err != nil {
		t.Fatal(err)
	}
	old := s.active
	config := stageBConfig(stageBServer("127.0.0.1:53", "replacement"))
	if result := ApplyConfig(context.Background(), s, config); !result.Applied || result.Err != nil {
		t.Fatalf("apply: %+v", result)
	}
	if err := L.DoString(`local _,_,err=query(saved,"good.example",true,false,false);assert(err); local _,_,err=general("good.example",true,false,false);assert(err)`); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), resolverContextKey{}, old)
	if _, _, err := s.LookupIPContext(ctx, "good.example", option); !errors.Is(err, context.Canceled) {
		t.Fatalf("old binding retargeted: %v", err)
	}
}

func TestM3DNSBindingSurvivesDetachedTransportAndCacheContext(t *testing.T) {
	s := m3DNSFeature(t)
	owner := s.active
	base := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	base = context.WithValue(base, resolverContextKey{}, owner)
	ctx := toDnsContext(base, context.Background(), "dns")
	if ctx.Value(resolverContextKey{}) != owner || session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal {
		t.Fatal("detachment lost owner identity or INTERNAL origin")
	}
	ctx = &dnsRequestContext{Context: context.WithoutCancel(ctx), caller: context.Background()}
	if ctx.Value(resolverContextKey{}) != owner {
		t.Fatal("cache-owned cancellation lost owner identity")
	}
}

func TestM3DNSActivationCancellationRetainsOwnedPendingSlot(t *testing.T) {
	for _, featureClose := range []bool{false, true} {
		t.Run(fmt.Sprint("feature-close=", featureClose), func(t *testing.T) {
			s := m3DNSFeature(t)
			initial := stageBConfig(stageBServer("127.0.0.1:53", "current"))
			if a := ApplyConfig(context.Background(), s, initial); !a.Applied || a.Err != nil {
				t.Fatalf("initial: %+v", a)
			}
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			blocked := &m3BlockedServer{entered: make(chan struct{}), release: make(chan struct{}), closeSignal: make(chan struct{}), waitClose: release}
			option := featuredns.IPOption{IPv4Enable: true}
			candidate := &resolver{ctx: context.Background(), prepared: mustM3Engine(t, m3DNSFile(t, `local s=require("xray.dns").Servers[1]; s:Query("initializing.example",true,false,false); function HandleDNSQuery(...) return s:Query(...) end`)), clients: []*Client{
				{server: blocked, ipOption: &option, timeoutMs: time.Hour, tag: "pending"},
				{server: NewLocalNameServer(), ipOption: &option, tag: "local-pending"},
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			applied := make(chan ApplyResult, 1)
			go func() { applied <- s.applyResolver(ctx, dnsTestResolver(s, candidate)) }()
			m3DNSReceive(t, blocked.entered)
			s.mu.Lock()
			owner, old := s.pending, s.active
			s.mu.Unlock()
			if owner == nil || owner != candidate {
				t.Fatal("activating candidate not owned")
			}
			if !s.MayUseSystemResolver() {
				t.Fatal("unsafe activation absent from safety predicate")
			}
			if releaseGuard, err := s.AcquireSystemDNS(); err == nil {
				releaseGuard()
				t.Fatal("takeover admitted unsafe activation")
			}
			if a := ApplyConfig(context.Background(), s, initial); a.Applied || a.Err == nil {
				t.Fatalf("third owner admitted: %+v", a)
			}
			var closed chan error
			if featureClose {
				closed = make(chan error, 1)
				go func() { closed <- s.Close() }()
			}
			cancel()
			a := m3DNSReceive(t, applied)
			if a.Applied || a.Err == nil {
				t.Fatalf("canceled activation published: %+v", a)
			}
			m3DNSReceive(t, blocked.closeSignal)
			s.mu.Lock()
			stillPending, current := s.pending == owner, s.active
			s.mu.Unlock()
			if !stillPending || current != old {
				t.Fatal("unfinished activation forgotten or publication changed")
			}
			unblock()
			m3DNSReceive(t, owner.done)
			s.mu.Lock()
			stillPending = s.pending == owner
			s.mu.Unlock()
			if stillPending {
				t.Fatal("terminal activation retained its pending slot")
			}
			if candidate.script.Load() != nil {
				t.Fatal("late initialization escaped retirement")
			}
			if closed != nil {
				if err := m3DNSReceive(t, closed); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestM3DNSFeatureCloseStartsBothOwnersBeforeJoining(t *testing.T) {
	otherClosed := make(chan struct{})
	current := &m3BlockedServer{entered: make(chan struct{}), release: make(chan struct{}), waitClose: otherClosed}
	pending := &m3BlockedServer{entered: make(chan struct{}), release: make(chan struct{}), closeSignal: otherClosed}
	s := stageBManualFeature(t, current)
	option := featuredns.IPOption{IPv4Enable: true}
	s.pending = dnsTestResolver(s, &resolver{clients: []*Client{{server: pending, ipOption: &option}}})
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	if err := m3DNSReceive(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestM3DNSNativeEngineCloseCancelsExplicitPoolContext(t *testing.T) {
	upstream := &stageBBlockingServer{started: make(chan struct{})}
	option := featuredns.IPOption{IPv4Enable: true}
	s := &resolver{ctx: context.Background(), clients: []*Client{{server: upstream, ipOption: &option, timeoutMs: time.Hour}}}
	path := m3DNSFile(t, `local s=require("xray.dns").Servers[1]; function HandleDNSQuery(...) return s:Query(...) end`)
	engine, err := newScriptEngine(path)
	if err != nil {
		t.Fatal(err)
	}
	dnsTestFeature(t, s)
	if err := engine.start(s); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := engine.queryContext(context.Background(), "blocked.example", option); done <- err }()
	m3DNSReceive(t, upstream.started)
	closed := make(chan struct{})
	go func() { engine.close(); close(closed) }()
	if err := m3DNSReceive(t, done); err == nil {
		t.Fatal("closed native engine query succeeded")
	}
	m3DNSReceive(t, closed)
}

func TestM3DNSFileApplyCancellationBeforePublication(t *testing.T) {
	address, calls := stageBTCPResolver(t, "192.0.2.31", map[string]bool{"init.example.": true})
	server := m3DNSFeature(t)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	old := server.active
	config := stageBConfig(stageBServer(address, "file"))
	config.Script = m3DNSFile(t, `
 local s=require("xray.dns").Servers[1]
 local _,_,err=s:Query("init.example",true,false,false)
 assert(not err)
 while true do end
 function HandleDNSQuery(...) return s:Query(...) end`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan ApplyResult, 1)
	go func() { done <- ApplyConfig(ctx, server, config) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for calls.Load() == 0 {
		select {
		case result := <-done:
			t.Fatalf("file initializer returned before query: %+v", result)
		case <-deadline.C:
			t.Fatal("file initializer did not query its server")
		case <-ticker.C:
		}
	}
	server.mu.Lock()
	pending := server.pending
	server.mu.Unlock()
	if pending == nil {
		t.Fatal("file activation was not owned")
	}
	cancel()
	result := m3DNSReceive(t, done)
	if result.Applied || !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("canceled file apply: %+v", result)
	}
	m3DNSReceive(t, pending.done)
	server.mu.Lock()
	current, closing := server.active, server.pending
	server.mu.Unlock()
	if current != old || closing != nil || pending.script.Load() != nil {
		t.Fatal("canceled file activation changed publication or escaped retirement")
	}
}

// Inline input is rejected by the adopted native compiler before either initial
// construction or an explicit update can initialize or publish a resolver.
func TestM3DNSRejectsInlineBeforeConstructionAndApply(t *testing.T) {
	const source = `
local server = require("xray.dns").Servers[1]
server:Query("init.example", true, false, false)
function HandleDNSQuery(...) return server:Query(...) end`
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(source)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, script string
	}{
		{"base64", "base64:" + base64.StdEncoding.EncodeToString([]byte(source))},
		{"base64+gzip", "base64+gzip:" + base64.StdEncoding.EncodeToString(compressed.Bytes())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, calls := stageBTCPResolver(t, "192.0.2.31", map[string]bool{"init.example.": true})
			config := stageBConfig(stageBServer(address, "rejected-inline"))
			config.Script = tc.script
			created, err := New(dnsTestContext(t), config)
			if created != nil {
				t.Cleanup(func() {
					if err := created.Close(); err != nil {
						t.Error(err)
					}
				})
				t.Fatal("constructor retained a resolver for rejected inline input")
			}
			if err == nil || !strings.Contains(err.Error(), "currently unavailable") {
				t.Fatalf("constructor error = %v; want native inline-policy rejection", err)
			}

			server := m3DNSFeature(t)
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			before := server.active
			server.mu.Unlock()
			result := ApplyConfig(context.Background(), server, config)
			if result.Applied || result.Err == nil || !strings.Contains(result.Err.Error(), "currently unavailable") {
				t.Fatalf("inline update = %+v; want native inline-policy rejection", result)
			}
			server.mu.Lock()
			current, pending := server.active, server.pending
			server.mu.Unlock()
			if current != before || pending != nil {
				t.Fatal("rejected inline update changed publication or retained activation")
			}
			if calls.Load() != 0 {
				t.Fatal("rejected inline input executed its DNS initializer")
			}
		})
	}
}
