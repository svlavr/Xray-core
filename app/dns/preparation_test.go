package dns

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/dns/fakedns"
	appgeodata "github.com/xtls/xray-core/app/geodata"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fdns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

func preparationServer(address, tag string) *NameServer {
	return &NameServer{Address: &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress(address))}, Tag: tag}
}

func preparationDomain(kind geodata.Domain_Type, value string) *geodata.DomainRule {
	return &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: kind, Value: value}}}
}

func preparationCore(config *Config, dnsFirst bool, fake bool) (*core.Instance, error) {
	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	if dnsFirst {
		apps = append([]*serial.TypedMessage{serial.ToTypedMessage(config)}, apps...)
	} else {
		apps = append(apps, serial.ToTypedMessage(config))
	}
	if fake {
		apps = append(apps, serial.ToTypedMessage(&fakedns.FakeDnsPool{IpPool: "198.18.0.0/15", LruSize: 16}))
	}
	return core.New(&core.Config{App: apps})
}

func TestDNSPreparationDependencyOrderRules(t *testing.T) {
	for _, dnsFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready-dispatcher", true: "late-dispatcher"}[dnsFirst], func(t *testing.T) {
			first := preparationServer("tcp://127.0.0.1:53", "default")
			preferred := preparationServer("tcp://127.0.0.1:54", "preferred")
			preferred.Domain = []*geodata.DomainRule{preparationDomain(geodata.Domain_Full, "specific.example")}
			instance, err := preparationCore(&Config{NameServer: []*NameServer{first, preferred, preparationServer("localhost", "local")}}, dnsFirst, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			resolver := instance.GetFeature(fdns.ClientType()).(*DNS)
			for name, want := range map[string]string{"specific.example": "preferred", "printer.local": "local", "ordinary.example.net": "default"} {
				clients := resolver.runtime.current.resolver.sortClients(name)
				if len(clients) == 0 || clients[0].tag != want {
					t.Fatalf("%s selected %v, want %s", name, clients, want)
				}
			}
		})
	}
}

func TestDNSPreparationLateFakeDNS(t *testing.T) {
	instance, err := preparationCore(&Config{NameServer: []*NameServer{preparationServer("fakedns", "fake")}}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	resolver := instance.GetFeature(fdns.ClientType()).(*DNS)
	ips, _, err := resolver.LookupIP("prepared.example", fdns.IPOption{IPv4Enable: true, FakeEnable: true})
	if err != nil || len(ips) != 1 {
		t.Fatalf("late FakeDNS query: %v %v", ips, err)
	}
}

func TestDNSPreparationInvalidDeferredRule(t *testing.T) {
	ns := preparationServer("tcp://127.0.0.1:53", "invalid")
	ns.Domain = []*geodata.DomainRule{preparationDomain(geodata.Domain_Regex, "[")}
	instance, err := preparationCore(&Config{NameServer: []*NameServer{ns}}, true, false)
	if instance != nil {
		instance.Close()
	}
	if err == nil {
		t.Fatal("deferred invalid domain rule bypassed preparation")
	}
}

func TestDNSPreparationFailureSurvivesLaterCallback(t *testing.T) {
	ns := preparationServer("tcp://127.0.0.1:53", "invalid")
	ns.Domain = []*geodata.DomainRule{preparationDomain(geodata.Domain_Regex, "[")}
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&Config{NameServer: []*NameServer{ns}}),
		// Geodata registers a second dispatcher callback. Its successful result
		// must not erase the DNS build failure when both become ready together.
		serial.ToTypedMessage(&appgeodata.Config{Cron: "* * * * *", Assets: []*appgeodata.Asset{{Url: "https://example.invalid/geodata", File: "unused.dat"}}}),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}})
	if instance != nil {
		instance.Close()
	}
	if err == nil {
		t.Fatal("later successful dependency callback masked failed DNS preparation")
	}
}

type preparationDispatcher struct {
	routing.Dispatcher
	calls atomic.Uint32
}

func (*preparationDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*preparationDispatcher) Start() error      { return nil }
func (*preparationDispatcher) Close() error      { return nil }
func (d *preparationDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	d.calls.Add(1)
	return nil, fmt.Errorf("unexpected dispatch during preparation")
}

func (d *preparationDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	d.calls.Add(1)
	return fmt.Errorf("unexpected dispatch during preparation")
}

func TestDNSPreparationAllNativeKinds(t *testing.T) {
	dispatcher := new(preparationDispatcher)
	fake, err := fakedns.NewFakeDNSHolder()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		address string
		kind    string
	}{
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
			config := &Config{NameServer: []*NameServer{preparationServer(tc.address, "prepared")}}
			// No core in this context: a deferred RequireFeatures call would panic.
			first, err := buildDNS(context.Background(), proto.Clone(config).(*Config), dispatcher, fake)
			if err != nil || first == nil || len(first.clients) != 1 {
				t.Fatalf("build %s: %v %v", tc.address, first, err)
			}
			server := first.clients[0].server
			if got := fmt.Sprintf("%T", server); got != tc.kind {
				t.Fatalf("kind %s want %s", got, tc.kind)
			}
			if first.clients[0].tag != "prepared" {
				t.Fatal("tag lost")
			}
			switch server := server.(type) {
			case *FakeDNSServer:
				if server.fakeDNSEngine != fake {
					t.Fatal("borrowed FakeDNS dependency changed")
				}
			case *ClassicNameServer:
				if len(server.requests) != 0 || server.dispatcher != dispatcher {
					t.Fatal("UDP preparation launched work or lost dispatcher")
				}
			case *QUICNameServer:
				if server.connection != nil {
					t.Fatal("QUIC preparation opened a connection")
				}
			}
			if cached, ok := server.(CachedNameserver); ok {
				second, err := buildDNS(context.Background(), proto.Clone(config).(*Config), dispatcher, fake)
				if err != nil {
					t.Fatal(err)
				}
				a := cached.getCacheController()
				b := second.clients[0].server.(CachedNameserver).getCacheController()
				if a == b || len(a.ips) != 0 || len(b.ips) != 0 {
					t.Fatal("candidate caches are not fresh and independent")
				}
				a.ips["one.example."] = &record{}
				if len(b.ips) != 0 {
					t.Fatal("candidate cache storage aliases")
				}
			}
		})
	}
	if dispatcher.calls.Load() != 0 {
		t.Fatal("preparation dispatched network work")
	}
}

func TestDNSPreparationInputSnapshot(t *testing.T) {
	instance := new(core.Instance)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ns := preparationServer("tcp://127.0.0.1:53", "original")
	ns.Domain = []*geodata.DomainRule{preparationDomain(geodata.Domain_Full, "snapshot.example.net")}
	config := &Config{NameServer: []*NameServer{preparationServer("localhost", "local"), ns}, ClientIp: []byte{1, 2, 3, 4}}
	resolver, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	// The caller may discard or mutate its request after New returns, even if
	// native bootstrap is still waiting for the dispatcher.
	ns.Tag = "mutated"
	ns.Domain[0].GetCustom().Value = "mutated.example.net"
	config.ClientIp[0] = 9
	if err := instance.AddFeature(new(preparationDispatcher)); err != nil {
		t.Fatal(err)
	}
	clients := resolver.runtime.current.resolver.sortClients("snapshot.example.net")
	if len(clients) != 2 || clients[0].tag != "original" {
		t.Fatalf("deferred preparation used caller-mutated rules: %+v", clients)
	}
	if got := clients[0].server.(*TCPNameServer).clientIP; got[0] != 1 {
		t.Fatalf("client IP still aliases request: %v", got)
	}
}

func TestDNSPreparationFailuresPublishNothing(t *testing.T) {
	badIP := &geodata.IPRule{Value: &geodata.IPRule_Geoip{Geoip: &geodata.GeoIPRule{File: filepath.Join(t.TempDir(), "missing.dat"), Code: "missing"}}}
	for name, alter := range map[string]func(*Config){
		"client-ip":       func(c *Config) { c.ClientIp = []byte{1} },
		"strategy":        func(c *Config) { c.QueryStrategy = QueryStrategy(99) },
		"missing-address": func(c *Config) { c.NameServer[1].Address = nil },
		"invalid-port":    func(c *Config) { c.NameServer[1] = preparationServer("tcp://127.0.0.1:99999", "invalid") },
		"missing-fake":    func(c *Config) { c.NameServer[1] = preparationServer("fakedns", "invalid") },
		"expected-ip":     func(c *Config) { c.NameServer[1].ExpectedIp = []*geodata.IPRule{badIP} },
		"unexpected-ip":   func(c *Config) { c.NameServer[1].UnexpectedIp = []*geodata.IPRule{badIP} },
		"domain-matcher": func(c *Config) {
			c.NameServer[1].Domain = []*geodata.DomainRule{preparationDomain(geodata.Domain_Regex, "[")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := &Config{NameServer: []*NameServer{preparationServer("localhost", "first"), preparationServer("tcp://127.0.0.1", "second")}}
			alter(config)
			dispatcher := new(preparationDispatcher)
			candidate, err := buildDNS(context.Background(), config, dispatcher, nil)
			if err == nil || candidate != nil || dispatcher.calls.Load() != 0 {
				t.Fatalf("failed candidate escaped: %v %v calls=%d", candidate, err, dispatcher.calls.Load())
			}
		})
	}
}

func TestDNSPreparationSynchronousHelpers(t *testing.T) {
	instance := new(core.Instance)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ns := preparationServer("tcp://127.0.0.1", "ready")
	updated := false
	update := func(bool) { updated = true }
	if client, err := NewClient(ctx, ns, nil, false, false, 0, "ready", fdns.IPOption{IPv4Enable: true}, update); err == nil || client != nil || updated {
		t.Fatalf("missing dispatcher returned partial client: %v %v", client, err)
	}
	if err := instance.AddFeature(new(preparationDispatcher)); err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("failed synchronous constructor left a deferred callback")
	}
	client, err := NewClient(ctx, ns, nil, false, false, 0, "ready", fdns.IPOption{IPv4Enable: true}, update)
	if err != nil || client == nil || !updated {
		t.Fatalf("ready constructor: %v %v", client, err)
	}
	fakeDest := net.TCPDestination(net.DomainAddress("fakedns"), 0)
	if server, err := NewServer(ctx, fakeDest, nil, false, false, 0, nil); err == nil || server != nil {
		t.Fatalf("missing FakeDNS returned partial server: %v %v", server, err)
	}
}
