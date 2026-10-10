package router

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func m3RoutedPeer(t *testing.T, protocol string, firstQuery ...func()) (*net.Endpoint, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	answer := func(request *mdns.Msg) *mdns.Msg {
		if calls.Add(1) == 1 && len(firstQuery) != 0 {
			firstQuery[0]()
		}
		r := new(mdns.Msg)
		r.SetReply(request)
		rr, _ := mdns.NewRR(request.Question[0].Name + " 60 IN A 192.0.2.83")
		r.Answer = append(r.Answer, rr)
		return r
	}
	if protocol == "doh" {
		peer := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wire, err := io.ReadAll(r.Body)
			if err != nil {
				return
			}
			request := new(mdns.Msg)
			if request.Unpack(wire) != nil {
				w.WriteHeader(400)
				return
			}
			data, _ := answer(request).Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(data)
		}), new(http2.Server)))
		t.Cleanup(peer.Close)
		return &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("h2c://" + peer.Listener.Addr().String() + "/dns-query"))}, calls
	}
	ready := make(chan struct{})
	peer := &mdns.Server{Net: protocol, NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) { _ = w.WriteMsg(answer(q)) })}
	var endpoint *net.Endpoint
	if protocol == "tcp" {
		listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		peer.Listener = listener
		endpoint = &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("tcp://" + listener.Addr().String()))}
	} else {
		packet, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		peer.PacketConn = packet
		endpoint = &net.Endpoint{Network: net.Network_UDP, Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(packet.LocalAddr().(*stdnet.UDPAddr).Port)}
	}
	done := make(chan error, 1)
	go func() { done <- peer.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { peer.Shutdown(); <-done })
	return endpoint, calls
}

func TestM4RouterRoutedDNSRetirement(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "doh"} {
		t.Run(protocol, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releasePeer := func() { releaseOnce.Do(func() { close(release) }) }
			// Release the peer before its cleanup even when an assertion fails.
			oldEndpoint, oldCalls := m3RoutedPeer(t, protocol, func() { close(entered); <-release })
			t.Cleanup(releasePeer)
			newEndpoint, newCalls := m3RoutedPeer(t, protocol)
			dnsScript := writeRouteScript(t, `local server=require("xray.dns").Servers[1]; function HandleDNSQuery(...) return server:Query(...) end`)
			routerScript := writeRouteScript(t, `
local dns=require("xray.dns")
local saved=dns.Servers[1]
function HandleRoute(ctx,inbound,...)
  if inbound=="dns" then return "direct",saved.ID end
  local ips,_,err=saved:Query("retiring.example",true,false,false)
  assert(not err)
  return ips[1]:String(),saved.ID
end`)
			config := func(id string, endpoint *net.Endpoint) *appdns.Config {
				return &appdns.Config{Tag: "dns", Script: dnsScript, NameServer: []*appdns.NameServer{{Id: id, TimeoutMs: 10000, Address: endpoint}}}
			}
			instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(config("old", oldEndpoint)), serial.ToTypedMessage(&Config{Script: routerScript}),
				serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			}, Outbound: []*core.OutboundHandlerConfig{{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			t.Cleanup(releasePeer)
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			r := instance.GetFeature(routing.RouterType()).(*Router)
			oldDone := make(chan error, 1)
			go func() { _, err := r.PickRoute(newLuaRouteTestContext()); oldDone <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("routed DNS query did not reach held peer")
			}
			client := instance.GetFeature(featuredns.ClientType()).(*appdns.DNS)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if a := appdns.ApplyConfig(ctx, client, config("new", newEndpoint)); !a.Applied || a.Err != nil {
				t.Fatalf("in-flight script replacement: %+v", a)
			}
			select {
			case err := <-oldDone:
				if err == nil {
					t.Fatal("retired route succeeded or replayed")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("retired route did not cancel while peer remained held")
			}
			if oldCalls.Load() != 1 || newCalls.Load() != 0 {
				t.Fatalf("old route crossed publication: old=%d new=%d", oldCalls.Load(), newCalls.Load())
			}
			route, err := r.PickRoute(newLuaRouteTestContext())
			if err != nil || route.GetOutboundTag() != "192.0.2.83" || route.GetRuleTag() != "new" {
				t.Fatalf("fresh route did not bind new inventory: %v %v", route, err)
			}
			if oldCalls.Load() != 1 || newCalls.Load() != 1 {
				t.Fatalf("fresh route used stale client: old=%d new=%d", oldCalls.Load(), newCalls.Load())
			}
			if a := appdns.ApplyConfig(ctx, client, config("last", newEndpoint)); !a.Applied || a.Err != nil {
				t.Fatalf("retirement did not release replacement slot: %+v", a)
			}
		})
	}
}

func TestM3RouterRoutedDNSProtocolsBindInventoryAndCache(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "doh"} {
		t.Run(protocol, func(t *testing.T) {
			endpoint, calls := m3RoutedPeer(t, protocol)
			dnsScript := writeRouteScript(t, `local server=require("xray.dns").Servers[1]; function HandleDNSQuery(...) return server:Query(...) end`)
			routerScript := writeRouteScript(t, `
local dns=require("xray.dns")
local saved=dns.Servers[1]
local id=saved.ID
local active=false
function HandleRoute(ctx,inbound,...)
  if inbound=="dns" then assert(not active,"outer VM reentered");return "direct",id end
  active=true
  local ips,_,err=dns.Query("nested.example",true,false,false)
  assert(not err and active)
  active=false
  return ips[1]:String(),id
end`)
			config := &appdns.Config{Tag: "dns", Script: dnsScript, NameServer: []*appdns.NameServer{{Id: "old", TimeoutMs: 2000, Address: endpoint}}}
			instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(config), serial.ToTypedMessage(&Config{Script: routerScript}),
				serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			}, Outbound: []*core.OutboundHandlerConfig{{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			r := instance.GetFeature(routing.RouterType()).(*Router)
			lookup := func(want string) {
				t.Helper()
				route, err := r.PickRoute(newLuaRouteTestContext())
				if err != nil || route.GetOutboundTag() != "192.0.2.83" || route.GetRuleTag() != want {
					t.Fatalf("bound %s route: %v %v", protocol, route, err)
				}
			}
			lookup("old")
			lookup("old")
			if calls.Load() != 1 {
				t.Fatalf("warm query missed native cache: %d", calls.Load())
			}
			config.NameServer[0].Id = "new"
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client := instance.GetFeature(featuredns.ClientType()).(*appdns.DNS)
			if a := appdns.ApplyConfig(ctx, client, config); !a.Applied || a.Err != nil {
				t.Fatalf("script replacement: %+v", a)
			}
			lookup("new")
			lookup("new")
			if calls.Load() != 2 {
				t.Fatalf("replacement reused old cache/owner: %d", calls.Load())
			}
		})
	}
}
