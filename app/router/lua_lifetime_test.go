package router

import (
	"context"
	"fmt"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/net"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

func m3RouterTCP(t *testing.T, address string) string {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &mdns.Server{Listener: listener, Net: "tcp", NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(r)
		record, _ := mdns.NewRR(r.Question[0].Name + " 60 IN A " + address)
		response.Answer = append(response.Answer, record)
		_ = w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { server.Shutdown(); <-done })
	return listener.Addr().String()
}

func m3RouterConfig(address string, ids ...string) *appdns.Config {
	c := &appdns.Config{DisableCache: true}
	for _, id := range ids {
		c.NameServer = append(c.NameServer, &appdns.NameServer{Id: id, Address: &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("tcp+local://" + address))}, TimeoutMs: 1000})
	}
	return c
}

func TestM3RouterSavedLuaInventoryAndStateAcrossReplacement(t *testing.T) {
	first := m3RouterTCP(t, "192.0.2.61")
	second := m3RouterTCP(t, "192.0.2.62")
	client, err := appdns.New(context.Background(), &appdns.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if a := appdns.ApplyConfig(context.Background(), client, m3RouterConfig(first, "", "duplicate", "duplicate")); !a.Applied || a.Err != nil {
		t.Fatalf("initial: %+v", a)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	r := startLuaRouter(t, `
local dns=require("xray.dns")
local savedList=dns.Servers
local savedServer=savedList[1]
local savedQuery=savedServer.Query
local general=dns.Query
local count=0
function HandleRoute(...)
  count=count+1
  local ips,_,err=savedQuery(savedServer,"saved.example",true,false,false)
  assert(not err)
  local all,_,err=general("general.example",true,false,false);assert(not err)
  assert(ips[1]:Equal(all[1]))
  return ips[1]:String(), savedServer.ID .. ":" .. #savedList .. ":" .. count
end`, client, nil)
	for i := 1; i <= 2; i++ {
		route, err := r.PickRoute(newLuaRouteTestContext())
		if err != nil || route.GetOutboundTag() != "192.0.2.61" || route.GetRuleTag() != fmt.Sprintf(":3:%d", i) {
			t.Fatalf("native state reuse: %v %v", route, err)
		}
	}
	// New inventory has reordered/removed/duplicate IDs; identity is the owner,
	// never the first matching ID or an alias to the previous configured client.
	if a := appdns.ApplyConfig(context.Background(), client, m3RouterConfig(second, "duplicate", "")); !a.Applied || a.Err != nil {
		t.Fatalf("replacement: %+v", a)
	}
	route, err := r.PickRoute(newLuaRouteTestContext())
	if err != nil || route.GetOutboundTag() != "192.0.2.62" || route.GetRuleTag() != "duplicate:2:1" {
		t.Fatalf("fresh inventory/state: %v %v", route, err)
	}
	// Returned native route errors remain visible after replacement.
	if a := appdns.ApplyConfig(context.Background(), client, m3RouterConfig(second)); a.Applied || a.Err == nil {
		t.Fatalf("empty update: %+v", a)
	}
}

type m3RouterContextClient struct {
	featuredns.Client
	entered chan struct{}
	once    sync.Once
}

type m3OriginContext struct {
	routing.Context
	origin context.Context
}

func (c *m3OriginContext) OriginatingContext() context.Context { return c.origin }

func (c *m3RouterContextClient) LookupIPContext(ctx context.Context, _ string, _ featuredns.IPOption) ([]net.IP, uint32, error) {
	c.once.Do(func() { close(c.entered) })
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

func TestM3RouterExplicitCallerAndEngineCancellation(t *testing.T) {
	for _, byClose := range []bool{false, true} {
		t.Run(fmt.Sprint("close=", byClose), func(t *testing.T) {
			client := &m3RouterContextClient{entered: make(chan struct{})}
			r := startLuaRouter(t, `local dns=require("xray.dns"); assert(dns.Servers==nil); function HandleRoute(...) local _,_,err=dns.Query("blocked.example",true,false,false); return nil,nil,err end`, client, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := r.PickRoute(&m3OriginContext{Context: newLuaRouteTestContext(), origin: ctx})
				done <- err
			}()
			select {
			case <-client.entered:
			case <-time.After(time.Second):
				t.Fatal("callback never entered")
			}
			if byClose {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled query succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("explicit pool context survived cancellation")
			}
		})
	}
}

func TestM3RouterGrowingFactoryRetirementDoesNotReplayOnNewOwner(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	hold := make(chan struct{})
	growth := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var initialized atomic.Int32
	server := &mdns.Server{Listener: listener, Net: "tcp", NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		switch q.Question[0].Name {
		case "init.example.":
			if initialized.Add(1) == 2 {
				close(growth)
				<-release
			}
		case "hold.example.":
			close(hold)
			<-release
		}
		a := new(mdns.Msg)
		a.SetReply(q)
		rr, _ := mdns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.71")
		a.Answer = append(a.Answer, rr)
		_ = w.WriteMsg(a)
	})}
	served := make(chan error, 1)
	go func() { served <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { unblock(); server.Shutdown(); <-served })
	client, err := appdns.New(context.Background(), &appdns.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	config := m3RouterConfig(listener.Addr().String(), "old")
	config.NameServer[0].TimeoutMs = 10000
	if a := appdns.ApplyConfig(context.Background(), client, config); !a.Applied || a.Err != nil {
		t.Fatalf("initial: %+v", a)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	r := startLuaRouter(t, `
local dns=require("xray.dns")
local id=dns.Servers[1].ID
local _,_,err=dns.Query("init.example",true,false,false); assert(not err)
function HandleRoute(...)
 if id=="old" then local _,_,err=dns.Query("hold.example",true,false,false);return nil,nil,err end
 return "fresh",id
end`, client, nil)
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := r.PickRoute(newLuaRouteTestContext()); first <- err }()
	select {
	case <-hold:
	case <-time.After(2 * time.Second):
		t.Fatal("first VM not borrowed")
	}
	go func() { _, err := r.PickRoute(newLuaRouteTestContext()); second <- err }()
	select {
	case <-growth:
	case <-time.After(2 * time.Second):
		t.Fatal("contended factory not initialized")
	}
	newAddress := m3RouterTCP(t, "192.0.2.72")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if a := appdns.ApplyConfig(ctx, client, m3RouterConfig(newAddress, "new")); !a.Applied || a.Err != nil {
		t.Fatalf("replace during growth: %+v", a)
	}
	for _, result := range []<-chan error{first, second} {
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("old operation replayed/succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("old work survived retirement")
		}
	}
	route, err := r.PickRoute(newLuaRouteTestContext())
	if err != nil || route.GetOutboundTag() != "fresh" || route.GetRuleTag() != "new" {
		t.Fatalf("new owner route: %v %v", route, err)
	}
	if initialized.Load() != 2 {
		t.Fatalf("old owner factory rerun after retirement: %d", initialized.Load())
	}
	unblock()
}
