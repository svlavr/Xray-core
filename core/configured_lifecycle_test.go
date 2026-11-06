package core_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

func configuredLuaFile(t *testing.T, name, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".lua")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func configuredBuild(t *testing.T, value any) *core.Config {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var config conf.Config
	if err := json.Unmarshal(wire, &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	return built
}

// The native handler starts its listener, then this barrier exercises the first
// accepted request before inbound.Manager.Start is allowed to return. Thus a
// router started later cannot accidentally make an early-inbound candidate pass.
type configuredStartBarrier struct {
	inbound.Handler
	probe func() error
}

func (h *configuredStartBarrier) Start() error {
	if err := h.Handler.Start(); err != nil {
		return err
	}
	return h.probe()
}

func configuredEndpoint(t *testing.T, marker byte) string {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			var request [1]byte
			if _, err := io.ReadFull(conn, request[:]); err == nil {
				_, _ = conn.Write([]byte{marker})
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("owned endpoint did not stop")
		}
	})
	return listener.Addr().String()
}

func TestConfiguredLuaRouteAtInboundStart(t *testing.T) {
	for _, typedEarly := range []bool{false, true} {
		t.Run(fmt.Sprintf("typed_early_control=%t", typedEarly), func(t *testing.T) {
			a, b := configuredEndpoint(t, 'A'), configuredEndpoint(t, 'B')
			script := configuredLuaFile(t, "route", `function HandleRoute(...) return "selected-A", "startup", nil end`)
			reservation, err := stdnet.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.Close()
			address := reservation.Addr().String()
			port := reservation.Addr().(*stdnet.TCPAddr).Port
			config := configuredBuild(t, map[string]any{
				"routing":  map[string]any{"script": script},
				"inbounds": []any{map[string]any{"tag": "startup", "listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": 443, "network": "tcp"}}},
				"outbounds": []any{
					map[string]any{"tag": "fallback-B", "protocol": "freedom", "settings": map[string]any{"redirect": b}},
					map[string]any{"tag": "selected-A", "protocol": "freedom", "settings": map[string]any{"redirect": a}},
				},
			})
			if typedEarly {
				// Explicit typed apps retain caller order. Config.Build is the owner
				// of the inbound-last guarantee; core.New is not a universal sorter.
				last := config.App[len(config.App)-1]
				if last.Type != serial.ToTypedMessage(&proxyman.InboundConfig{}).Type {
					t.Fatal("unexpected inbound app")
				}
				config.App = append(config.App[:3], append([]*serial.TypedMessage{last}, config.App[3:len(config.App)-1]...)...)
			}
			// Construct the configured native handler once and wrap only Start.
			nativeConfig := config.Inbound[0]
			config.Inbound = nil
			instance, err := core.New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			object, err := core.CreateObject(instance, nativeConfig)
			if err != nil {
				t.Fatal(err)
			}
			want := byte('A')
			if typedEarly {
				want = 'B'
			}
			barrier := &configuredStartBarrier{Handler: object.(inbound.Handler), probe: func() error {
				conn, err := stdnet.DialTimeout("tcp4", address, 3*time.Second)
				if err != nil {
					return err
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = conn.Write([]byte{'?'}); err != nil {
					return err
				}
				var got [1]byte
				if _, err = io.ReadFull(conn, got[:]); err != nil {
					return err
				}
				if got[0] != want {
					return fmt.Errorf("request accepted during Start reached endpoint %c, want %c", got[0], want)
				}
				return nil
			}}
			manager := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
			if err := manager.AddHandler(context.Background(), barrier); err != nil {
				t.Fatal(err)
			}
			_ = reservation.Close()
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfiguredCloseCancelsActiveDNSAndLuaRoute(t *testing.T) {
	for _, dnsFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("typed_dns_first=%t", dnsFirst), func(t *testing.T) {
			listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			arrivals := make(chan string, 4)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			ready := make(chan struct{})
			peer := &mdns.Server{Listener: listener, Net: "tcp", NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
				arrivals <- q.Question[0].Name
				<-release
				answer := new(mdns.Msg)
				answer.SetReply(q)
				rr, _ := mdns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.80")
				answer.Answer = append(answer.Answer, rr)
				_ = w.WriteMsg(answer)
			})}
			served := make(chan error, 1)
			go func() { served <- peer.ActivateAndServe() }()
			<-ready
			defer func() { unblock(); _ = peer.Shutdown(); <-served }()
			dnsScript := configuredLuaFile(t, "dns", `local server=require("xray.dns").Servers[1]; function HandleDNSQuery(domain,ipv4,ipv6,fake) return server:Query(domain,ipv4,ipv6,fake) end`)
			routeScript := configuredLuaFile(t, "route", `local dns=require("xray.dns"); function HandleRoute(...) local ips,_,err=dns.Query("route.close.example",true,false,false); if err then return nil,nil,err end; return "unexpected-late-success",nil,nil end`)
			config := configuredBuild(t, map[string]any{
				"routing": map[string]any{"script": routeScript},
				"dns":     map[string]any{"script": dnsScript, "disableCache": true, "servers": []any{map[string]any{"address": "tcp+local://" + listener.Addr().String(), "timeoutMs": 10000}}},
			})
			if dnsFirst {
				ri, di := -1, -1
				for i, app := range config.App {
					if app.Type == serial.ToTypedMessage(&router.Config{}).Type {
						ri = i
					}
					if app.Type == serial.ToTypedMessage(&appdns.Config{}).Type {
						di = i
					}
				}
				if ri < 0 || di < 0 {
					t.Fatal("missing configured DNS/router apps")
				}
				config.App[ri], config.App[di] = config.App[di], config.App[ri]
			}
			instance, err := core.New(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(); err != nil {
				_ = instance.Close()
				t.Fatal(err)
			}
			client := instance.GetFeature(featuredns.ClientType()).(featuredns.ContextClient)
			routerFeature := instance.GetFeature(routing.RouterType()).(routing.Router)
			dnsDone, routeDone := make(chan error, 1), make(chan error, 1)
			go func() {
				_, _, err := client.LookupIPContext(context.Background(), "direct.close.example", featuredns.IPOption{IPv4Enable: true})
				dnsDone <- err
			}()
			go func() {
				_, err := routerFeature.PickRoute(&routingsession.Context{Outbound: &session.Outbound{Target: net.TCPDestination(net.DomainAddress("target.example"), 443)}})
				routeDone <- err
			}()
			seen := map[string]bool{}
			for len(seen) < 2 {
				select {
				case name := <-arrivals:
					seen[name] = true
				case <-time.After(3 * time.Second):
					unblock()
					_ = instance.Close()
					t.Fatal("both active operations did not reach the owned DNS peer")
				}
			}
			if !seen["direct.close.example."] || !seen["route.close.example."] {
				unblock()
				_ = instance.Close()
				t.Fatalf("query barriers: %v", seen)
			}
			for name, done := range map[string]<-chan error{"DNS": dnsDone, "route": routeDone} {
				select {
				case err := <-done:
					unblock()
					_ = instance.Close()
					t.Fatalf("%s was no longer active at the Close barrier: %v", name, err)
				default:
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- instance.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(2 * time.Second):
				unblock()
				t.Fatal("Close waited for a held DNS response instead of canceling active owners")
			}
			for name, done := range map[string]<-chan error{"DNS": dnsDone, "route": routeDone} {
				select {
				case err := <-done:
					if err == nil {
						t.Errorf("%s lost cancellation", name)
					}
				case <-time.After(time.Second):
					t.Errorf("%s survived Close", name)
				}
			}
			if _, _, err := client.LookupIPContext(context.Background(), "after.close.example", featuredns.IPOption{IPv4Enable: true}); err == nil {
				t.Error("closed DNS accepted new work")
			}
		})
	}
}

type configuredCloseBarrier struct {
	inbound.Handler
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (h *configuredCloseBarrier) Close() error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return h.Handler.Close()
}

type configuredIngressPayload struct {
	endpoint byte
	payload  string
}

func configuredPayloadEndpoint(t *testing.T, marker byte, arrivals chan<- configuredIngressPayload) string {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			var payload [8]byte
			if _, err := io.ReadFull(conn, payload[:]); err == nil {
				arrivals <- configuredIngressPayload{endpoint: marker, payload: string(payload[:])}
				_, _ = conn.Write(append([]byte{marker}, payload[:]...))
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("owned payload endpoint did not stop")
		}
	})
	return listener.Addr().String()
}

func configuredSOCKSRequest(t *testing.T, address, domain, payload string) stdnet.Conn {
	t.Helper()
	conn, err := stdnet.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("native SOCKS method response: %x, %v", method, err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(domain))}, []byte(domain)...)
	request = append(request, 0, 80)
	request = append(request, []byte(payload)...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 0 {
		t.Fatalf("native SOCKS CONNECT response: %x, %v", header, err)
	}
	addressBytes := 0
	switch header[3] {
	case 1:
		addressBytes = 4
	case 4:
		addressBytes = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatal(err)
		}
		addressBytes = int(length[0])
	default:
		t.Fatalf("unexpected SOCKS address type: %d", header[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, addressBytes+2)); err != nil {
		t.Fatal(err)
	}
	return conn
}

// This is the ingress acceptance predicate, rather than a universal callback
// join requirement: retirement of a Lua routing decision must not turn either
// its admitted payload or a concurrently admitted request into default-outbound
// traffic. Native fallthrough on a canceled routing error is an R4 decision if
// reproduced; this fixture does not change or mask that dispatcher behavior.
func TestConfiguredCloseIngressDoesNotFallBackAfterLuaCancellation(t *testing.T) {
	payloads := make(chan configuredIngressPayload, 8)
	a, b := configuredPayloadEndpoint(t, 'A', payloads), configuredPayloadEndpoint(t, 'B', payloads)
	dnsListener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsEntered, dnsRelease := make(chan struct{}), make(chan struct{})
	var dnsOnce, dnsReleaseOnce sync.Once
	unblockDNS := func() { dnsReleaseOnce.Do(func() { close(dnsRelease) }) }
	ready := make(chan struct{})
	peer := &mdns.Server{Listener: dnsListener, Net: "tcp", NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		if q.Question[0].Name == "held.close.example." {
			dnsOnce.Do(func() { close(dnsEntered) })
			<-dnsRelease
		}
		answer := new(mdns.Msg)
		answer.SetReply(q)
		rr, _ := mdns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.81")
		answer.Answer = append(answer.Answer, rr)
		_ = w.WriteMsg(answer)
	})}
	served := make(chan error, 1)
	go func() { served <- peer.ActivateAndServe() }()
	<-ready
	defer func() { unblockDNS(); _ = peer.Shutdown(); <-served }()
	dnsScript := configuredLuaFile(t, "ingress-dns", `local server=require("xray.dns").Servers[1]; function HandleDNSQuery(domain,ipv4,ipv6,fake) return server:Query(domain,ipv4,ipv6,fake) end`)
	routeScript := configuredLuaFile(t, "ingress-route", `local dns=require("xray.dns"); function HandleRoute(ctx,inbound,sourcePort,targetPort,localPort,domain) local _,_,err=dns.Query(domain,true,false,false); if err then return nil,nil,err end; return "selected-A","ingress",nil end`)
	reservation, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	address, port := reservation.Addr().String(), reservation.Addr().(*stdnet.TCPAddr).Port
	config := configuredBuild(t, map[string]any{
		"routing":  map[string]any{"script": routeScript},
		"dns":      map[string]any{"script": dnsScript, "disableCache": true, "servers": []any{map[string]any{"address": "tcp+local://" + dnsListener.Addr().String(), "timeoutMs": 10000}}},
		"inbounds": []any{map[string]any{"tag": "close-ingress", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
		"outbounds": []any{
			map[string]any{"tag": "fallback-B", "protocol": "freedom", "settings": map[string]any{"redirect": b}},
			map[string]any{"tag": "selected-A", "protocol": "freedom", "settings": map[string]any{"redirect": a}},
		},
	})
	nativeConfig := config.Inbound[0]
	config.Inbound = nil
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
	var releaseOnce, closeOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	closed := make(chan struct{})
	var closeErr error
	startClose := func() { closeOnce.Do(func() { go func() { closeErr = instance.Close(); close(closed) }() }) }
	defer func() {
		unblockDNS()
		releaseClose()
		startClose()
		select {
		case <-closed:
			if closeErr != nil {
				t.Error(closeErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("owned instance Close did not finish after fixture release")
		}
	}()
	object, err := core.CreateObject(instance, nativeConfig)
	if err != nil {
		t.Fatal(err)
	}
	barrier := &configuredCloseBarrier{Handler: object.(inbound.Handler), entered: closeEntered, release: closeRelease}
	if err := instance.GetFeature(inbound.ManagerType()).(inbound.Manager).AddHandler(context.Background(), barrier); err != nil {
		t.Fatal(err)
	}
	_ = reservation.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	baseline := configuredSOCKSRequest(t, address, "baseline.close.example", "baseline")
	var baselineReply [9]byte
	if _, err := io.ReadFull(baseline, baselineReply[:]); err != nil || !bytes.Equal(baselineReply[:], []byte("Abaseline")) {
		t.Fatalf("real ingress preflight: %q, %v", baselineReply, err)
	}
	_ = baseline.Close()
	select {
	case got := <-payloads:
		if got.endpoint != 'A' || got.payload != "baseline" {
			t.Fatalf("preflight backend payload: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("preflight payload did not reach the selected endpoint")
	}
	held := configuredSOCKSRequest(t, address, "held.close.example", "held----")
	select {
	case <-dnsEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("real ingress did not enter the held router-to-DNS query")
	}
	startClose()
	select {
	case <-closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel DNS/router and reach native inbound retirement")
	}
	// The listener is deliberately still native and open at this exact point;
	// the SOCKS replies prove that the concurrent request reached its input.
	during := configuredSOCKSRequest(t, address, "during.close.example", "during--")
	for name, conn := range map[string]stdnet.Conn{"held": held, "during": during} {
		var response [9]byte
		n, err := io.ReadFull(conn, response[:])
		if err == nil || n != 0 {
			t.Errorf("%s ingress received payload after routing retirement: n=%d bytes=%q err=%v", name, n, response[:n], err)
		} else if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
			t.Errorf("%s ingress remained pending after routing retirement: %v", name, err)
		}
		_ = conn.Close()
	}
	for {
		select {
		case got := <-payloads:
			t.Errorf("retired routing decision delivered application payload to endpoint %c: %q", got.endpoint, got.payload)
		default:
			goto drained
		}
	}
drained:
	releaseClose()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish native listener retirement")
	}
	if conn, err := stdnet.DialTimeout("tcp4", address, time.Second); err == nil {
		_ = conn.Close()
		t.Error("configured inbound accepted a connection after Close returned")
	}
}
