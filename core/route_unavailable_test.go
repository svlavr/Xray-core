package core_test

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
)

func unavailableDNSPeer(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered, release, ready := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	peer := &mdns.Server{Listener: listener, Net: "tcp", NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		once.Do(func() { close(entered) })
		<-release
		answer := new(mdns.Msg)
		answer.SetReply(q)
		_ = w.WriteMsg(answer)
	})}
	done := make(chan error, 1)
	go func() { done <- peer.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { unblock(); _ = peer.Shutdown(); <-done })
	return listener.Addr().String(), entered, unblock
}

func unavailableInstance(t *testing.T, script, dnsAddress string, timeoutMs int) (*core.Instance, string, <-chan configuredIngressPayload) {
	t.Helper()
	payloads := make(chan configuredIngressPayload, 8)
	a, b := configuredPayloadEndpoint(t, 'A', payloads), configuredPayloadEndpoint(t, 'B', payloads)
	reservation, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	config := map[string]any{
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": reservation.Addr().(*stdnet.TCPAddr).Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
		"outbounds": []any{
			map[string]any{"tag": "fallback-B", "protocol": "freedom", "settings": map[string]any{"redirect": b}},
			map[string]any{"tag": "selected-A", "protocol": "freedom", "settings": map[string]any{"redirect": a}},
		},
	}
	if script != "" {
		config["routing"] = map[string]any{"script": configuredLuaFile(t, "unavailable-route", script)}
	}
	if dnsAddress != "" {
		config["dns"] = map[string]any{"disableCache": true, "servers": []any{map[string]any{"address": "tcp+local://" + dnsAddress, "timeoutMs": timeoutMs}}}
	}
	instance, err := core.New(configuredBuild(t, config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	address := reservation.Addr().String()
	_ = reservation.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, address, payloads
}

func TestRouteUnavailablePreservesNativeFallback(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		dnsTimeout   bool
	}{
		{name: "native-no-rule"},
		{name: "lua-nil", script: `function HandleRoute(...) return nil end`},
		{name: "lua-returned-error", script: `function HandleRoute(...) return nil,nil,"ordinary route error" end`},
		{name: "lua-raised-error", script: `function HandleRoute(...) error("ordinary script failure") end`},
		{name: "execution-deadline", script: `function HandleRoute(...) while true do end end`},
		{name: "live-DNS-server-deadline", dnsTimeout: true, script: `local dns=require("xray.dns"); function HandleRoute(ctx,inbound,sourcePort,targetPort,localPort,domain) local _,_,err=dns.Query(domain,true,false,false); return nil,nil,err end`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dnsAddress string
			var entered <-chan struct{}
			var unblock func()
			if tc.dnsTimeout {
				dnsAddress, entered, unblock = unavailableDNSPeer(t)
			}
			_, address, payloads := unavailableInstance(t, tc.script, dnsAddress, 100)
			if unblock != nil {
				t.Cleanup(unblock)
			}
			conn := configuredSOCKSRequest(t, address, "live.route.example", "control-")
			// A live engine's native execution limit is six seconds.
			_ = conn.SetDeadline(time.Now().Add(9 * time.Second))
			var response [9]byte
			if _, err := io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "Bcontrol-" {
				t.Fatalf("native fallback changed: %q %v", response, err)
			}
			if entered != nil {
				select {
				case <-entered:
				default:
					t.Fatal("DNS timeout control never reached the owned peer")
				}
			}
			select {
			case got := <-payloads:
				if got.endpoint != 'B' || got.payload != "control-" {
					t.Fatalf("wrong fallback payload custody: %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("fallback payload was not delivered")
			}
		})
	}
}

func TestRouteUnavailableRetiredOwnerCannotMaskResult(t *testing.T) {
	for _, retirement := range []string{"DNS", "engine"} {
		for _, result := range []string{"nil", `"selected-A"`} {
			t.Run(retirement+"/return="+result, func(t *testing.T) {
				dnsAddress, entered, unblock := unavailableDNSPeer(t)
				script := `local dns=require("xray.dns"); function HandleRoute(ctx,inbound,sourcePort,targetPort,localPort,domain) dns.Query(domain,true,false,false); return ` + result + ` end`
				instance, address, payloads := unavailableInstance(t, script, dnsAddress, 10000)
				t.Cleanup(unblock)
				conn := configuredSOCKSRequest(t, address, "held.route.example", "held----")
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("native ingress did not enter the exact DNS owner")
				}
				router := instance.GetFeature(routing.RouterType()).(routing.Router)
				owner := interface{ Close() error }(router)
				if retirement == "DNS" {
					owner = instance.GetFeature(featuredns.ClientType()).(interface{ Close() error })
				}
				closed := make(chan error, 1)
				go func() { closed <- owner.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("owner retirement did not cancel its admitted route")
				}
				var response [9]byte
				if n, err := io.ReadFull(conn, response[:]); err == nil || n != 0 {
					t.Fatalf("retired owner forwarded payload: n=%d bytes=%q err=%v", n, response[:n], err)
				} else if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
					t.Fatalf("retired route remained pending: %v", err)
				}
				route, err := router.PickRoute(&routingsession.Context{Outbound: &session.Outbound{Target: net.TCPDestination(net.DomainAddress("after.route.example"), 443)}})
				var unavailable *routing.RouteUnavailableError
				if route != nil || !errors.As(err, &unavailable) || !errors.Is(err, context.Canceled) {
					t.Fatalf("post-retirement admission lost terminal cause: %v %v", route, err)
				}
				select {
				case got := <-payloads:
					t.Fatalf("retired owner delivered application payload: %+v", got)
				default:
				}
			})
		}
	}
}

func TestRouteUnavailableCanceledCallerDoesNotFallBack(t *testing.T) {
	instance, _, payloads := unavailableInstance(t, "", "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := core.Dial(ctx, instance, net.TCPDestination(net.DomainAddress("canceled.route.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, _ = conn.Write([]byte("caller--"))
		var payload [1]byte
		n, err := conn.Read(payload[:])
		if n != 0 || err == nil {
			done <- errors.New("canceled caller received outbound payload")
		} else {
			done <- nil
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled caller was left pending")
	}
	select {
	case got := <-payloads:
		t.Fatalf("canceled caller delivered application payload: %+v", got)
	default:
	}
}
