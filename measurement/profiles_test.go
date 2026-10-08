package measurement_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/measurement"
	legacyss "github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

// Retain both ordinary networks on both tags and DIRECT while one measured
// exchange is held at its endpoint. Nothing redials an ordinary connection.
func testProtocolWorkingNode(t *testing.T, e *measurement.Executor, v *core.Instance, tunnelHost string, exactUDP bool) {
	t.Helper()
	t.Run("working-node", func(t *testing.T) {
		var carrierScope uint64
		if carrierDials != nil {
			carrierScope = carrierDials.beginScope()
		}
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		var peersMu sync.Mutex
		var peers []net.Conn
		accepted := make(chan struct{}, 8)
		acceptDone := make(chan struct{})
		go func() {
			defer close(acceptDone)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				workers.Add(1)
				peersMu.Lock()
				peers = append(peers, c)
				peersMu.Unlock()
				accepted <- struct{}{}
				go func() { defer workers.Done(); defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		var connections []net.Conn
		var connectionRoutes []measurement.Route
		var destinations []xnet.Destination
		var globalIDs [][8]byte
		var remoteEntries []*mux.XUDP
		var echoTimes []time.Duration
		var b7 *b7OrdinaryFacts
		defer func() {
			for _, c := range connections {
				c.Close()
			}
			cancel()
			ln.Close()
			<-acceptDone
			peersMu.Lock()
			for _, c := range peers {
				c.Close()
			}
			peersMu.Unlock()
			joined := make(chan struct{})
			go func() { workers.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(3 * time.Second):
				t.Error("ordinary endpoint TCP workers retained after close")
			}
		}()
		pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) { _, _ = pc.WriteTo(b, a) })
		routes := []measurement.Route{{Kind: measurement.ExactOutbound, Tag: "exact"}, {Kind: measurement.ExactOutbound, Tag: "second"}, {Kind: measurement.Direct}}
		// Establish a cold Measurement stream before any ordinary connection.
		cold := directHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "cold") }), "127.0.0.1", true, tunnelHost)
		epoch := 0
		exchangeOrdinary := func(t *testing.T, index int) {
			t.Helper()
			epoch++
			c := connections[index]
			payload := []byte(fmt.Sprintf("ordinary-%02d-%04d", index, epoch))
			done := make(chan error, 1)
			started := time.Now()
			go func() {
				var err error
				if globalIDs[index] != [8]byte{} {
					b := buf.FromBytes(payload)
					dest := destinations[index]
					b.UDP = &dest
					err = c.(buf.Writer).WriteMultiBuffer(buf.MultiBuffer{b})
				} else {
					n, writeErr := c.Write(payload)
					err = writeErr
					if err == nil && n != len(payload) {
						err = io.ErrShortWrite
					}
				}
				if err == nil {
					b := make([]byte, len(payload))
					_, err = io.ReadFull(c, b)
					if err == nil && !bytes.Equal(b, payload) {
						err = fmt.Errorf("ordinary connection%d payload=%q", index, b)
					}
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("ordinary connection%d: %v", index, err)
				}
			case <-time.After(3 * time.Second):
				c.Close()
				t.Fatalf("ordinary connection%d stalled", index)
			}
			echoTimes = append(echoTimes, time.Since(started))
			b7.receipt(connectionRoutes[index], len(payload))
			if id := globalIDs[index]; id != [8]byte{} {
				mux.XUDPManager.Lock()
				entry := mux.XUDPManager.Map[id]
				mux.XUDPManager.Unlock()
				if entry == nil {
					t.Fatal("nonzero native XUDP GlobalID did not reach peer")
				}
				if remoteEntries[index] == nil {
					remoteEntries[index] = entry
				} else if remoteEntries[index] != entry {
					t.Fatal("Measurement replaced ordinary persistent XUDP entry")
				}
			}
		}
		pulse := func(t *testing.T) {
			t.Helper()
			for index := range connections {
				exchangeOrdinary(t, index)
			}
			b7.check(t, false)
		}
		for _, route := range routes {
			r := request(cold, route.Kind)
			// Include REALITY's native five-second detector increments in this
			// one cold exchange; no retry or preparatory warm request is made.
			r.Timeout = 10 * time.Second
			r.Route, r.URL = route, protocolFixtureURL(r.URL, route, tunnelHost)
			if got, err := e.HTTPS(ctx, r); err != nil || string(got.Body) != "cold" || !got.BodyComplete {
				cold.Close()
				t.Fatalf("cold %+v %v", got, err)
			}
		}
		cold.Close()
		b7 = b7BeginOrdinary(t, v, exactUDP)
		if carrierDials != nil {
			carrierDials.mu.Lock()
			carrierDials.uploads = make(map[string]map[string]int)
			carrierDials.mu.Unlock()
		}
		for _, route := range routes {
			for _, network := range []string{"tcp", "udp"} {
				if network == "udp" && route.Kind == measurement.ExactOutbound && !exactUDP {
					continue
				}
				addr := ln.Addr().String()
				if network == "udp" {
					addr = pc.LocalAddr().String()
				}
				var c net.Conn
				var err error
				var source xnet.Destination
				dest, parseErr := xnet.ParseDestination(network + ":" + addr)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				var globalID [8]byte
				if route.Kind == measurement.Direct {
					c, err = (&net.Dialer{}).DialContext(ctx, network, addr)
				} else {
					if tunnelHost != "" {
						dest.Address = xnet.ParseAddress(tunnelHost)
					}
					ordinary := session.ContextWithTrafficOrigin(session.SetForcedOutboundTagToContext(ctx, route.Tag), session.TrafficOriginUser)
					if b7 != nil {
						source = xnet.Destination{Network: dest.Network, Address: xnet.LocalHostIP, Port: xnet.Port(40000 + len(connections))}
						ordinary = session.ContextWithInbound(ordinary, &session.Inbound{Name: "socks", Source: source})
					}
					if carrierDials != nil && network == "udp" {
						sender, err := v.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler(route.Tag).SenderSettings().GetInstance()
						if err != nil {
							t.Fatal(err)
						}
						if settings := sender.(*proxyman.SenderConfig).MultiplexSettings; settings != nil && settings.XudpConcurrency > 0 {
							// Distinct source addresses keep the two ordinary GlobalIDs
							// distinct even if a released ephemeral source port repeats.
							source := xnet.IPAddress(net.IPv4(127, 0, 0, byte(len(connections)+1)))
							ordinary = session.ContextWithInbound(ordinary, &session.Inbound{Name: "socks", Source: xnet.UDPDestination(source, udp.PickPort())})
							ordinary = context.WithValue(ordinary, "cone", true)
							globalID = xudp.GetGlobalID(ordinary)
							if globalID == [8]byte{} {
								t.Fatal("fixture did not admit nonzero ordinary XUDP identity")
							}
						}
					}
					c, err = core.Dial(ordinary, v, dest)
					if inbound := session.InboundFromContext(ordinary); inbound != nil {
						source = inbound.Source
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				connections = append(connections, c)
				b7.endpoint(route, dest, source)
				connectionRoutes = append(connectionRoutes, route)
				destinations = append(destinations, dest)
				globalIDs = append(globalIDs, globalID)
				remoteEntries = append(remoteEntries, nil)
				exchangeOrdinary(t, len(connections)-1)
			}
		}
		pulse(t)
		if len(accepted) != 3 {
			t.Fatalf("ordinary TCP endpoint connections=%d want3", len(accepted))
		}
		for _, route := range routes {
			if route.Kind == measurement.ExactOutbound && !exactUDP {
				continue
			}
			for _, mode := range []string{"echo", "malformed", "cancel"} {
				t.Run(fmt.Sprintf("UDP/%d-%s/%s", route.Kind, route.Tag, mode), func(t *testing.T) {
					seen, release := make(chan []byte, 1), make(chan struct{})
					defer close(release)
					peer := udpFixture(t, func(pc net.PacketConn, b []byte, source net.Addr) {
						seen <- b
						<-release
						if mode == "cancel" {
							return
						}
						if mode == "malformed" {
							b[0] ^= 0xff
						}
						_, _ = pc.WriteTo(b, source)
					})
					r := udpRequest(peer.LocalAddr(), route.Kind)
					r.Route, r.Count, r.Interval, r.ReplyWait = route, 1, 0, 500*time.Millisecond
					r.Destination = protocolFixtureDestination(r.Destination, route, tunnelHost)
					ctx, cancel := context.WithCancel(ctx)
					defer cancel()
					type result struct {
						receipt measurement.UDPEchoReceipt
						err     error
					}
					done := make(chan result, 1)
					go func() { got, err := e.UDPEcho(ctx, r); done <- result{got, err} }()
					var packet []byte
					select {
					case packet = <-seen:
					case got := <-done:
						t.Fatalf("UDP ended before peer: %+v", got)
					case <-time.After(3 * time.Second):
						t.Fatal("UDP did not reach peer")
					}
					pulse(t)
					if b7 != nil && route.Kind == measurement.ExactOutbound {
						dest, err := xnet.ParseDestination("udp:" + r.Destination.String())
						if err != nil {
							t.Fatal(err)
						}
						b7.checkLive(t, fsB7Expected(dest, route.Tag))
					}
					if mode == "cancel" {
						cancel()
					} else {
						release <- struct{}{}
					}
					select {
					case got := <-done:
						if len(got.receipt.Sends) != 1 || len(packet) != r.PacketBytes || !bytes.Equal(packet[4:20], got.receipt.Nonce[:]) {
							t.Fatalf("UDP peer/write facts: %+v %v", got.receipt, got.err)
						}
						if mode == "cancel" {
							if !errors.Is(got.err, context.Canceled) || got.receipt.WindowComplete {
								t.Fatalf("UDP cancel: %+v %v", got.receipt, got.err)
							}
						} else if got.err != nil || !got.receipt.WindowComplete || len(got.receipt.Replies) != 1 || (got.receipt.Replies[0].Issue == measurement.UDPReplyValid) != (mode == "echo") {
							t.Fatalf("UDP %s: %+v %v", mode, got.receipt, got.err)
						}
					case <-time.After(4 * time.Second):
						t.Fatal("UDP did not join")
					}
					pulse(t)
				})
			}
		}
		for wave := range 3 {
			for _, route := range routes {
				for _, mode := range []string{"success", "failure", "cancel"} {
					t.Run(fmt.Sprintf("wave%d/%d-%s/%s", wave, route.Kind, route.Tag, mode), func(t *testing.T) {
						entered, release := make(chan struct{}), make(chan struct{}, 1)
						s := directHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							w.Header().Set("Content-Length", "12")
							_, _ = io.WriteString(w, "prefix")
							w.(http.Flusher).Flush()
							close(entered)
							select {
							case <-release:
							case <-r.Context().Done():
								return
							}
							if mode == "success" {
								_, _ = io.WriteString(w, "suffix")
							}
						}), "127.0.0.1", true, tunnelHost)
						defer s.Close()
						defer close(release)
						request := request(s, route.Kind)
						request.Route = route
						request.Timeout = 15 * time.Second
						request.URL = protocolFixtureURL(request.URL, route, tunnelHost)
						ctx, cancel := context.WithCancel(ctx)
						defer cancel()
						if b7 != nil && wave == 0 && route.Kind == measurement.ExactOutbound && route.Tag == "exact" && mode == "success" {
							ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
							ctx = session.ContextWithLogicalObservation(ctx, b7InheritedOrdinary(t))
						}
						done := make(chan struct{})
						var receipt measurement.HTTPSReceipt
						var err error
						go func() { receipt, err = e.HTTPS(ctx, request); close(done) }()
						select {
						case <-entered:
						case <-done:
							t.Fatalf("exchange ended before peer: %v", err)
						case <-time.After(4 * time.Second):
							t.Fatal("exchange did not reach peer")
						}
						pulse(t)
						if b7 != nil && route.Kind == measurement.ExactOutbound {
							b7.checkLive(t, fsB7Expected(b7HTTPDestination(request.URL), route.Tag))
						}
						if mode == "cancel" {
							cancel()
						} else {
							release <- struct{}{}
						}
						select {
						case <-done:
						case <-time.After(4 * time.Second):
							t.Fatal("exchange did not return")
						}
						if mode == "success" {
							if err != nil || !receipt.BodyComplete || string(receipt.Body) != "prefixsuffix" {
								t.Fatalf("success %+v %v", receipt, err)
							}
						} else if mode == "failure" {
							if !errors.Is(err, io.ErrUnexpectedEOF) || receipt.BodyComplete || string(receipt.Body) != "prefix" {
								t.Fatalf("partial %+v %v", receipt, err)
							}
						} else if !errors.Is(err, context.Canceled) || receipt.BodyComplete {
							t.Fatalf("cancel %+v %v", receipt, err)
						}
						pulse(t)
					})
				}
			}
			var memory runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&memory)
			t.Logf("same-config wave%d: HeapAlloc=%d HeapObjects=%d goroutines=%d", wave, memory.HeapAlloc, memory.HeapObjects, runtime.NumGoroutine())
			t.Logf("ordinary echo durations wave%d: %v", wave, echoTimes)
			echoTimes = nil
		}
		if carrierDials != nil {
			carrierDials.check(t, v, carrierScope)
		}
		testProtocolHandlerChanges(t, e, v, tunnelHost, func(t *testing.T, primary bool) {
			if primary {
				pulse(t)
				return
			}
			first := 1
			if exactUDP {
				first = 2
			}
			for index := first; index < len(connections); index++ {
				exchangeOrdinary(t, index)
			}
		})
		if len(accepted) != 3 {
			t.Fatal("ordinary TCP sessions were replaced")
		}
		b7.finish(t, connections)
	})
}

// Remove changes registration only. Replacing the tag with native Freedom
// changes future selection, without creating a competing WireGuard device
// with another live handler's keys. Close tests the original profile owner.
func testProtocolHandlerChanges(t *testing.T, e *measurement.Executor, v *core.Instance, tunnelHost string, pulse func(*testing.T, bool)) {
	t.Helper()
	t.Run("handler-changes", func(t *testing.T) {
		manager := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
		old := manager.GetHandler("exact")
		closed := false
		defer func() {
			_ = manager.RemoveHandler(context.Background(), "exact")
			if closed {
				object, err := core.CreateObject(v, &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: old.SenderSettings(), ProxySettings: old.ProxySettings()})
				if err != nil {
					t.Error(err)
					return
				}
				old = &protocolDispatchWitness{Handler: object.(outbound.Handler), counter: old.(*protocolDispatchWitness).counter}
			}
			if err := manager.AddHandler(context.Background(), old); err != nil {
				t.Error(err)
			}
		}()
		entered, release := make(chan struct{}, 1), make(chan struct{}, 1)
		s := directHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/active" {
				entered <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = io.WriteString(w, "handler")
		}), "127.0.0.1", true, tunnelHost)
		defer s.Close()
		defer close(release)
		r := request(s, measurement.ExactOutbound)
		r.URL = protocolFixtureURL(r.URL, r.Route, tunnelHost)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type result struct {
			receipt measurement.HTTPSReceipt
			err     error
		}
		active := func() chan result {
			done := make(chan result, 1)
			a := r
			a.URL += "/active"
			go func() { got, err := e.HTTPS(ctx, a); done <- result{got, err} }()
			select {
			case <-entered:
			case got := <-done:
				t.Fatalf("active handler ended: %+v", got)
			case <-time.After(4 * time.Second):
				t.Fatal("handler request not active")
			}
			return done
		}
		done := active()
		if err := manager.RemoveHandler(ctx, "exact"); err != nil {
			t.Fatal(err)
		}
		pulse(t, true)
		if got, err := e.HTTPS(ctx, r); err == nil || got.StatusCode != 0 {
			t.Fatalf("removed tag fell back: %+v %v", got, err)
		}
		release <- struct{}{}
		select {
		case got := <-done:
			if got.err != nil || string(got.receipt.Body) != "handler" {
				t.Fatalf("remove closed selected handler: %+v", got)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("selected old handler did not finish")
		}
		object, err := core.CreateObject(v, config("exact", false))
		if err != nil {
			t.Fatal(err)
		}
		replacement := object.(outbound.Handler)
		defer replacement.Close()
		if err := manager.AddHandler(ctx, replacement); err != nil {
			t.Fatal(err)
		}
		directReplacement := r
		directReplacement.URL = s.URL
		if got, err := e.HTTPS(ctx, directReplacement); err != nil || string(got.Body) != "handler" {
			t.Fatalf("replacement: %+v %v", got, err)
		}
		pulse(t, true)
		if err := manager.RemoveHandler(ctx, "exact"); err != nil {
			t.Fatal(err)
		}
		if err := manager.AddHandler(ctx, old); err != nil {
			t.Fatal(err)
		}
		done = active()
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
		closed = true
		// Native Close may be a no-op or close its own device/sessions.
		// Only the unaffected tag and DIRECT must retain ordinary exchanges.
		pulse(t, false)
		cancel()
		select {
		case got := <-done:
			if got.err == nil {
				t.Fatal("active Close/cancel lost interruption")
			}
			t.Logf("replacement Close/cancel: %v outbound=%v", got.err, got.receipt.OutboundError)
		case <-time.After(4 * time.Second):
			t.Fatal("handler Close/cancel did not return")
		}
	})
}

func TestAdditionalProtocolMeasurements(t *testing.T) {
	for _, profile := range []string{"ss-aes128", "ss-aes256", "ss-chacha20", "ss-xchacha20", "socks", "http"} {
		t.Run(profile, func(t *testing.T) {
			e, v, counters := plainProtocolExecutor(t, profile)
			testProtocolMeasurements(t, e, v, counters, profile == "http")
			if profile != "http" {
				limit := 8137
				if profile == "ss-aes128" {
					limit = 8153
				} else if profile == "socks" {
					limit = 8182
				}
				testProtocolPacketBoundary(t, e, "", limit, false)
			}
		})
	}
}

func TestXHTTPManagerConfigSnapshotAndNilDefaults(t *testing.T) {
	config := &splithttp.XmuxConfig{CMaxReuseTimes: &splithttp.RangeConfig{From: 2, To: 2}}
	calls := 0
	m := splithttp.NewXmuxManager(config, func() splithttp.XmuxConn { calls++; return xmuxFixtureConn{} })
	config.CMaxReuseTimes.From, config.CMaxReuseTimes.To = 1, 1
	for range 4 {
		m.GetXmuxClient(context.Background())
	}
	if calls != 2 {
		t.Fatalf("caller mutation changed the private manager snapshot: %d connections", calls)
	}
	var nilCalls, emptyCalls int
	nilManager := splithttp.NewXmuxManager(nil, func() splithttp.XmuxConn { nilCalls++; return xmuxFixtureConn{} })
	emptyManager := splithttp.NewXmuxManager(&splithttp.XmuxConfig{}, func() splithttp.XmuxConn { emptyCalls++; return xmuxFixtureConn{} })
	for range 64 {
		nilManager.GetXmuxClient(context.Background()).AddRunning()
		emptyManager.GetXmuxClient(context.Background()).AddRunning()
	}
	if nilCalls != emptyCalls || nilCalls == 0 {
		t.Fatalf("nil configuration lost native defaults: nil%d empty%d", nilCalls, emptyCalls)
	}
}

type xmuxFixtureConn struct{}

func (xmuxFixtureConn) IsClosed() bool { return false }

// These profile ceilings bound complete native round trips, not executor policy.
// A request may reach the peer above a smaller native reply-path limit.
// A reply authenticates every echoed byte against the operation's original
// random payload. Writer acceptance alone does not establish peer delivery.
func testProtocolPacketBoundary(t *testing.T, e *measurement.Executor, tunnelHost string, limit int, aboveReachesPeer bool) {
	t.Helper()
	if b7Enabled {
		return
	}
	if carrierDials != nil {
		return
	}
	testProtocolPacketBoundaryAt(t, e, tunnelHost, limit, aboveReachesPeer, "127.0.0.1")
	if tunnelHost == "" {
		t.Run("ipv6", func(t *testing.T) {
			directIPv6Capability(t)
			ipv6Limit := limit
			switch limit {
			case 8181, 8153, 8137, 8182, 8134, 8110:
				ipv6Limit -= 12
			}
			testProtocolPacketBoundaryAt(t, e, "", ipv6Limit, aboveReachesPeer, "::1")
		})
	}
}

func testProtocolPacketBoundaryAt(t *testing.T, e *measurement.Executor, tunnelHost string, limit int, aboveReachesPeer bool, host string) {
	t.Helper()
	for _, tag := range []string{"exact", "second"} {
		t.Run("packet-boundary/"+tag, func(t *testing.T) {
			for _, offset := range []int{-1, 0, 1} {
				t.Run(fmt.Sprint(offset), func(t *testing.T) {
					packets := make(chan []byte, 4)
					pc := udpFixtureAt(t, net.JoinHostPort(host, "0"), func(pc net.PacketConn, b []byte, source net.Addr) {
						packets <- b
						_, _ = pc.WriteTo(b, source)
					})
					r := udpRequest(pc.LocalAddr(), measurement.ExactOutbound)
					r.Route.Tag = tag
					r.Destination = protocolFixtureDestination(r.Destination, r.Route, tunnelHost)
					ceiling := limit
					r.Count, r.PacketBytes, r.Interval, r.ReplyWait, r.Timeout = 1, ceiling+offset, 0, 200*time.Millisecond, 3*time.Second
					got, err := e.UDPEcho(context.Background(), r)
					wantPeer := offset <= 0 || aboveReachesPeer
					if wantPeer {
						select {
						case packet := <-packets:
							if len(packet) != r.PacketBytes || string(packet[:4]) != "MUE1" || !bytes.Equal(packet[4:20], got.Nonce[:]) {
								t.Fatalf("peer packet corrupted: len%d want%d", len(packet), r.PacketBytes)
							}
						default:
							t.Fatalf("packet%d did not reach peer: %+v, %v", r.PacketBytes, got, err)
						}
					} else if len(packets) != 0 {
						t.Fatalf("oversize packet%d reached peer", r.PacketBytes)
					}
					if offset <= 0 {
						if err != nil || !got.WindowComplete || len(got.Sends) != 1 || got.Sends[0].WriterBytes != r.PacketBytes || len(got.Replies) != 1 || got.Replies[0].Issue != measurement.UDPReplyValid || got.Replies[0].Bytes != r.PacketBytes || got.Replies[0].Source != r.Destination {
							t.Fatalf("native boundary%d: %+v, %v", r.PacketBytes, got, err)
						}
					} else {
						for _, reply := range got.Replies {
							if reply.Issue == measurement.UDPReplyValid {
								t.Fatalf("oversize native payload accepted: %+v", got)
							}
						}
					}
					t.Logf("payload%d peer%t replies%d error%v outbound%v", r.PacketBytes, wantPeer, len(got.Replies), err, got.OutboundError)
				})
			}
		})
	}
}

func TestLegacyShadowsocksPacketCapacity(t *testing.T) {
	for _, cipher := range []legacyss.CipherType{legacyss.CipherType_AES_128_GCM, legacyss.CipherType_AES_256_GCM, legacyss.CipherType_CHACHA20_POLY1305, legacyss.CipherType_XCHACHA20_POLY1305} {
		t.Run(cipher.String(), func(t *testing.T) {
			account, err := (&legacyss.Account{CipherType: cipher, Password: "fixture"}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			r := &protocol.RequestHeader{Command: protocol.RequestCommandUDP, Address: xnet.LocalHostIP, Port: 12345, User: &protocol.MemoryUser{Account: account}}
			limit := 8137 // IPv4 address7, salt32, AEAD tag16 in native8192.
			if cipher == legacyss.CipherType_AES_128_GCM {
				limit = 8153 // AES128 salt16.
			}
			for _, size := range []int{limit - 1, limit, limit + 1, buf.Size + 1} {
				payload := bytes.Repeat([]byte{0x5a}, size)
				encoded, err := legacyss.EncodeUDPPacket(r, payload)
				if size > limit {
					if !errors.Is(err, buf.ErrBufferFull) || encoded != nil {
						t.Fatalf("oversize payload%d encoded=%v error=%v", size, encoded, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				validator := new(legacyss.Validator)
				validator.Add(r.User)
				decodedRequest, decoded, err := legacyss.DecodeUDPPacket(validator, encoded)
				if err != nil {
					encoded.Release()
					t.Fatal(err)
				}
				if !bytes.Equal(decoded.Bytes(), payload) || decodedRequest.Address != r.Address || decodedRequest.Port != r.Port {
					t.Errorf("boundary packet%d did not preserve payload/destination", size)
				}
				decoded.Release()
			}
		})
	}
}
