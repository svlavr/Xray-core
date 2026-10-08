package measurement_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	statsfeature "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	hyproxy "github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	legacyss "github.com/xtls/xray-core/proxy/shadowsocks"
	ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessencoding "github.com/xtls/xray-core/proxy/vmess/encoding"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessout "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func hysteriaExecutor(t *testing.T) (*measurement.Executor, *core.Instance, [2]statsfeature.Counter) {
	t.Helper()
	certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	stream := func(server bool) *internet.StreamConfig {
		security := &xtls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{hash[:]}, NextProtocol: []string{"h3"}}
		if server {
			security.Certificate = []*xtls.Certificate{xtls.ParseCertificate(certificate)}
		}
		return &internet.StreamConfig{
			ProtocolName:      "hysteria",
			TransportSettings: []*internet.TransportConfig{{ProtocolName: "hysteria", Settings: serial.ToTypedMessage(&hytransport.Config{Auth: "fixture", UdpIdleTimeout: 60})}},
			SecurityType:      serial.GetMessageType(security), SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(security)},
			QuicParams: &internet.QuicParams{DisableChromeParrot: true, Congestion: "reno"},
		}
	}
	v := instance(t)
	var counters [2]statsfeature.Counter
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	for i, tag := range []string{"exact", "second"} {
		port := udp.PickPort()
		peer, err := core.New(&core.Config{
			App:      protocolPeerApps(),
			Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}, StreamSettings: stream(true)}), ProxySettings: serial.ToTypedMessage(&hyproxy.ServerConfig{Users: []*protocol.User{{Account: serial.ToTypedMessage(&hyaccount.Account{Auth: "fixture"})}}})}},
			Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.Start(); err != nil {
			peer.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		counters[i] = addProtocolOutbound(t, v, &core.OutboundHandlerConfig{Tag: tag, SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: stream(false)}), ProxySettings: serial.ToTypedMessage(&hyproxy.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port)}})})
	}
	return executor(t, v), v, counters
}

func TestHysteriaMeasurementSeriesAndUDPCancellation(t *testing.T) {
	e, v, counters := hysteriaExecutor(t)
	testProtocolMeasurements(t, e, v, counters)
	// Serialization grows dynamically; the native receive buffer bounds decoded payload.
	testProtocolPacketBoundary(t, e, "", int(buf.Size), false)
}

func TestNativeProtocolMeasurements(t *testing.T) {
	for _, profile := range []string{"vless", "vmess", "trojan", ss.MethodAES128GCM, ss.MethodAES256GCM, ss.MethodChaCha20Poly1305} {
		t.Run(profile, func(t *testing.T) {
			e, v, counters := plainProtocolExecutor(t, profile)
			testProtocolMeasurements(t, e, v, counters)
			limit, abovePeer := 7526, false
			if profile == "trojan" {
				limit = 8181
			} else if profile == ss.MethodChaCha20Poly1305 {
				limit, abovePeer = 8110, true
			} else if profile == ss.MethodAES128GCM || profile == ss.MethodAES256GCM {
				limit, abovePeer = 8134, true
			}
			testProtocolPacketBoundary(t, e, "", limit, abovePeer)
		})
	}
}

func plainProtocolExecutor(t *testing.T, profile string, customize ...func(*core.InboundHandlerConfig, *core.OutboundHandlerConfig)) (*measurement.Executor, *core.Instance, [2]statsfeature.Counter) {
	t.Helper()
	v := instance(t)
	var counters [2]statsfeature.Counter
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	for i, tag := range []string{"exact", "second"} {
		var port xnet.Port
		if profile == "trojan" || profile == "vless" || profile == "vmess" || profile == "socks" || profile == "http" {
			port = tcp.PickPort()
		} else {
			port = protocolTCPUDPPort(t)
		}
		var inbound, client *serial.TypedMessage
		if profile == "vless" {
			peerID := uuid.New()
			id := peerID.String()
			inbound = serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: id})}}})
			client = serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"})}}})
		} else if profile == "vmess" {
			id := uuid.New()
			account := serial.ToTypedMessage(&vmess.Account{Id: id.String(), SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}})
			inbound = serial.ToTypedMessage(&vmessin.Config{User: []*protocol.User{{Account: account}}})
			client = serial.ToTypedMessage(&vmessout.Config{Receiver: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: account}}})
		} else if profile == "trojan" {
			account := serial.ToTypedMessage(&trojan.Account{Password: "fixture"})
			inbound = serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{{Account: account}}})
			client = serial.ToTypedMessage(&trojan.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: account}}})
		} else if profile == "socks" {
			inbound = serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{"fixture": "password"}, Address: xnet.NewIPOrDomain(xnet.LocalHostIP), UdpEnabled: true})
			client = serial.ToTypedMessage(&socks.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(&socks.Account{Username: "fixture", Password: "password"})}}})
		} else if profile == "http" {
			inbound = serial.ToTypedMessage(&httpproxy.ServerConfig{Accounts: map[string]string{"fixture": "password"}})
			client = serial.ToTypedMessage(&httpproxy.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(&httpproxy.Account{Username: "fixture", Password: "password"})}}})
		} else if cipher, ok := map[string]legacyss.CipherType{"ss-aes128": legacyss.CipherType_AES_128_GCM, "ss-aes256": legacyss.CipherType_AES_256_GCM, "ss-chacha20": legacyss.CipherType_CHACHA20_POLY1305, "ss-xchacha20": legacyss.CipherType_XCHACHA20_POLY1305}[profile]; ok {
			user := &protocol.User{Account: serial.ToTypedMessage(&legacyss.Account{Password: "fixture", CipherType: cipher})}
			inbound = serial.ToTypedMessage(&legacyss.ServerConfig{Users: []*protocol.User{user}, Network: []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}})
			client = serial.ToTypedMessage(&legacyss.ClientConfig{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: user}})
		} else {
			keySize := 32
			if profile == ss.MethodAES128GCM {
				keySize = 16
			}
			key := base64.StdEncoding.EncodeToString(make([]byte, keySize)) // Local fixture only.
			inbound = serial.ToTypedMessage(&ss.ServerConfig{Method: profile, Key: key, Network: []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}})
			client = serial.ToTypedMessage(&ss.ClientConfig{Method: profile, Key: key, Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port)})
		}
		inboundConfig := &core.InboundHandlerConfig{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}}), ProxySettings: inbound}
		outboundConfig := &core.OutboundHandlerConfig{Tag: tag, SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: client}
		for _, apply := range customize {
			apply(inboundConfig, outboundConfig)
		}
		peer, err := core.New(&core.Config{
			App:      protocolPeerApps(),
			Inbound:  []*core.InboundHandlerConfig{inboundConfig},
			Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.Start(); err != nil {
			peer.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		if carrierDials != nil {
			sender, err := outboundConfig.SenderSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			stream := sender.(*proxyman.SenderConfig).StreamSettings
			if stream != nil && stream.ProtocolName == "splithttp" {
				settings, err := stream.TransportSettings[0].Settings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				if settings.(*splithttp.Config).Mode == "packet-up" {
					addr := packetUploadWitnessRelay(t, net.JoinHostPort("127.0.0.1", port.String())).(*net.TCPAddr)
					settings, err := outboundConfig.ProxySettings.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					settings.(*vlessout.Config).Vnext.Port = uint32(addr.Port)
					outboundConfig.ProxySettings = serial.ToTypedMessage(settings)
				}
			}
		}
		counters[i] = addProtocolOutbound(t, v, outboundConfig)
	}
	return executor(t, v), v, counters
}

// SS2022's fixture binds both networks. Windows can exclude different ranges
// for TCP and UDP, so a port allocated in just one network is insufficient.
func protocolTCPUDPPort(t *testing.T) xnet.Port {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := xnet.Port(ln.Addr().(*net.TCPAddr).Port)
		pc, err := net.ListenPacket("udp4", ln.Addr().String())
		ln.Close()
		if err == nil {
			pc.Close()
			return port
		}
		lastErr = err
	}
	t.Fatalf("no available combined TCP/UDP fixture port: %v", lastErr)
	return 0
}

func TestVMessUDPSourceBearingMeasurements(t *testing.T) {
	for _, disabled := range []string{"false", "true"} {
		t.Run("cone-disabled-"+disabled, func(t *testing.T) {
			t.Setenv("xray.cone.disabled", disabled)
			e, _, counters := plainProtocolExecutor(t, "vmess")
			for _, port := range []int{0, 53, 443} {
				t.Run(strconv.Itoa(port), func(t *testing.T) {
					var queries, echoes atomic.Int32
					pc := udpFixtureAt(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), func(pc net.PacketConn, b []byte, a net.Addr) {
						if string(b) == "native-fixture-echo" {
							pc.WriteTo(b, a)
						} else if len(b) >= 4 && string(b[:4]) == "MUE1" {
							echoes.Add(1)
							pc.WriteTo(b, a)
						} else if reply := dnsReply(b); reply != nil {
							queries.Add(1)
							pc.WriteTo(reply, a)
						}
					})
					// Some hosts filter loopback port 53 even after a successful bind.
					// Prove native delivery independently before attributing a failure to VMess.
					if port != 0 {
						probe, err := net.Dial("udp4", pc.LocalAddr().String())
						if err != nil {
							t.Fatal(err)
						}
						probe.SetDeadline(time.Now().Add(200 * time.Millisecond))
						_, writeErr := probe.Write([]byte("native-fixture-echo"))
						var b [64]byte
						n, readErr := probe.Read(b[:])
						probe.Close()
						if writeErr != nil || readErr != nil || string(b[:n]) != "native-fixture-echo" {
							t.Skipf("native loopback UDP port %d unavailable: write=%v read=%v", port, writeErr, readErr)
						}
					}
					for index, tag := range []string{"exact", "second"} {
						checkRoute := func(t *testing.T, before [2]int64) {
							t.Helper()
							if counters[index].Value() <= before[index] || counters[1-index].Value() != before[1-index] {
								t.Fatalf("wrong VMess peer for %s: before=%v after=[%d %d]", tag, before, counters[0].Value(), counters[1].Value())
							}
						}
						t.Run(tag+"-dns", func(t *testing.T) {
							before := [2]int64{counters[0].Value(), counters[1].Value()}
							r := dnsRequest(pc.LocalAddr(), measurement.DNSUDP, measurement.ExactOutbound)
							r.Route.Tag = tag
							got, err := e.DNSQuery(context.Background(), r)
							if err != nil || !got.ResponseComplete || got.Message == nil || len(got.Message.Answer) != 1 || len(got.Wire) == 0 {
								t.Fatalf("DNS delivered=%d receipt=%+v error=%v", queries.Load(), got, err)
							}
							checkRoute(t, before)
						})
						t.Run(tag+"-echo", func(t *testing.T) {
							before := [2]int64{counters[0].Value(), counters[1].Value()}
							r := udpRequest(pc.LocalAddr(), measurement.ExactOutbound)
							r.Route.Tag = tag
							got, err := e.UDPEcho(context.Background(), r)
							if err != nil || !got.WindowComplete || len(got.Replies) != r.Count {
								t.Fatalf("echo delivered=%d receipt=%+v error=%v", echoes.Load(), got, err)
							}
							for _, reply := range got.Replies {
								if reply.Issue != measurement.UDPReplyValid || reply.Source != r.Destination || reply.RoundTrip == nil {
									t.Fatalf("invalid source-bearing echo: %+v", reply)
								}
							}
							checkRoute(t, before)
						})
					}
					if queries.Load() != 2 || echoes.Load() != 6 {
						t.Fatalf("peer exchanges: DNS=%d echo=%d", queries.Load(), echoes.Load())
					}
				})
			}
		})
	}
}

// Decode actual outbound headers with the native VMess codec. This isolates
// command selection from host low-port filtering; it is not delivery evidence.
func TestVMessUDPCommandSelection(t *testing.T) {
	for _, disabled := range []string{"false", "true"} {
		t.Run("cone-disabled-"+disabled, func(t *testing.T) {
			t.Setenv("xray.cone.disabled", disabled)
			id := uuid.New()
			account := &vmess.Account{Id: id.String(), SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}}
			user, err := (&protocol.User{Account: serial.ToTypedMessage(account)}).ToMemoryUser()
			if err != nil {
				t.Fatal(err)
			}
			validator := vmess.NewTimedUserValidator()
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			history := vmessencoding.NewSessionHistory()
			t.Cleanup(func() { history.Close() })
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			type observed struct {
				header *protocol.RequestHeader
				err    error
			}
			headers := make(chan observed, 1)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					c.SetDeadline(time.Now().Add(time.Second))
					header, err := vmessencoding.NewServerSession(validator, history).DecodeRequestHeader(c, false)
					c.Close()
					headers <- observed{header, err}
				}
			}()
			t.Cleanup(func() { ln.Close(); <-stopped })
			v := instance(t)
			cfg := &core.OutboundHandlerConfig{Tag: "vmess-command", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: serial.ToTypedMessage(&vmessout.Config{Receiver: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(ln.Addr().(*net.TCPAddr).Port), User: &protocol.User{Account: serial.ToTypedMessage(account)}}})}
			if err := core.AddOutboundHandler(v, cfg); err != nil {
				t.Fatal(err)
			}
			for _, port := range []xnet.Port{53, 443, 12345} {
				for _, origin := range []session.TrafficOrigin{session.TrafficOriginUnknown, session.TrafficOriginUser, session.TrafficOriginControlledMeasurement} {
					for _, source := range []bool{false, true} {
						t.Run(fmt.Sprintf("port-%d/origin-%d/source-%t", port, origin, source), func(t *testing.T) {
							ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
							defer cancel()
							ctx = session.SetForcedOutboundTagToContext(ctx, "vmess-command")
							ctx = session.ContextWithTrafficOrigin(ctx, origin)
							if source {
								ctx = session.ContextWithUDPPacketSource(ctx)
							}
							dest := xnet.UDPDestination(xnet.LocalHostIP, port)
							c, err := core.Dial(ctx, v, dest)
							if err != nil {
								t.Fatal(err)
							}
							defer c.Close()
							if _, err := c.Write([]byte("command-witness")); err != nil {
								t.Fatal(err)
							}
							select {
							case got := <-headers:
								if got.err != nil {
									t.Fatal(got.err)
								}
								want := protocol.RequestCommandUDP
								if (disabled == "false" && port != 53 && port != 443) || (origin == session.TrafficOriginControlledMeasurement && source) {
									want = protocol.RequestCommandMux
								}
								// Mux headers omit the port on wire; 666 is a local codec selector.
								if got.header.Command != want || (want == protocol.RequestCommandUDP && got.header.Destination() != dest) || (want == protocol.RequestCommandMux && got.header.Address.Domain() != "v1.mux.cool") {
									t.Fatalf("VMess command: %+v want=%d", got.header, want)
								}
							case <-ctx.Done():
								t.Fatal("VMess header not observed")
							}
						})
					}
				}
			}
		})
	}
}

func TestVMessUDPCancellationAndOrdinaryContinuity(t *testing.T) {
	for _, disabled := range []string{"false", "true"} {
		t.Run("cone-disabled-"+disabled, func(t *testing.T) {
			t.Setenv("xray.cone.disabled", disabled)
			e, v, _ := plainProtocolExecutor(t, "vmess")
			testProtocolUDPCancellation(t, e, v)
		})
	}
}

// These fixture inbounds prohibit splice (CanSpliceCopy=3), so native response
// counters advance before forwarding replies. Freedom also has no inbound.Conn.
// Mixed-origin counters are route witnesses, never per-operation byte receipts.
func protocolPeerApps() []*serial.TypedMessage {
	return []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&stats.Config{}), serial.ToTypedMessage(&policy.Config{System: &policy.SystemPolicy{Stats: &policy.SystemPolicy_Stats{OutboundDownlink: true}}}),
	}
}

// Count actual native selection before endpoint work. Response-byte counters can
// publish after splice/EOF or cancellation and cannot witness one invocation.
type protocolDispatchWitness struct {
	outbound.Handler
	counter statsfeature.Counter
}

func (h *protocolDispatchWitness) Dispatch(ctx context.Context, link *transport.Link) {
	b7RememberOrdinary(ctx)
	if session.TrafficOriginFromContext(ctx) == session.TrafficOriginControlledMeasurement {
		h.counter.Add(1)
	}
	h.Handler.Dispatch(ctx, link)
}

func addProtocolOutbound(t *testing.T, v *core.Instance, config *core.OutboundHandlerConfig) statsfeature.Counter {
	t.Helper()
	counter, err := v.GetFeature(statsfeature.ManagerType()).(statsfeature.Manager).GetOrRegisterCounter("fixture>>>" + config.Tag + ">>>dispatches")
	if err != nil {
		t.Fatal(err)
	}
	object, err := core.CreateObject(v, config)
	if err != nil {
		t.Fatal(err)
	}
	handler := object.(outbound.Handler)
	if err := v.GetFeature(outbound.ManagerType()).(outbound.Manager).AddHandler(context.Background(), &protocolDispatchWitness{Handler: handler, counter: counter}); err != nil {
		t.Fatal(err)
	}
	return counter
}

func TestFreedomProtocolMeasurements(t *testing.T) {
	v := instance(t)
	var counters [2]statsfeature.Counter
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	for i, tag := range []string{"exact", "second"} {
		c := config(tag, false)
		counters[i] = addProtocolOutbound(t, v, c)
	}
	e := executor(t, v)
	testProtocolMeasurements(t, e, v, counters)
	testProtocolPacketBoundary(t, e, "", 8192, true)
}

func testProtocolMeasurements(t *testing.T, e *measurement.Executor, v *core.Instance, counters [2]statsfeature.Counter, tcpOnly ...bool) {
	t.Helper()
	exactUDP := len(tcpOnly) == 0 || !tcpOnly[0]
	testProtocolMeasurementsAt(t, e, v, counters, "", exactUDP)
}

// WireGuard's gVisor peer uses a non-loopback inner target and native Freedom
// redirects it to the local fixtures. DIRECT always keeps the real host address.
func protocolFixtureURL(endpoint string, route measurement.Route, tunnelHost string) string {
	if tunnelHost == "" || route.Kind == measurement.Direct {
		return endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	u.Host = net.JoinHostPort(tunnelHost, u.Port())
	return u.String()
}

func protocolFixtureDestination(endpoint netip.AddrPort, route measurement.Route, tunnelHost string) netip.AddrPort {
	if tunnelHost != "" && route.Kind == measurement.ExactOutbound {
		return netip.AddrPortFrom(netip.MustParseAddr(tunnelHost), endpoint.Port())
	}
	return endpoint
}

func testProtocolMeasurementsAt(t *testing.T, e *measurement.Executor, v *core.Instance, counters [2]statsfeature.Counter, tunnelHost string, exactUDP bool) {
	t.Helper()
	if v != nil {
		testProtocolWorkingNode(t, e, v, tunnelHost, exactUDP)
	}
	if b7Enabled {
		return
	}
	if carrierDials != nil {
		return
	}
	for _, tag := range []string{"exact", "second"} {
		if v == nil {
			break
		}
		if v.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler(tag) == nil {
			t.Fatalf("required fixture tag %s is missing", tag)
		}
	}
	if v != nil {
		testProtocolRawMethodsAt(t, e, counters, "127.0.0.1", false, exactUDP, tunnelHost)
	}
	t.Run("finite-series", func(t *testing.T) {
		secondWritten := make(chan struct{})
		cancelEntered := make(chan int, 3)
		var seriesCalls atomic.Int32
		s := directHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seriesCalls.Add(1)
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			w.Header().Set("X-Peer", host)
			switch r.URL.Path {
			case "/canceled":
				index := r.URL.Query().Get("index")
				w.Header().Set("X-Attempt", index)
				w.Header().Set("Content-Length", "100")
				_, _ = io.WriteString(w, "canceled-"+index)
				w.(http.Flusher).Flush()
				cancelEntered <- 1
				<-r.Context().Done()
			case "/attempt":
				index := r.URL.Query().Get("index")
				if index == "0" {
					select {
					case <-secondWritten:
					case <-r.Context().Done():
						return
					}
				}
				w.Header().Set("X-Attempt", index)
				if index == "1" {
					w.Header().Set("Content-Length", "100")
				}
				_, _ = io.WriteString(w, "attempt-"+index)
				if index == "2" {
					w.(http.Flusher).Flush()
					close(secondWritten)
				}
			default:
				_, _ = io.WriteString(w, "fixture")
			}
		}), "127.0.0.1", true, tunnelHost)
		defer s.Close()
		defer s.CloseClientConnections()
		samples, err := measurement.RunSeries(context.Background(), e, 6, 3, func(ctx context.Context, index int) (measurement.HTTPSReceipt, error) {
			r := request(s, measurement.ExactOutbound)
			r.URL += fmt.Sprintf("/attempt?index=%d", index)
			if index%3 == 1 {
				r.Route.Tag = "second"
			} else if index%3 == 2 {
				r.Route = measurement.Route{Kind: measurement.Direct}
			}
			if v == nil {
				r.Route = measurement.Route{Kind: measurement.Direct}
			}
			r.URL = protocolFixtureURL(r.URL, r.Route, tunnelHost)
			return e.HTTPS(ctx, r)
		})
		if err != nil || len(samples) != 6 || seriesCalls.Load() != 6 {
			t.Fatalf("series: %d, %v", len(samples), err)
		}
		for index, sample := range samples {
			want := fmt.Sprintf("attempt-%d", index)
			validError := sample.Err == nil
			if index == 1 {
				validError = errors.Is(sample.Err, io.ErrUnexpectedEOF)
			}
			wantPeer := "127.0.0.1"
			if !validError || sample.Index != index || string(sample.Receipt.Body) != want || sample.Receipt.Header.Get("X-Attempt") != fmt.Sprint(index) || sample.Receipt.Header.Get("X-Peer") != wantPeer || sample.Receipt.BodyBytes != int64(len(want)) || sample.Receipt.StatusCode != 200 || sample.Receipt.BodyComplete != (index != 1) || sample.Receipt.Elapsed < 0 || sample.Receipt.FirstByteElapsed == nil || *sample.Receipt.FirstByteElapsed > sample.Receipt.Elapsed {
				t.Fatalf("sample: %+v", sample)
			}
		}
		t.Run("series-cancellation", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				samples []measurement.Sample[measurement.HTTPSReceipt]
				err     error
			}
			returned := make(chan result, 1)
			go func() {
				samples, err := measurement.RunSeries(ctx, e, 3, 3, func(ctx context.Context, index int) (measurement.HTTPSReceipt, error) {
					r := request(s, measurement.ExactOutbound)
					r.URL += fmt.Sprintf("/canceled?index=%d", index)
					if index == 1 {
						r.Route.Tag = "second"
					} else if index == 2 {
						r.Route = measurement.Route{Kind: measurement.Direct}
					}
					if v == nil {
						r.Route = measurement.Route{Kind: measurement.Direct}
					}
					r.URL = protocolFixtureURL(r.URL, r.Route, tunnelHost)
					return e.HTTPS(ctx, r)
				})
				returned <- result{samples, err}
			}()
			for range 3 {
				select {
				case <-cancelEntered:
				case <-time.After(3 * time.Second):
					cancel()
					<-returned
					t.Fatal("parallel series did not reach all peers")
				}
			}
			cancel()
			select {
			case got := <-returned:
				if !errors.Is(got.err, context.Canceled) || len(got.samples) != 3 {
					t.Fatalf("canceled series: %+v", got)
				}
				for index, sample := range got.samples {
					r := sample.Receipt
					want := "canceled-" + fmt.Sprint(index)
					// Cancellation can precede HTTP header/body handoff. Absent raw
					// facts remain absent; any observed prefix must belong to this attempt.
					if sample.Index != index || !errors.Is(sample.Err, context.Canceled) || r.BodyComplete || r.BodyBytes != int64(len(r.Body)) || !bytes.HasPrefix([]byte(want), r.Body) || (r.Header != nil && (r.Header.Get("X-Attempt") != fmt.Sprint(index) || r.Header.Get("X-Peer") != "127.0.0.1")) {
						t.Fatalf("canceled attempt facts: %+v", sample)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled series did not join")
			}
		})
		t.Run("missing-tag-no-fallback", func(t *testing.T) {
			before := seriesCalls.Load()
			r := request(s, measurement.ExactOutbound)
			r.Route.Tag = "missing-c1-tag"
			r.URL = protocolFixtureURL(r.URL, r.Route, tunnelHost)
			if got, err := e.HTTPS(context.Background(), r); err == nil || got.StatusCode != 0 || got.BodyComplete || len(got.Body) != 0 {
				t.Fatalf("missing tag receipt: %+v, %v", got, err)
			}
			if seriesCalls.Load() != before {
				t.Fatal("missing tag reached peer through fallback")
			}
		})
		if !exactUDP {
			v = nil // The protocol's UDP rejection is exercised in the raw-method suite.
		}
		testProtocolUDPCancellation(t, e, v, tunnelHost)
	})
}

func testProtocolUDPCancellation(t *testing.T, e *measurement.Executor, v *core.Instance, tunnelHosts ...string) {
	t.Helper()
	tunnelHost := ""
	if len(tunnelHosts) != 0 {
		tunnelHost = tunnelHosts[0]
	}
	pc := udpFixture(t, func(pc net.PacketConn, b []byte, addr net.Addr) { _, _ = pc.WriteTo(b, addr) })
	// Retain an ordinary packet session across a canceled Measurement train.
	ordinaryCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	ordinaryCtx = session.SetForcedOutboundTagToContext(ordinaryCtx, "exact")
	dest, _ := xnet.ParseDestination("udp:" + pc.LocalAddr().String())
	if v != nil && tunnelHost != "" {
		dest.Address = xnet.ParseAddress(tunnelHost)
	}
	var ordinary net.Conn
	var err error
	kind := measurement.ExactOutbound
	if v == nil {
		kind = measurement.Direct
		ordinary, err = net.Dial("udp", pc.LocalAddr().String())
	} else {
		ordinary, err = core.Dial(ordinaryCtx, v, dest)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	ordinaryEcho := func() {
		t.Helper()
		if _, err := ordinary.Write([]byte("ordinary")); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var b [32]byte
			n, err := ordinary.Read(b[:])
			if string(b[:n]) != "ordinary" {
				err = errors.Join(err, errors.New("ordinary packet mismatch"))
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			ordinary.Close()
			<-done
			t.Fatal("ordinary packet session stalled")
		}
	}
	ordinaryEcho() // Prove a live warm session exists before cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan []byte, 1)
	blocked := udpFixture(t, func(_ net.PacketConn, packet []byte, _ net.Addr) {
		select {
		case seen <- packet:
		default:
		}
	})
	r := udpRequest(blocked.LocalAddr(), kind)
	r.Destination = protocolFixtureDestination(r.Destination, r.Route, tunnelHost)
	r.Count, r.Interval, r.ReplyWait = 100, time.Millisecond, time.Second
	type udpResult struct {
		receipt measurement.UDPEchoReceipt
		err     error
	}
	returned := make(chan udpResult, 1)
	go func() { got, err := e.UDPEcho(ctx, r); returned <- udpResult{got, err} }()
	var packet []byte
	select {
	case packet = <-seen:
	case <-time.After(2 * time.Second):
		cancel()
		<-returned
		t.Fatal("Measurement datagram did not reach endpoint")
	}
	ordinaryEcho() // The same warm session also exchanges while Measurement is active.
	cancel()
	select {
	case got := <-returned:
		if !errors.Is(got.err, context.Canceled) || got.receipt.Elapsed < 0 || got.receipt.WindowComplete || len(got.receipt.Replies) != 0 || len(got.receipt.Sends) == 0 || len(got.receipt.Sends) > r.Count || len(packet) < 24 || !bytes.Equal(got.receipt.Nonce[:], packet[4:20]) {
			t.Fatalf("canceled train facts: %+v, %v", got.receipt, got.err)
		}
		for i, sent := range got.receipt.Sends {
			if sent.Sequence != uint32(i) || sent.WriteReturned == nil {
				t.Fatalf("canceled write facts: %+v", sent)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Measurement UDP cancel stalled")
	}
	ordinaryEcho()
	retry := udpRequest(pc.LocalAddr(), kind)
	retry.Destination = protocolFixtureDestination(retry.Destination, retry.Route, tunnelHost)
	got, err := e.UDPEcho(context.Background(), retry)
	if err != nil || len(got.Replies) != 3 || !got.WindowComplete {
		t.Fatalf("post-cancel train: %+v, %v", got, err)
	}
	for _, reply := range got.Replies {
		if reply.Issue != measurement.UDPReplyValid {
			t.Fatalf("reply: %+v", reply)
		}
	}
}

// This external-package caller consumes public Go receipts directly. Each case
// selects one operation; reading embedded facts and pure identity parsing adds no I/O.
func testProtocolRawMethods(t *testing.T, e *measurement.Executor, counters [2]statsfeature.Counter, directHost ...string) {
	t.Helper()
	host := "127.0.0.1"
	if len(directHost) != 0 {
		host = directHost[0]
	}
	testProtocolRawMethodsAt(t, e, counters, host, len(directHost) != 0, true)
}

func testProtocolRawMethodsAt(t *testing.T, e *measurement.Executor, counters [2]statsfeature.Counter, host string, directOnly, exactUDP bool, tunnelHosts ...string) {
	t.Helper()
	tunnelHost := ""
	if len(tunnelHosts) != 0 {
		tunnelHost = tunnelHosts[0]
	}
	routes := []measurement.Route{{Kind: measurement.ExactOutbound, Tag: "exact"}, {Kind: measurement.ExactOutbound, Tag: "second"}, {Kind: measurement.Direct}}
	if directOnly {
		routes = []measurement.Route{{Kind: measurement.Direct}}
	}
	for i, route := range routes {
		name := route.Tag
		if route.Kind == measurement.Direct {
			name = "direct"
		}
		t.Run(name, func(t *testing.T) {
			wantSource := host
			witness := func() [2]int64 {
				if counters[0] == nil && counters[1] == nil {
					return [2]int64{}
				}
				return [2]int64{counters[0].Value(), counters[1].Value()}
			}
			checkRoute := func(t *testing.T, before [2]int64) {
				t.Helper()
				for peer, counter := range counters {
					if counter == nil {
						continue
					}
					delta := counter.Value() - before[peer]
					want := int64(0)
					if peer == i {
						want = 1
					}
					if delta != want {
						t.Errorf("route %s handler %d dispatch count=%d want=%d", name, peer, delta, want)
					}
				}
			}
			checkSource := func(addr string) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil || host != wantSource {
					t.Errorf("peer-observed route: source=%s want=%s error=%v", addr, wantSource, err)
				}
			}
			var calls atomic.Int32
			payload := make([]byte, 128<<10+7)
			for j := range payload {
				payload[j] = byte(j)
			}
			digest := sha256.Sum256(payload)
			handle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				checkSource(r.RemoteAddr)
				w.Header().Set("X-Peer", wantSource)
				switch r.URL.Path {
				case "/upload", "/upload-raw", "/upload-bad", "/upload-malformed":
					if r.Method != http.MethodPost {
						t.Error("upload method")
					}
					var observed bytes.Buffer
					r.Body = io.NopCloser(io.TeeReader(r.Body, &observed))
					if r.URL.Path == "/upload" {
						acknowledge(w, r)
					} else {
						_, _ = io.Copy(io.Discard, r.Body)
						if r.URL.Path == "/upload-raw" {
							_, _ = io.WriteString(w, "raw")
						} else if r.URL.Path == "/upload-malformed" {
							_, _ = io.WriteString(w, "{")
						} else {
							_ = json.NewEncoder(w).Encode(map[string]any{"nonce": "wrong", "bytes": len(payload), "sha256": hex.EncodeToString(digest[:])})
						}
					}
					if !bytes.Equal(observed.Bytes(), payload) {
						t.Errorf("peer upload payload: got %d bytes", observed.Len())
					}
				case "/download":
					if r.Method != http.MethodGet {
						t.Error("download method")
					}
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					_, _ = w.Write(payload)
				case "/partial":
					w.Header().Set("Content-Length", "100")
					_, _ = io.WriteString(w, "prefix")
				case "/identity":
					if r.Method != http.MethodGet {
						t.Error("identity method")
					}
					_ = json.NewEncoder(w).Encode(reflectorBody("192.0.2.1"))
				case "/identity-malformed":
					_, _ = io.WriteString(w, "{")
				case "/dns-query", "/dns-bad":
					q, err := io.ReadAll(r.Body)
					if err != nil || r.Method != http.MethodPost || r.Header.Get("Accept") != "application/dns-message" || r.Header.Get("Content-Type") != "application/dns-message" {
						t.Errorf("DoH request: %v", err)
					}
					checkProtocolDNSQuestion(t, q)
					w.Header().Set("Content-Type", "application/dns-message")
					if r.URL.Path == "/dns-bad" {
						_, _ = w.Write([]byte("invalid"))
					} else {
						_, _ = w.Write(dnsReply(q))
					}
				default:
					if r.Method != http.MethodHead && r.Method != http.MethodGet {
						t.Errorf("probe method %s", r.Method)
					}
					_, _ = io.WriteString(w, "fixture")
				}
			})
			s := directHTTPFixture(t, handle, host, true, tunnelHost)
			defer s.Close()
			plain := directHTTPFixture(t, handle, host, false)
			defer plain.Close()
			base := request(s, route.Kind)
			base.Route = route
			base.URL = protocolFixtureURL(base.URL, route, tunnelHost)
			// Include REALITY's native initial five-second record-detection wait.
			// This is an explicit fixture budget, not a Measurement runtime default.
			base.Timeout = 10 * time.Second
			// Every HTTP-based operation must cause exactly one peer request,
			// including failed validation and streaming, with no retry or extra probe.
			one := func(name string, run func(*testing.T)) {
				t.Run(name, func(t *testing.T) {
					before := calls.Load()
					beforeRoute := witness()
					run(t)
					checkRoute(t, beforeRoute)
					if delta := calls.Load() - before; delta != 1 {
						t.Fatalf("peer requests=%d want=1", delta)
					}
				})
			}
			checkHTTP := func(t *testing.T, r measurement.HTTPSReceipt, err error, body string, tls bool) {
				t.Helper()
				if err != nil || r.StatusCode != 200 || r.Header.Get("X-Peer") != wantSource || !r.BodyComplete || string(r.Body) != body || r.BodyBytes != int64(len(body)) || r.Elapsed < 0 || r.FirstByteElapsed == nil || *r.FirstByteElapsed > r.Elapsed || (r.EndpointTLS != nil) != tls {
					t.Fatalf("HTTP raw facts: %+v, %v", r, err)
				}
			}
			for _, secure := range []bool{false, true} {
				for _, method := range []string{http.MethodHead, http.MethodGet} {
					one(fmt.Sprintf("HTTP/%t/%s", secure, method), func(t *testing.T) {
						r := measurement.HTTPRequest(base)
						if !secure {
							r.URL = protocolFixtureURL(plain.URL, route, tunnelHost)
						}
						body := "fixture"
						if method == http.MethodHead {
							r.MaxBodyBytes = 0
							body = ""
						}
						got, err := e.HTTP(context.Background(), method, r)
						checkHTTP(t, got, err, body, secure)
					})
				}
			}
			one("HTTPS/identity-reuse", func(t *testing.T) {
				r := base
				r.URL += "/identity"
				got, err := e.HTTPS(context.Background(), r)
				checkHTTP(t, got, err, string(got.Body), true)
				identity, err := measurement.IdentityFromHTTPS(got, measurement.IPv4)
				if err != nil || identity.Address.String() != "192.0.2.1" || identity.Family != measurement.IPv4 || identity.HTTPS.Elapsed != got.Elapsed || !bytes.Equal(identity.HTTPS.Body, got.Body) {
					t.Fatalf("reused identity: %+v, %v", identity, err)
				}
			})
			for _, path := range []string{"/identity", "/identity-malformed", "/identity-wrong-family"} {
				one("EgressIdentity"+path, func(t *testing.T) {
					r := measurement.IdentityRequest{HTTPS: base, Family: measurement.IPv4}
					if path == "/identity-wrong-family" {
						r.HTTPS.URL += "/identity"
						r.Family = measurement.IPv6
					} else {
						r.HTTPS.URL += path
					}
					got, err := e.EgressIdentity(context.Background(), r)
					if path == "/identity" {
						if err != nil || got.Address.String() != "192.0.2.1" {
							t.Fatalf("identity: %+v, %v", got, err)
						}
					} else if !errors.Is(err, measurement.ErrIdentityResponse) || got.Address.IsValid() {
						t.Fatalf("invalid identity: %+v, %v", got, err)
					}
					checkHTTP(t, got.HTTPS, nil, string(got.HTTPS.Body), true)
				})
			}
			for _, hash := range []bool{false, true} {
				one(fmt.Sprintf("Download/hash-%t", hash), func(t *testing.T) {
					r := downloadRequest(s, route.Kind)
					r.HTTPS.Route = route
					r.HTTPS.URL = protocolFixtureURL(r.HTTPS.URL, route, tunnelHost)
					r.HTTPS.URL += "/download"
					if hash {
						r.ExpectedSHA256 = &digest
					}
					got, err := e.Download(context.Background(), r)
					if err != nil || got.PayloadBytes != int64(len(payload)) || got.DeclaredLength == nil || *got.DeclaredLength != int64(len(payload)) || got.ActiveElapsed == nil || got.IntegrityVerified != hash || (got.SHA256 != nil) != hash {
						t.Fatalf("download facts: %+v, %v", got, err)
					}
					if hash && *got.SHA256 != digest {
						t.Fatal("download digest")
					}
					checkHTTP(t, got.HTTPS, nil, "", true) // Stream bytes remain in PayloadBytes, never HTTPS.Body.
				})
			}
			one("Download/partial", func(t *testing.T) {
				r := downloadRequest(s, route.Kind)
				r.HTTPS.Route = route
				r.HTTPS.URL = protocolFixtureURL(r.HTTPS.URL, route, tunnelHost)
				r.HTTPS.URL += "/partial"
				got, err := e.Download(context.Background(), r)
				if !errors.Is(err, io.ErrUnexpectedEOF) || got.PayloadBytes != 6 || got.HTTPS.BodyComplete || got.HTTPS.StatusCode != 200 || got.HTTPS.Header.Get("X-Peer") != wantSource || got.ActiveElapsed == nil {
					t.Fatalf("partial download: %+v, %v", got, err)
				}
			})
			for _, path := range []string{"/upload", "/upload-raw", "/upload-bad", "/upload-malformed"} {
				one("Upload"+path, func(t *testing.T) {
					r := uploadRequest(s, route.Kind)
					r.HTTPS.Route = route
					r.HTTPS.URL = protocolFixtureURL(r.HTTPS.URL, route, tunnelHost)
					r.HTTPS.URL += path
					r.RequireAcknowledgment = path != "/upload-raw"
					got, err := e.Upload(context.Background(), r)
					if got.GeneratedBytes != r.PayloadBytes || got.WriterAcceptedBytes != r.PayloadBytes || got.ActiveElapsed == nil {
						t.Fatalf("upload counts: %+v, %v", got, err)
					}
					if path == "/upload-bad" || path == "/upload-malformed" {
						if !errors.Is(err, measurement.ErrUploadACK) || got.Acknowledgment != nil {
							t.Fatalf("invalid ACK: %+v, %v", got, err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
					if path == "/upload" && (got.Acknowledgment == nil || got.Acknowledgment.Bytes != r.PayloadBytes || got.Acknowledgment.SHA256 != digest) {
						t.Fatalf("ACK: %+v", got)
					}
					if path == "/upload-raw" && (got.Acknowledgment != nil || got.WriterAcceptedSHA256 != nil || got.Nonce != "") {
						t.Fatalf("optional ACK work: %+v", got)
					}
					checkHTTP(t, got.HTTPS, nil, string(got.HTTPS.Body), true)
				})
			}
			for _, transport := range []measurement.DNSTransport{measurement.DNSUDP, measurement.DNSTCP, measurement.DNSDoT, measurement.DNSDoH} {
				t.Run(fmt.Sprintf("DNS/%d", transport), func(t *testing.T) {
					var addr net.Addr
					var queries atomic.Int32
					if transport == measurement.DNSUDP {
						addr = udpFixtureAt(t, net.JoinHostPort(host, "0"), func(pc net.PacketConn, q []byte, a net.Addr) {
							checkSource(a.String())
							checkProtocolDNSQuestion(t, q)
							queries.Add(1)
							_, _ = pc.WriteTo(dnsReply(q), a)
						}).LocalAddr()
					} else if transport == measurement.DNSDoH {
						addr = s.Listener.Addr()
					} else {
						cfg := s.TLS.Clone()
						if transport == measurement.DNSTCP {
							cfg = nil
						}
						addr = dnsStreamFixture(t, cfg, func(c net.Conn, q []byte) {
							checkSource(c.RemoteAddr().String())
							checkProtocolDNSQuestion(t, q)
							queries.Add(1)
							dnsFrame(c, dnsReply(q))
						}, host)
					}
					r := dnsRequest(addr, transport, route.Kind)
					r.Route = route
					r.Resolver = protocolFixtureDestination(r.Resolver, route, tunnelHost)
					pool := x509.NewCertPool()
					pool.AddCert(s.Certificate())
					r.ServerName, r.RootCAs, r.DoHPath, r.MaxHeaderBytes = "example.com", pool, "/dns-query", 4096
					before := calls.Load()
					beforeRoute := witness()
					got, err := e.DNSQuery(context.Background(), r)
					checkRoute(t, beforeRoute)
					if transport == measurement.DNSUDP && route.Kind == measurement.ExactOutbound && !exactUDP {
						if err == nil || got.Message != nil || got.ResponseComplete || queries.Load() != 0 {
							t.Fatalf("TCP-only DNS/UDP rejection: %+v, %v queries=%d", got, err, queries.Load())
						}
						return
					}
					if err != nil || !got.ResponseComplete || got.Message == nil || len(got.Message.Answer) != 1 || len(got.Wire) < 12 || got.Elapsed < 0 {
						t.Fatalf("DNS raw facts: %+v, %v", got, err)
					}
					answer, ok := got.Message.Answer[0].(*dns.A)
					if !ok || answer.A.String() != "192.0.2.1" || got.Message.Id != got.QueryID || got.Message.Question[0].Name != r.Name {
						t.Fatalf("DNS answer association: %+v", got)
					}
					if transport == measurement.DNSDoH {
						if got.HTTPStatus != 200 || got.HTTPContentType != "application/dns-message" || got.EndpointTLS == nil || got.WrittenBytes != nil || calls.Load()-before != 1 {
							t.Fatalf("DoH reused HTTP facts: %+v requests=%d", got, calls.Load()-before)
						}
						r.DoHPath = "/dns-bad"
						beforeRoute = witness()
						bad, err := e.DNSQuery(context.Background(), r)
						checkRoute(t, beforeRoute)
						if !errors.Is(err, measurement.ErrDNSResponse) || bad.Message != nil || !bad.ResponseComplete || string(bad.Wire) != "invalid" || bad.HTTPStatus != 200 || bad.HTTPContentType != "application/dns-message" || bad.EndpointTLS == nil || calls.Load()-before != 2 {
							t.Fatalf("DoH error facts: %+v, %v", bad, err)
						}
					} else if queries.Load() != 1 || got.WrittenBytes == nil || *got.WrittenBytes < 12 || (got.EndpointTLS != nil) != (transport == measurement.DNSDoT) {
						t.Fatalf("DNS exchange counts: %+v queries=%d", got, queries.Load())
					}
				})
			}
			t.Run("UDPEcho", func(t *testing.T) {
				var packets atomic.Int32
				pc := udpFixtureAt(t, net.JoinHostPort(host, "0"), func(pc net.PacketConn, b []byte, a net.Addr) {
					checkSource(a.String())
					packets.Add(1)
					_, _ = pc.WriteTo(b, a)
				})
				r := udpRequest(pc.LocalAddr(), route.Kind)
				r.Route = route
				r.Destination = protocolFixtureDestination(r.Destination, route, tunnelHost)
				beforeRoute := witness()
				got, err := e.UDPEcho(context.Background(), r)
				checkRoute(t, beforeRoute)
				if route.Kind == measurement.ExactOutbound && !exactUDP {
					if err == nil || got.WindowComplete || len(got.Replies) != 0 || packets.Load() != 0 {
						t.Fatalf("TCP-only echo rejection: %+v, %v packets=%d", got, err, packets.Load())
					}
					return
				}
				if err != nil || !got.WindowComplete || len(got.Sends) != r.Count || len(got.Replies) != r.Count || packets.Load() != int32(r.Count) {
					t.Fatalf("UDP raw train: %+v, %v packets=%d", got, err, packets.Load())
				}
				for index, sent := range got.Sends {
					if sent.Sequence != uint32(index) || sent.WriterBytes != r.PacketBytes || sent.WriteReturned == nil || sent.Error != nil {
						t.Fatalf("send: %+v", sent)
					}
				}
				for _, reply := range got.Replies {
					if reply.Issue != measurement.UDPReplyValid || reply.Source != r.Destination || reply.Bytes != r.PacketBytes || reply.RoundTrip == nil || reply.Sequence == nil || reply.Duplicate {
						t.Fatalf("reply: %+v", reply)
					}
				}
			})
			testProtocolTransferFailures(t, e, route, host, tunnelHost)
			testProtocolDNSFailures(t, e, route, host, tunnelHost, exactUDP, s)
		})
	}
}

func testProtocolDNSFailures(t *testing.T, e *measurement.Executor, route measurement.Route, host, tunnelHost string, exactUDP bool, tlsPeer *httptest.Server) {
	t.Helper()
	for _, transport := range []measurement.DNSTransport{measurement.DNSUDP, measurement.DNSTCP, measurement.DNSDoT, measurement.DNSDoH} {
		if transport == measurement.DNSUDP && !exactUDP && route.Kind == measurement.ExactOutbound {
			continue // The native HTTP CONNECT rejection is tested above.
		}
		for _, canceled := range []bool{false, true} {
			if transport == measurement.DNSDoH && !canceled {
				continue // The existing DoH malformed-response case already covers it.
			}
			t.Run(fmt.Sprintf("DNS/%d/failure-cancel-%t", transport, canceled), func(t *testing.T) {
				entered := make(chan struct{})
				release := make(chan struct{})
				var queries atomic.Int32
				observe := func(q []byte) {
					checkProtocolDNSQuestion(t, q)
					queries.Add(1)
					if canceled {
						close(entered)
					}
				}
				var address net.Addr
				pool := x509.NewCertPool()
				pool.AddCert(tlsPeer.Certificate())
				if transport == measurement.DNSUDP {
					pc := udpFixtureAt(t, net.JoinHostPort(host, "0"), func(pc net.PacketConn, q []byte, source net.Addr) {
						observe(q)
						if !canceled {
							_, _ = pc.WriteTo([]byte("invalid"), source)
						}
					})
					address = pc.LocalAddr()
				} else if transport == measurement.DNSDoH {
					s := directHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						q, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						observe(q)
						select {
						case <-r.Context().Done():
						case <-release:
						}
					}), host, true, tunnelHost)
					defer s.Close()
					address = s.Listener.Addr()
					pool = x509.NewCertPool()
					pool.AddCert(s.Certificate())
				} else {
					config := tlsPeer.TLS.Clone()
					if transport == measurement.DNSTCP {
						config = nil
					}
					address = dnsStreamFixture(t, config, func(c net.Conn, q []byte) {
						observe(q)
						if canceled {
							<-release
						} else {
							dnsFrame(c, []byte("invalid"))
						}
					}, host)
				}
				defer close(release)
				r := dnsRequest(address, transport, route.Kind)
				r.Route = route
				r.Resolver = protocolFixtureDestination(r.Resolver, route, tunnelHost)
				r.ServerName, r.RootCAs, r.DoHPath, r.MaxHeaderBytes = "example.com", pool, "/dns-query", 4096
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var receipt measurement.DNSReceipt
				var resultErr error
				done := make(chan struct{})
				go func() { defer close(done); receipt, resultErr = e.DNSQuery(ctx, r) }()
				if canceled {
					select {
					case <-entered:
					case <-done:
						t.Fatalf("DNS ended before active cancellation: %v", resultErr)
					case <-time.After(3 * time.Second):
						cancel()
						<-done
						t.Fatal("DNS did not reach peer")
					}
					cancel()
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					cancel()
					<-done
					t.Fatal("DNS failure did not return")
				}
				wantError := measurement.ErrDNSResponse
				if canceled {
					wantError = context.Canceled
				}
				if !errors.Is(resultErr, wantError) || receipt.Message != nil || queries.Load() != 1 || (canceled && receipt.ResponseComplete) {
					t.Fatalf("DNS failure facts: %+v, %v peer queries=%d", receipt, resultErr, queries.Load())
				}
			})
		}
	}
}

func testProtocolTransferFailures(t *testing.T, e *measurement.Executor, route measurement.Route, host, tunnelHost string) {
	t.Helper()
	for _, operation := range []string{"download", "upload"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/interrupted-cancel-%t", operation, canceled), func(t *testing.T) {
				entered := make(chan struct{})
				release := make(chan struct{})
				var calls atomic.Int32
				var peerBytes atomic.Int64
				s := directHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if operation == "upload" {
						n, err := io.CopyN(io.Discard, r.Body, 4096)
						peerBytes.Store(n)
						if err != nil {
							t.Errorf("peer upload prefix: %v", err)
						}
						if !canceled {
							conn, _, err := w.(http.Hijacker).Hijack()
							if err != nil {
								t.Error(err)
								return
							}
							_ = conn.Close()
							return
						}
					} else {
						w.Header().Set("Content-Length", "100")
						_, _ = io.WriteString(w, "prefix")
						w.(http.Flusher).Flush()
					}
					if canceled {
						close(entered)
						select {
						case <-r.Context().Done():
						case <-release:
						}
					}
				}), host, true, tunnelHost)
				defer s.Close()
				defer close(release)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan struct{})
				var download measurement.DownloadReceipt
				var upload measurement.UploadReceipt
				var resultErr error
				go func() {
					defer close(done)
					if operation == "download" {
						r := downloadRequest(s, route.Kind)
						r.HTTPS.Route = route
						r.HTTPS.URL = protocolFixtureURL(r.HTTPS.URL, route, tunnelHost)
						r.TransferTimeout = 3 * time.Second
						download, resultErr = e.Download(ctx, r)
					} else {
						r := uploadRequest(s, route.Kind)
						r.HTTPS.Route = route
						r.HTTPS.URL = protocolFixtureURL(r.HTTPS.URL, route, tunnelHost)
						r.PayloadBytes, r.TransferTimeout = 32<<20, 3*time.Second
						upload, resultErr = e.Upload(ctx, r)
					}
				}()
				if canceled {
					select {
					case <-entered:
					case <-done:
						t.Fatalf("operation ended before active cancellation: %v", resultErr)
					case <-time.After(4 * time.Second):
						cancel()
						<-done
						t.Fatal("operation did not reach peer")
					}
					cancel()
				}
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					cancel()
					<-done
					t.Fatal("interrupted transfer did not return")
				}
				if resultErr == nil || (canceled && !errors.Is(resultErr, context.Canceled)) || calls.Load() != 1 {
					t.Fatalf("interrupted transfer error=%v peer requests=%d", resultErr, calls.Load())
				}
				if operation == "download" {
					if download.HTTPS.BodyComplete || download.PayloadBytes < 0 || download.PayloadBytes > 6 || (!canceled && (!errors.Is(resultErr, io.ErrUnexpectedEOF) || download.PayloadBytes != 6)) {
						t.Fatalf("partial download facts: %+v, %v", download, resultErr)
					}
				} else if peerBytes.Load() != 4096 || upload.WriterAcceptedBytes <= 0 || upload.WriterAcceptedBytes > upload.GeneratedBytes || upload.GeneratedBytes > 32<<20 || upload.Acknowledgment != nil || upload.HTTPS.BodyComplete {
					t.Fatalf("partial upload facts: %+v, %v peer prefix=%d", upload, resultErr, peerBytes.Load())
				}
			})
		}
	}
}

func checkProtocolDNSQuestion(t *testing.T, wire []byte) {
	t.Helper()
	q := new(dns.Msg)
	if err := q.Unpack(wire); err != nil || len(q.Question) != 1 || q.Question[0].Name != "fixture.invalid." || q.Question[0].Qtype != dns.TypeA || !q.RecursionDesired {
		t.Errorf("peer DNS question: %+v, %v", q, err)
	}
}
