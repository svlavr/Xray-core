package measurement_test

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	hyproxy "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	vmessout "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// Installed once before constructing any instance, in a dedicated subprocess.
// Return the original connection so native concrete types and fast paths survive.
var carrierDials *carrierDialWitness

type carrierDialWitness struct {
	native     internet.DefaultSystemDialer
	mu         sync.Mutex
	scope      uint64
	sockets    map[string][]carrierDialRecord
	muxSockets map[string][]carrierDialRecord
	uploads    map[string]map[string]int
}

type carrierDialRecord struct {
	scope  uint64
	source string
}

// Delimit the fixture before its first cold operation. Capture scope at dial
// entry so a previous fixture's delayed completion cannot enter the new scope.
func (w *carrierDialWitness) beginScope() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.scope++
	return w.scope
}

func (w *carrierDialWitness) Dial(ctx context.Context, source xnet.Address, dest xnet.Destination, options *internet.SocketConfig) (xnet.Conn, error) {
	w.mu.Lock()
	scope := w.scope
	w.mu.Unlock()
	c, err := w.native.Dial(ctx, source, dest, options)
	if err == nil && c != nil {
		w.mu.Lock()
		record := carrierDialRecord{scope: scope, source: c.LocalAddr().String()}
		w.sockets[dest.String()] = append(w.sockets[dest.String()], record)
		if obs := session.OutboundsFromContext(ctx); len(obs) > 0 && obs[len(obs)-1].Target.Address != nil && obs[len(obs)-1].Target.Address.Family().IsDomain() && obs[len(obs)-1].Target.Address.Domain() == "v1.mux.cool" {
			w.muxSockets[dest.String()] = append(w.muxSockets[dest.String()], record)
		}
		w.mu.Unlock()
	}
	return c, err
}

func (*carrierDialWitness) DestIpAddress() xnet.IP { return nil }

func (w *carrierDialWitness) scopedSockets(dest string, scope uint64) ([]string, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	sources := func(records []carrierDialRecord) []string {
		var result []string
		for _, record := range records {
			if record.scope == scope {
				result = append(result, record.source)
			}
		}
		return result
	}
	return sources(w.sockets[dest]), sources(w.muxSockets[dest])
}

func (w *carrierDialWitness) check(t *testing.T, v *core.Instance, scope uint64) {
	t.Helper()
	for _, tag := range []string{"exact", "second"} {
		h := v.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler(tag)
		config, err := h.ProxySettings().GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		var dest xnet.Destination
		switch c := config.(type) {
		case *vlessout.Config:
			dest = xnet.TCPDestination(c.Vnext.Address.AsAddress(), xnet.Port(c.Vnext.Port))
		case *vmessout.Config:
			dest = xnet.TCPDestination(c.Receiver.Address.AsAddress(), xnet.Port(c.Receiver.Port))
		case *hyproxy.ClientConfig:
			dest = xnet.UDPDestination(c.Server.Address.AsAddress(), xnet.Port(c.Server.Port))
		case *wireguard.DeviceConfig:
			dest, err = xnet.ParseDestination("udp:" + c.Peers[0].Endpoint)
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unknown carrier fixture %T", config)
		}
		settings, err := h.SenderSettings().GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		sender := settings.(*proxyman.SenderConfig)
		sockets, muxSockets := w.scopedSockets(dest.String(), scope)
		t.Logf("physical peer %s %s sockets=%v sender-MUX-sockets=%v", tag, dest, sockets, muxSockets)
		if sender.MultiplexSettings != nil {
			if len(muxSockets) != 1 {
				t.Fatalf("%s did not retain one native MUX/XUDP carrier: %v", tag, muxSockets)
			}
			if sender.MultiplexSettings.Concurrency > 0 && len(sockets) != 1 {
				t.Fatalf("%s TCP/UDP MUX did not share carrier: %v", tag, sockets)
			}
		} else if sender.StreamSettings != nil && (sender.StreamSettings.ProtocolName == "grpc" || sender.StreamSettings.ProtocolName == "hysteria") {
			if len(sockets) != 1 {
				t.Fatalf("%s shared transport redialed: %v", tag, sockets)
			}
		} else if sender.StreamSettings != nil && sender.StreamSettings.ProtocolName == "splithttp" {
			settings, err := sender.StreamSettings.TransportSettings[0].Settings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if settings.(*splithttp.Config).Mode == "packet-up" {
				w.mu.Lock()
				reused := false
				for _, source := range sockets {
					if w.uploads[dest.String()][source] > 1 {
						reused = true
					}
				}
				t.Logf("warm packet-up uploads %s: %v", tag, w.uploads[dest.String()])
				w.mu.Unlock()
				if !reused {
					t.Fatal("warm packet-up POSTs did not reuse a witnessed physical socket")
				}
			} else if len(sockets) != 1 {
				t.Fatalf("%s H2 streams did not share socket: %v", tag, sockets)
			}
		} else if _, ok := config.(*wireguard.DeviceConfig); ok && len(sockets) != 1 {
			t.Fatalf("%s WireGuard device redialed: %v", tag, sockets)
		}
	}
}

func TestC5SharedCarriers(t *testing.T) {
	if isolatedSystemDialer(t, 90*time.Second) {
		return
	}
	t.Run("witness-scope", TestCarrierDialWitnessFixtureScope)
	carrierDials = &carrierDialWitness{sockets: make(map[string][]carrierDialRecord), muxSockets: make(map[string][]carrierDialRecord), uploads: make(map[string]map[string]int)}
	internet.UseAlternativeSystemDialer(carrierDials)
	t.Run("sender", TestSenderMUXProfileMeasurements)
	t.Run("transport", TestTransportProfileMeasurements)
	t.Run("hysteria", TestHysteriaMeasurementSeriesAndUDPCancellation)
	t.Run("wireguard", TestWireGuardProtocolMeasurements)
}

func TestCarrierDialWitnessFixtureScope(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dest, err := xnet.ParseDestination("tcp:" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	w := &carrierDialWitness{sockets: make(map[string][]carrierDialRecord), muxSockets: make(map[string][]carrierDialRecord)}
	dial := func(mux bool) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if mux {
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: xnet.TCPDestination(xnet.DomainAddress("v1.mux.cool"), 0)}})
		}
		c, err := w.Dial(ctx, nil, dest, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().String()
	}
	// A previous endpoint/DIRECT record has exactly the later peer's destination.
	historical := dial(false)
	scope := w.beginScope()
	if sockets, mux := w.scopedSockets(dest.String(), scope); len(sockets) != 0 || len(mux) != 0 {
		t.Fatalf("historical dial %s entered new fixture: sockets=%v mux=%v", historical, sockets, mux)
	}
	cold := dial(true)
	if sockets, mux := w.scopedSockets(dest.String(), scope); len(sockets) != 1 || sockets[0] != cold || len(mux) != 1 || mux[0] != cold {
		t.Fatalf("cold carrier was lost or contaminated: sockets=%v mux=%v", sockets, mux)
	}
	redial := dial(true)
	if sockets, mux := w.scopedSockets(dest.String(), scope); len(sockets) != 2 || sockets[0] != cold || sockets[1] != redial || len(mux) != 2 || mux[0] != cold || mux[1] != redial {
		t.Fatalf("real carrier redial was hidden: sockets=%v mux=%v", sockets, mux)
	}
}

// Observe cleartext outer H1 requests without rewriting headers/body/framing or
// replacing the native dialer's concrete socket. Only this isolated fixture
// routes through the relay; Measurement still reaches the configured peer.
func packetUploadWitnessRelay(t *testing.T, peer string) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := "tcp:" + ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			front, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[front] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer front.Close()
				back, err := (&net.Dialer{}).DialContext(ctx, "tcp4", peer)
				if err != nil {
					return
				}
				mu.Lock()
				active[back] = struct{}{}
				mu.Unlock()
				defer func() { back.Close(); mu.Lock(); delete(active, front); delete(active, back); mu.Unlock() }()
				reader, writer := io.Pipe()
				parsed := make(chan struct{})
				go func() {
					defer close(parsed)
					defer reader.Close()
					stream := bufio.NewReader(reader)
					for {
						req, err := http.ReadRequest(stream)
						if err != nil {
							return
						}
						_, err = io.Copy(io.Discard, req.Body)
						req.Body.Close()
						if err != nil {
							return
						}
						if req.Method == http.MethodPost {
							carrierDials.mu.Lock()
							if carrierDials.uploads[key] == nil {
								carrierDials.uploads[key] = make(map[string]int)
							}
							carrierDials.uploads[key][front.RemoteAddr().String()]++
							carrierDials.mu.Unlock()
						}
					}
				}()
				forwarded := make(chan struct{})
				go func() {
					defer close(forwarded)
					_, _ = io.Copy(back, io.TeeReader(front, writer))
					writer.Close()
					back.Close()
				}()
				_, _ = io.Copy(front, back)
				front.Close()
				writer.Close()
				<-forwarded
				<-parsed
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-accepted
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return ln.Addr()
}

func TestTransportProfileMeasurements(t *testing.T) {
	for _, profile := range []string{"websocket", "grpc", "packet-up", "stream-up", "stream-one"} {
		t.Run(profile, func(t *testing.T) {
			transport := "splithttp"
			settings := serial.ToTypedMessage(&splithttp.Config{Path: "/measurement", Mode: profile})
			switch profile {
			case "websocket":
				transport = "websocket"
				settings = serial.ToTypedMessage(&websocket.Config{Path: "/measurement"})
			case "grpc":
				transport = "grpc"
				settings = serial.ToTypedMessage(&grpc.Config{ServiceName: "measurement", MultiMode: false})
			}
			stream := func() *internet.StreamConfig {
				return &internet.StreamConfig{ProtocolName: transport, TransportSettings: []*internet.TransportConfig{{ProtocolName: transport, Settings: settings}}}
			}
			server, client := stream(), stream()
			if profile == "stream-up" || profile == "stream-one" {
				// Streaming uploads use HTTP/2; plaintext native XHTTP chooses HTTP/1.1.
				serverTLS, clientTLS := protocolProfileTLS([]string{"h2"})
				profileStreamSecurity(server, serial.ToTypedMessage(serverTLS))
				profileStreamSecurity(client, serial.ToTypedMessage(clientTLS))
			}
			e, v, counters := plainProtocolExecutor(t, "vless", func(inbound *core.InboundHandlerConfig, outbound *core.OutboundHandlerConfig) {
				profileStreams(t, inbound, outbound, server, client)
			})
			testProtocolMeasurements(t, e, v, counters)
			testProtocolPacketBoundary(t, e, "", 7526, false)
		})
	}
}

func TestSenderMUXProfileMeasurements(t *testing.T) {
	for _, persistentXUDP := range []bool{false, true} {
		name := "tcp-mux"
		mux := &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8, XudpConcurrency: 0, XudpProxyUDP443: "allow"}
		if persistentXUDP {
			name = "persistent-xudp"
			mux.Concurrency, mux.XudpConcurrency = -1, 8
		}
		t.Run(name, func(t *testing.T) {
			e, v, counters := plainProtocolExecutor(t, "vmess", func(inbound *core.InboundHandlerConfig, outbound *core.OutboundHandlerConfig) {
				profileStreams(t, inbound, outbound, protocolProfileRAW(), protocolProfileRAW())
				sender, err := outbound.SenderSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				sender.(*proxyman.SenderConfig).MultiplexSettings = mux
				outbound.SenderSettings = serial.ToTypedMessage(sender)
			})
			testProtocolMeasurements(t, e, v, counters)
			testProtocolPacketBoundary(t, e, "", 8192, false)
		})
	}
}

func TestVisionProfileMeasurements(t *testing.T) {
	for _, security := range []string{"tls13", "reality"} {
		t.Run(security, func(t *testing.T) {
			server, client := protocolProfileRAW(), protocolProfileRAW()
			if security == "tls13" {
				serverTLS, clientTLS := protocolProfileTLS([]string{"h2", "http/1.1"})
				profileStreamSecurity(server, serial.ToTypedMessage(serverTLS))
				profileStreamSecurity(client, serial.ToTypedMessage(clientTLS))
			} else {
				// REALITY consumes the real local cover's TLS 1.3 ServerHello and records.
				cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("local REALITY cover"))
				}))
				cover.EnableHTTP2 = true
				cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, SessionTicketsDisabled: true}
				cover.StartTLS()
				t.Cleanup(cover.Close)
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
				profileStreamSecurity(server, serial.ToTypedMessage(&reality.Config{Type: "tcp", Dest: cover.Listener.Addr().String(), ServerNames: []string{"localhost"}, PrivateKey: key.Bytes(), ShortIds: [][]byte{shortID}}))
				profileStreamSecurity(client, serial.ToTypedMessage(&reality.Config{Fingerprint: "chrome", ServerName: "localhost", PublicKey: key.PublicKey().Bytes(), ShortId: shortID, SpiderX: "/"}))
			}
			e, v, counters := plainProtocolExecutor(t, "vless", func(inbound *core.InboundHandlerConfig, outbound *core.OutboundHandlerConfig) {
				profileStreams(t, inbound, outbound, server, client)
				profileVisionAccounts(t, inbound, outbound)
			})
			testProtocolMeasurements(t, e, v, counters)
			testProtocolPacketBoundary(t, e, "", 7526, false)
		})
	}
}

func protocolProfileRAW() *internet.StreamConfig {
	return &internet.StreamConfig{ProtocolName: "tcp", TransportSettings: []*internet.TransportConfig{{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&tcp.Config{})}}}
}

func protocolProfileTLS(alpn []string) (*xtls.Config, *xtls.Config) {
	certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	server := &xtls.Config{Certificate: []*xtls.Certificate{xtls.ParseCertificate(certificate)}, MinVersion: "1.3", MaxVersion: "1.3", NextProtocol: alpn}
	client := &xtls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{hash[:]}, MinVersion: "1.3", MaxVersion: "1.3", NextProtocol: alpn}
	return server, client
}

func profileStreamSecurity(stream *internet.StreamConfig, security *serial.TypedMessage) {
	stream.SecurityType = security.Type
	stream.SecuritySettings = []*serial.TypedMessage{security}
}

func profileStreams(t *testing.T, inbound *core.InboundHandlerConfig, outbound *core.OutboundHandlerConfig, server, client *internet.StreamConfig) {
	t.Helper()
	receiver, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	receiver.(*proxyman.ReceiverConfig).StreamSettings = server
	inbound.ReceiverSettings = serial.ToTypedMessage(receiver)
	sender, err := outbound.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender.(*proxyman.SenderConfig).StreamSettings = client
	outbound.SenderSettings = serial.ToTypedMessage(sender)
}

func profileVisionAccounts(t *testing.T, inbound *core.InboundHandlerConfig, outbound *core.OutboundHandlerConfig) {
	t.Helper()
	server, err := inbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range server.(*vlessin.Config).Users {
		account, err := user.Account.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		account.(*vless.Account).Flow = vless.XRV
		user.Account = serial.ToTypedMessage(account)
	}
	inbound.ProxySettings = serial.ToTypedMessage(server)
	client, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	user := client.(*vlessout.Config).Vnext.User
	account, err := user.Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	account.(*vless.Account).Flow = vless.XRV
	user.Account = serial.ToTypedMessage(account)
	outbound.ProxySettings = serial.ToTypedMessage(client)
}
