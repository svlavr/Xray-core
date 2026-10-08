package measurement_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"

	"github.com/xtls/xray-core/measurement"
)

func dnsReply(query []byte) []byte {
	q := new(dns.Msg)
	if err := q.Unpack(query); err != nil {
		return nil
	}
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 12}, A: net.IPv4(192, 0, 2, 1)}}
	wire, _ := r.Pack()
	return wire
}

func dnsRequest(addr net.Addr, transport measurement.DNSTransport, kind measurement.RouteKind) measurement.DNSRequest {
	r := measurement.DNSRequest{Route: measurement.Route{Kind: kind}, Transport: transport, Resolver: netip.MustParseAddrPort(addr.String()), Name: "fixture.invalid.", Type: dns.TypeA, RecursionDesired: true, EDNSSize: 1232, Timeout: 2 * time.Second, MaxResponseBytes: 1232}
	if kind == measurement.ExactOutbound {
		r.Route.Tag = "exact"
	}
	return r
}

// One local server owns its connections; tests always close accepted sockets.
func dnsStreamFixture(t *testing.T, tlsConfig *tls.Config, respond func(net.Conn, []byte), host ...string) net.Addr {
	t.Helper()
	address := "127.0.0.1"
	if len(host) != 0 {
		address = host[0]
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	}
	stopped := make(chan struct{})
	t.Cleanup(func() { ln.Close(); <-stopped })
	go func() {
		defer close(stopped)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var p [2]byte
				if _, err := io.ReadFull(c, p[:]); err != nil {
					return
				}
				q := make([]byte, int(binary.BigEndian.Uint16(p[:])))
				if _, err := io.ReadFull(c, q); err == nil {
					respond(c, q)
				}
			}()
		}
	}()
	return ln.Addr()
}

func dnsFrame(c net.Conn, wire []byte) {
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(len(wire)))
	c.Write(p[:])
	c.Write(wire)
}

func TestDNSLocalTransportsDirectAndExact(t *testing.T) {
	v := instance(t)
	e := executor(t, v)
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certServer.Close()
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	for _, transport := range []measurement.DNSTransport{measurement.DNSUDP, measurement.DNSTCP, measurement.DNSDoT, measurement.DNSDoH} {
		t.Run(string(rune('0'+transport)), func(t *testing.T) {
			var addr net.Addr
			var calls atomic.Int32
			if transport == measurement.DNSUDP {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				addr = pc.LocalAddr()
				go func() {
					b := make([]byte, 2048)
					for {
						n, a, err := pc.ReadFrom(b)
						if err != nil {
							return
						}
						calls.Add(1)
						pc.WriteTo(dnsReply(b[:n]), a)
					}
				}()
			} else if transport == measurement.DNSDoH {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != "POST" || r.URL.Path != "/dns-query" || r.Header.Get("Accept") != "application/dns-message" || r.Header.Get("Content-Type") != "application/dns-message" {
						t.Error("unexpected DoH request")
					}
					q, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(dnsReply(q))
				}))
				s.TLS = certServer.TLS.Clone()
				s.StartTLS()
				defer s.Close()
				addr = s.Listener.Addr()
			} else {
				var cfg *tls.Config
				if transport == measurement.DNSDoT {
					cfg = certServer.TLS.Clone()
				}
				addr = dnsStreamFixture(t, cfg, func(c net.Conn, q []byte) {
					calls.Add(1)
					wire := dnsReply(q)
					// Deliberately split the TCP length and every payload byte.
					frame := make([]byte, len(wire)+2)
					binary.BigEndian.PutUint16(frame, uint16(len(wire)))
					copy(frame[2:], wire)
					for _, b := range frame {
						c.Write([]byte{b})
					}
				})
			}
			for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
				r := dnsRequest(addr, transport, kind)
				if transport == measurement.DNSDoT || transport == measurement.DNSDoH {
					r.ServerName = "example.com"
					r.RootCAs = pool
				}
				if transport == measurement.DNSDoH {
					r.DoHPath = "/dns-query"
					r.MaxHeaderBytes = 4096
				}
				got, err := e.DNSQuery(context.Background(), r)
				if err != nil || got.Message == nil || got.Message.Rcode != dns.RcodeSuccess || len(got.Message.Answer) != 1 || !got.ResponseComplete {
					t.Fatalf("transport=%d kind=%d receipt=%+v err=%v", transport, kind, got, err)
				}

				if (transport == measurement.DNSDoT || transport == measurement.DNSDoH) && got.EndpointTLS == nil {
					t.Fatal("missing endpoint TLS")
				}
				if transport == measurement.DNSDoH {
					if got.QueryID != 0 || got.WrittenBytes != nil || got.HTTPStatus != 200 {
						t.Fatalf("wrong DoH facts: %+v", got)
					}
				} else if got.WrittenBytes == nil || *got.WrittenBytes < 12 {
					t.Fatalf("missing write facts: %+v", got)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("requests=%d", calls.Load())
			}
		})
	}
}

func TestDNSResponsesAndLimits(t *testing.T) {
	e := executor(t, instance(t))
	for _, name := range []string{"nxdomain", "servfail", "tc", "id", "name", "type", "class", "qr", "opcode", "trailing", "counts", "short", "oversize", "partial"} {
		t.Run(name, func(t *testing.T) {
			addr := dnsStreamFixture(t, nil, func(c net.Conn, q []byte) {
				r := new(dns.Msg)
				r.Unpack(dnsReply(q))
				switch name {
				case "nxdomain":
					r.Rcode = dns.RcodeNameError
					r.Answer = nil
				case "servfail":
					r.Rcode = dns.RcodeServerFailure
				case "tc":
					r.Truncated = true
				case "id":
					r.Id++
				case "name":
					r.Question[0].Name = "other.invalid."
				case "type":
					r.Question[0].Qtype = dns.TypeAAAA
				case "class":
					r.Question[0].Qclass = dns.ClassCHAOS
				case "qr":
					r.Response = false
				case "opcode":
					r.Opcode = dns.OpcodeNotify
				}
				wire, _ := r.Pack()
				switch name {
				case "trailing":
					wire = append(wire, 0)
				case "counts":
					binary.BigEndian.PutUint16(wire[6:8], 65535)
				case "short":
					wire = wire[:8]
				case "oversize":
					wire = make([]byte, 2000)
				case "partial":
					var p [2]byte
					binary.BigEndian.PutUint16(p[:], uint16(len(wire)))
					c.Write(p[:])
					c.Write(wire[:18])
					return
				}
				dnsFrame(c, wire)
			})
			got, err := e.DNSQuery(context.Background(), dnsRequest(addr, measurement.DNSTCP, measurement.Direct))
			success := name == "nxdomain" || name == "servfail" || name == "tc" || name == "trailing" || name == "counts"
			if success {
				if err != nil || got.Message == nil {
					t.Fatalf("raw DNS outcome: %+v %v", got, err)
				}
			} else if err == nil || got.Message != nil {
				t.Fatalf("accepted invalid: %+v %v", got, err)
			}
			if name == "oversize" && (!errors.Is(err, measurement.ErrDNSLimit) || len(got.Wire) != 0) {
				t.Fatal("declared bound not checked before allocation")
			}
			if name == "partial" && (len(got.Wire) != 18 || got.ResponseComplete || !errors.Is(err, io.ErrUnexpectedEOF)) {
				t.Fatalf("lost partial: %+v %v", got, err)
			}
		})
	}
}

func TestDNSUDPTruncationBoundsAndSource(t *testing.T) {
	e := executor(t, instance(t))
	for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		for _, mode := range []string{"tc", "oversize", "trailing", "source"} {
			t.Run(mode+string(rune('0'+kind)), func(t *testing.T) {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				var calls atomic.Int32
				go func() {
					b := make([]byte, 2048)
					n, a, err := pc.ReadFrom(b)
					if err != nil {
						return
					}
					calls.Add(1)
					q := new(dns.Msg)
					q.Unpack(dnsReply(b[:n]))
					q.Truncated = true
					wire, _ := q.Pack()
					switch mode {
					case "oversize":
						wire = append(wire, make([]byte, 1600)...)
					case "trailing":
						wire = append(wire, 0)
					case "source":
						other, _ := net.ListenPacket("udp", "127.0.0.1:0")
						defer other.Close()
						other.WriteTo(wire, a)
						return
					}
					pc.WriteTo(wire, a)
				}()
				r := dnsRequest(pc.LocalAddr(), measurement.DNSUDP, kind)
				r.Timeout = 200 * time.Millisecond
				got, err := e.DNSQuery(context.Background(), r)
				if mode == "tc" || mode == "trailing" {
					if err != nil || got.Message == nil || !got.Message.Truncated {
						t.Fatalf("TC rejected: %+v %v", got, err)
					}
				} else if err == nil || got.Message != nil {
					t.Fatalf("invalid UDP accepted: %+v %v", got, err)
				}
				if mode == "oversize" && (!errors.Is(err, measurement.ErrDNSLimit) || len(got.Wire) != r.MaxResponseBytes) {
					t.Fatalf("UDP limit: %+v %v", got, err)
				}
				if calls.Load() != 1 {
					t.Fatal("retry or fallback")
				}
			})
		}
	}
}

func TestDNSDoHFailuresAndTLSTrust(t *testing.T) {
	e := executor(t, instance(t))
	for _, mode := range []string{"status", "media", "body", "redirect", "trust", "hostname", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				q, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/dns-message")
				switch mode {
				case "status":
					w.WriteHeader(503)
				case "media":
					w.Header().Set("Content-Type", "text/plain")
				case "redirect":
					w.Header().Set("Location", "/other")
					w.WriteHeader(302)
				case "body":
					w.Write(make([]byte, 1600))
					return
				}
				wire := dnsReply(q)
				if mode == "trailing" {
					wire = append(wire, 0)
				}
				w.Write(wire)
			}))
			defer s.Close()
			r := dnsRequest(s.Listener.Addr(), measurement.DNSDoH, measurement.Direct)
			r.DoHPath = "/dns-query"
			r.MaxHeaderBytes = 4096
			r.ServerName = "example.com"
			pool := x509.NewCertPool()
			pool.AddCert(s.Certificate())
			r.RootCAs = pool
			if mode == "trust" {
				r.RootCAs = x509.NewCertPool()
			}
			if mode == "hostname" {
				r.ServerName = "mismatch.invalid"
			}
			got, err := e.DNSQuery(context.Background(), r)
			if mode == "trailing" {
				if err != nil || got.Message == nil {
					t.Fatalf("native DNS decode rejected trailing bytes: %+v %v", got, err)
				}
			} else if err == nil || got.Message != nil {
				t.Fatalf("invalid DoH accepted: %+v %v", got, err)
			}

			if mode == "trust" || mode == "hostname" {
				if calls.Load() != 0 {
					t.Fatal("sent HTTP with bad TLS")
				}
			} else if calls.Load() != 1 || got.HTTPStatus == 0 || len(got.Wire) == 0 {
				t.Fatalf("lost HTTP failure facts: %+v %v", got, err)
			}
		})
	}
}

func TestDNSCancelDeadlineAndExactMissing(t *testing.T) {
	e := executor(t, instance(t))
	for _, transport := range []measurement.DNSTransport{measurement.DNSUDP, measurement.DNSTCP, measurement.DNSDoT} {
		for _, kind := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
			var addr net.Addr
			opened := make(chan struct{}, 1)
			if transport == measurement.DNSUDP {
				pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
				defer pc.Close()
				addr = pc.LocalAddr()
				go func() { b := make([]byte, 2048); pc.ReadFrom(b); opened <- struct{}{} }()
			} else {
				ln, _ := net.Listen("tcp", "127.0.0.1:0")
				defer ln.Close()
				addr = ln.Addr()
				go func() {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					opened <- struct{}{}
					io.Copy(io.Discard, c)
				}()
			}
			r := dnsRequest(addr, transport, kind)
			r.Timeout = 150 * time.Millisecond
			if transport == measurement.DNSDoT {
				r.ServerName = "example.com"
			}
			began := time.Now()
			got, err := e.DNSQuery(context.Background(), r)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) > 1500*time.Millisecond || got.Message != nil {
				t.Fatalf("cancel failed transport=%d kind=%d %+v %v", transport, kind, got, err)
			}
			if transport == measurement.DNSDoT && got.EndpointTLS == nil {
				t.Fatal("lost failed endpoint TLS phase")
			}
			select {
			case <-opened:
			default:
				t.Fatal("deadline did not exercise active native I/O")
			}
			r.Route = measurement.Route{Kind: measurement.ExactOutbound, Tag: "missing"}
			_, err = e.DNSQuery(context.Background(), r)
			if err == nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = e.DNSQuery(ctx, r)
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		}
	}
}

func TestDNSRequestValidation(t *testing.T) {
	e := executor(t, instance(t))
	base := dnsRequest(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, measurement.DNSTCP, measurement.Direct)
	cases := []func(*measurement.DNSRequest){
		func(r *measurement.DNSRequest) { r.Name = "relative" },
		func(r *measurement.DNSRequest) { r.Name = strings.Repeat("a", 256) + "." },
		func(r *measurement.DNSRequest) { r.Resolver = netip.MustParseAddrPort("[fe80::1%eth0]:53") },
		func(r *measurement.DNSRequest) { r.Timeout = 0 },
		func(r *measurement.DNSRequest) { r.MaxResponseBytes = 0 },
		func(r *measurement.DNSRequest) { r.DNSSECOK = true; r.EDNSSize = 0 },
		func(r *measurement.DNSRequest) { r.Type = dns.TypeAXFR },
	}
	for i, change := range cases {
		r := base
		change(&r)
		got, err := e.DNSQuery(context.Background(), r)
		if err == nil || got.Elapsed != 0 {
			t.Fatalf("invalid input %d was admitted %+v %v", i, got, err)
		}
	}
}

func TestDNSExactVLESSStreamsAndPacket(t *testing.T) {
	port := tcp.PickPort()
	peerID := uuid.New()
	id := peerID.String()
	peer, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}}), ProxySettings: serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: id})}}})}},
		Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	v := instance(t)
	manager := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := manager.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	if err := core.AddOutboundHandler(v, &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"})}}})}); err != nil {
		t.Fatal(err)
	}

	e := executor(t, v)
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cert.Close()
	pool := x509.NewCertPool()
	pool.AddCert(cert.Certificate())
	for _, transport := range []measurement.DNSTransport{measurement.DNSTCP, measurement.DNSDoT, measurement.DNSDoH} {
		var addr net.Addr
		if transport == measurement.DNSDoH {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(dnsReply(q))
			}))
			s.TLS = cert.TLS.Clone()
			s.StartTLS()
			defer s.Close()
			addr = s.Listener.Addr()
		} else {
			var cfg *tls.Config
			if transport == measurement.DNSDoT {
				cfg = cert.TLS.Clone()
			}
			addr = dnsStreamFixture(t, cfg, func(c net.Conn, q []byte) { dnsFrame(c, dnsReply(q)) })
		}
		r := dnsRequest(addr, transport, measurement.ExactOutbound)
		if transport != measurement.DNSTCP {
			r.ServerName = "example.com"
			r.RootCAs = pool
		}
		if transport == measurement.DNSDoH {
			r.DoHPath = "/dns-query"
			r.MaxHeaderBytes = 4096
		}
		got, err := e.DNSQuery(context.Background(), r)
		if err != nil || got.Message == nil {
			t.Fatalf("VLESS transport=%d %+v %v", transport, got, err)
		}
	}
	pc := udpFixture(t, func(pc net.PacketConn, packet []byte, addr net.Addr) { _, _ = pc.WriteTo(dnsReply(packet), addr) })
	r := dnsRequest(pc.LocalAddr(), measurement.DNSUDP, measurement.ExactOutbound)
	got, err := e.DNSQuery(context.Background(), r)
	if err != nil || got.Message == nil {
		t.Fatalf("native VLESS DNS packet: %+v %v", got, err)
	}
}

func TestDNSConcurrentAndNoResolverMutation(t *testing.T) {
	e := executor(t, instance(t))
	original := net.DefaultResolver
	addr := dnsStreamFixture(t, nil, func(c net.Conn, q []byte) { dnsFrame(c, dnsReply(q)) })
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kind := measurement.Direct
			if i%2 == 1 {
				kind = measurement.ExactOutbound
			}
			r, err := e.DNSQuery(context.Background(), dnsRequest(addr, measurement.DNSTCP, kind))
			if err != nil || r.Message == nil {
				t.Errorf("concurrent DNS %+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	if net.DefaultResolver != original {
		t.Fatal("global resolver changed")
	}
}

func TestDNSPresentationEscapesMatchWireQuestion(t *testing.T) {
	e := executor(t, instance(t))
	addr := dnsStreamFixture(t, nil, func(c net.Conn, q []byte) { dnsFrame(c, dnsReply(q)) })
	for _, name := range []string{`\065.example.`, `a\046b.example.`, `\255.example.`} {
		r := dnsRequest(addr, measurement.DNSTCP, measurement.ExactOutbound)
		r.Name = name
		got, err := e.DNSQuery(context.Background(), r)
		if err != nil || got.Message == nil || !got.ResponseComplete {
			t.Fatalf("escaped name %q rejected %+v %v", name, got, err)
		}
	}
}
