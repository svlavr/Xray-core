package measurement_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	statsfeature "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/measurement"
)

func directHTTPFixture(t *testing.T, handler http.Handler, host string, secure bool, tunnelHosts ...string) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Listener.Close()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	s.Listener = ln
	if secure {
		if len(tunnelHosts) != 0 && tunnelHosts[0] != "" {
			certificate, _ := cert.MustGenerate(nil, cert.DNSNames("example.com"), func(c *x509.Certificate) {
				c.IPAddresses = []net.IP{net.ParseIP(host), net.ParseIP(tunnelHosts[0])}
			})
			pair, err := tls.X509KeyPair(certificate.ToPEM())
			if err != nil {
				t.Fatal(err)
			}
			s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		}
		s.StartTLS()
	} else {
		s.Start()
	}
	return s
}

// A native control exchange distinguishes host IPv6 restrictions from a
// Measurement regression. Binding alone does not prove outbound capability.
func directIPv6Capability(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("native IPv6 TCP bind unavailable:", err)
	}
	defer ln.Close()
	c, err := net.DialTimeout("tcp6", ln.Addr().String(), time.Second)
	if err != nil {
		t.Skip("native IPv6 TCP connect unavailable:", err)
	}
	c.Close()
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("native IPv6 UDP bind unavailable:", err)
	}
	defer pc.Close()
	c, err = net.Dial("udp6", pc.LocalAddr().String())
	if err != nil {
		t.Skip("native IPv6 UDP dial unavailable:", err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("native")); err != nil {
		t.Skip("native IPv6 UDP write unavailable:", err)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	var b [16]byte
	n, addr, err := pc.ReadFrom(b[:])
	if err != nil || string(b[:n]) != "native" {
		t.Skip("native IPv6 UDP delivery unavailable:", err)
	}
	if _, err = pc.WriteTo(b[:n], addr); err != nil {
		t.Skip("native IPv6 UDP response unavailable:", err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if n, err = c.Read(b[:]); err != nil || string(b[:n]) != "native" {
		t.Skip("native IPv6 UDP return unavailable:", err)
	}
}

func TestIndependentDirectRawMethods(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			if host == "::1" {
				directIPv6Capability(t)
			}
			testProtocolRawMethods(t, executor(t, nil), [2]statsfeature.Counter{}, host)
		})
	}
}

func TestIndependentDirectSeriesAndCancellation(t *testing.T) {
	testProtocolMeasurements(t, executor(t, nil), nil, [2]statsfeature.Counter{})
}

func TestIndependentDirectExactRejectedBeforeNetwork(t *testing.T) {
	if isolatedSystemDialer(t) {
		return
	}
	e, err := measurement.New(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var sockets, peers atomic.Int32
	connectController(t, func(_ string, _ string, raw syscall.RawConn) error {
		sockets.Add(1)
		return raw.Control(func(uintptr) {})
	})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		peers.Add(1)
		_, _ = io.WriteString(w, "direct")
	}))
	defer s.Close()
	base := request(s, measurement.ExactOutbound)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	cases := map[string]func() error{
		"HTTP": func() error {
			_, err := e.HTTP(context.Background(), http.MethodHead, measurement.HTTPRequest(base))
			return err
		},
		"HTTPS": func() error { _, err := e.HTTPS(context.Background(), base); return err },
		"Download": func() error {
			_, err := e.Download(context.Background(), downloadRequest(s, measurement.ExactOutbound))
			return err
		},
		"Upload": func() error {
			_, err := e.Upload(context.Background(), uploadRequest(s, measurement.ExactOutbound))
			return err
		},
		"Identity": func() error {
			_, err := e.EgressIdentity(context.Background(), measurement.IdentityRequest{HTTPS: base, Family: measurement.IPv4})
			return err
		},
		"UDP": func() error {
			r, err := e.UDPEcho(context.Background(), udpRequest(addr, measurement.ExactOutbound))
			if len(r.Sends) != 0 || len(r.Replies) != 0 || r.WindowComplete {
				t.Errorf("exact UDP fabricated I/O: %+v", r)
			}
			return err
		},
		"TCP": func() error {
			_, err := e.TCPConnect(context.Background(), measurement.TCPConnectRequest{Route: base.Route, Destination: netip.MustParseAddrPort("127.0.0.1:9"), Timeout: time.Second})
			return err
		},
		"ICMP": func() error {
			_, err := e.ICMPEcho(context.Background(), measurement.ICMPEchoRequest{Route: base.Route, Destination: netip.MustParseAddr("127.0.0.1"), PayloadBytes: 24, Timeout: time.Second})
			return err
		},
	}
	for _, transport := range []measurement.DNSTransport{measurement.DNSUDP, measurement.DNSTCP, measurement.DNSDoT, measurement.DNSDoH} {
		r := dnsRequest(addr, transport, measurement.ExactOutbound)
		r.ServerName, r.DoHPath, r.MaxHeaderBytes = "fixture.invalid", "/dns-query", 4096
		run := func() error {
			got, err := e.DNSQuery(context.Background(), r)
			if got.WrittenBytes != nil || len(got.Wire) != 0 || got.Message != nil || got.ResponseComplete {
				t.Errorf("exact DNS fabricated I/O: %+v", got)
			}
			return err
		}
		if err := run(); !errors.Is(err, measurement.ErrUnsupported) {
			t.Fatalf("DNS transport %d: %v", transport, err)
		}
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			for range 3 {
				if err := run(); !errors.Is(err, measurement.ErrUnsupported) {
					t.Fatalf("exact without instance: %v", err)
				}
			}
		})
	}
	if sockets.Load() != 0 || peers.Load() != 0 {
		t.Fatalf("exact fell back: sockets=%d requests=%d", sockets.Load(), peers.Load())
	}
	base.Route = measurement.Route{Kind: measurement.Direct}
	got, err := e.HTTPS(context.Background(), base)
	if err != nil || string(got.Body) != "direct" || peers.Load() != 1 || sockets.Load() != 1 {
		t.Fatalf("slot reuse/native controller: %+v %v sockets=%d requests=%d", got, err, sockets.Load(), peers.Load())
	}
	pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) { _, _ = pc.WriteTo(b, a) })
	gotUDP, err := e.UDPEcho(context.Background(), udpRequest(pc.LocalAddr(), measurement.Direct))
	if err != nil || len(gotUDP.Replies) != 3 || sockets.Load() != 2 {
		t.Fatalf("native UDP controller: %+v %v sockets=%d", gotUDP, err, sockets.Load())
	}
}
