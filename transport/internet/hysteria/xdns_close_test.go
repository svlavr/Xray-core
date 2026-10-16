package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type xdnsReadWitness struct {
	net.PacketConn
	entered   chan struct{}
	once      sync.Once
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *xdnsReadWitness) Close() error {
	c.closeOnce.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return c.PacketConn.Close()
}

func (c *xdnsReadWitness) ReadFrom(p []byte) (int, net.Addr, error) {
	c.once.Do(func() { close(c.entered) })
	return c.PacketConn.ReadFrom(p)
}

func testXDNSPair(t *testing.T) (net.PacketConn, net.PacketConn) {
	t.Helper()
	var raw net.PacketConn
	var listener net.Listener
	var err error
	for range 256 {
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		raw, err = net.ListenPacket("udp4", listener.Addr().String())
		if err == nil {
			break
		}
		listener.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	domain := &xdns.DomainProto{Name: "x.example", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}
	s, err := (&xdns.Config{Domains: []*xdns.DomainProto{domain}, TcpOnly: true}).WrapPacketConnServer(raw, raw.LocalAddr(), &finalmask.ListenConfig{Listen: func(net.Addr) (net.Listener, error) { return listener, nil }})
	if err != nil {
		raw.Close()
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c, err := xdns.NewClient(&xdns.Config{Domains: []*xdns.DomainProto{domain}, Resolvers: []*xdns.ResolverProto{{Type: "tcp", Addr: s.LocalAddr().String()}}}, &finalmask.Dialer{DialTCP: func(d xnet.Destination) (xnet.Conn, error) { return net.DialTimeout("tcp", d.NetAddr(), time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, s
}

func TestXDNSOwnedQUICClose(t *testing.T) {
	for _, first := range []string{"client", "listener"} {
		t.Run(first, func(t *testing.T) {
			c, s := testXDNSPair(t)
			clientPC := &xdnsReadWitness{PacketConn: c, entered: make(chan struct{})}
			serverPC := &xdnsReadWitness{PacketConn: s, entered: make(chan struct{})}
			cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(cert.Close)
			roots := x509.NewCertPool()
			roots.AddCert(cert.Certificate())
			serverTR := &quic.Transport{Conn: serverPC, DisableGSO: true}
			clientTR := &quic.Transport{Conn: clientPC, DisableGSO: true}
			t.Cleanup(func() { c.Close(); s.Close(); clientTR.Close(); serverTR.Close() })
			config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, DisablePathManager: true, HandshakeIdleTimeout: 10 * time.Second}
			ql, err := serverTR.Listen(&tls.Config{Certificates: cert.TLS.Certificates, NextProtos: []string{"h3"}}, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ql.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			qc, err := clientTR.Dial(ctx, s.LocalAddr(), &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h3"}}, config)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := ql.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.CloseWithError(0, "") })
			for _, entered := range []chan struct{}{clientPC.entered, serverPC.entered} {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("QUIC reader was not entered")
				}
			}
			h := &client{conn: qc, tr: clientTR, pktConn: clientPC}
			l := &Listener{listener: ql, tr: serverTR, pktConn: serverPC}
			closeOwner := func(close func() error) {
				t.Helper()
				done := make(chan error, 1)
				go func() { done <- close() }()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					// Rescue cleanup only after a failed assertion, never as a success path.
					c.Close()
					s.Close()
					select {
					case <-done:
					case <-time.After(time.Second):
					}
					t.Fatal("owner Close waited for an unsupported XDNS read deadline")
				}
			}
			closeClient := func() error { h.close(); return nil }
			if first == "client" {
				closeOwner(closeClient)
				closeOwner(l.Close)
			} else {
				closeOwner(l.Close)
				closeOwner(closeClient)
			}
			if h.conn != nil || h.tr != nil || h.pktConn != nil {
				t.Fatal("client retained closed QUIC resources")
			}
		})
	}
}

func TestXDNSHysteriaAuthenticationAndCleanup(t *testing.T) {
	for _, auth := range []string{"expected", "rejected"} {
		t.Run(auth, func(t *testing.T) {
			c, s := testXDNSPair(t)
			clientPC := &xdnsReadWitness{PacketConn: c, entered: make(chan struct{}), closed: make(chan struct{})}
			cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(cert.Close)
			key, err := x509.MarshalPKCS8PrivateKey(cert.TLS.Certificates[0].PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			serverTLS := &xtls.Config{NextProtocol: []string{"h3"}, Certificate: []*xtls.Certificate{{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate().Raw}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), OneTimeLoading: true}}}
			params := &internet.QuicParams{Congestion: "reno", DisableChromeParrot: true, DisablePathMtuDiscovery: true}
			serverFM := finalmask.NewFinalMask(nil, nil, nil, nil, nil, func(context.Context, net.Addr) (net.PacketConn, error) { return s, nil })
			listener, err := Listen(context.Background(), xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{ProtocolSettings: &Config{Auth: "expected"}, SecuritySettings: serverTLS, FinalMask: serverFM, QuicParams: params}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close(); listener.Close() })
			roots := x509.NewCertPool()
			roots.AddCert(cert.Certificate())
			remote := s.LocalAddr().(*net.UDPAddr)
			clientFM := finalmask.NewFinalMask(nil, nil, nil, nil, func(context.Context, xnet.Destination) (net.PacketConn, net.Addr, error) {
				return clientPC, remote, nil
			}, nil)
			h := &client{config: &Config{Auth: auth}, tlsConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h3"}}, quicParams: params, finalMask: clientFM, dest: xnet.UDPDestination(xnet.IPAddress(remote.IP), xnet.Port(remote.Port))}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.dial(ctx) }()
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				c.Close()
				s.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatal("Hysteria authentication cleanup did not complete")
			}
			if auth == "expected" {
				if err != nil {
					t.Fatal(err)
				}
				closed := make(chan struct{})
				go func() { h.close(); close(closed) }()
				select {
				case <-closed:
				case <-time.After(3 * time.Second):
					c.Close()
					s.Close()
					select {
					case <-closed:
					case <-time.After(time.Second):
					}
					t.Fatal("authenticated client close stalled")
				}
			} else if err == nil || !strings.Contains(err.Error(), "auth failed code") {
				t.Fatalf("authentication rejection: %v", err)
			}
			select {
			case <-clientPC.closed:
			default:
				t.Fatal("Hysteria retained owned XDNS packet connection")
			}
		})
	}
}
