package masque

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

const masqueOwnerName = "masque-owner.example"

func masqueOwnerCertificate(t *testing.T, issuer *cert.Certificate, responder string) (*xraytls.Certificate, []byte) {
	t.Helper()
	leaf, _ := cert.MustGenerate(issuer, cert.CommonName(masqueOwnerName), cert.DNSNames(masqueOwnerName), func(c *x509.Certificate) {
		c.OCSPServer = []string{responder}
	})
	entry := xraytls.ParseCertificate(leaf)
	issuerPEM, _ := issuer.ToPEM()
	entry.Certificate = append(entry.Certificate, issuerPEM...)
	return entry, leaf.Certificate
}

func masqueOwnerSettings(entry *xraytls.Certificate) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Path: DefaultPath},
		SecurityType:     "tls",
		SecuritySettings: &xraytls.Config{
			NextProtocol: []string{http2.NextProtoTLS, http3.NextProtoH3},
			Certificate:  []*xraytls.Certificate{entry},
		},
	}
}

func masqueOwnerUnexpectedHandler(t *testing.T) internet.ConnHandler {
	return func(conn stat.Connection) {
		_ = conn.Close()
		t.Error("an unrelated-path HTTP request reached the MASQUE application handler")
	}
}

// Each invocation uses fresh transports so the returned TLS state comes from
// new handshakes, including after certificate replacement.
func masqueOwnerCheckProtocols(t *testing.T, l *Listener, roots *x509.CertPool, wantDER []byte) {
	t.Helper()
	h2 := &http2.Transport{TLSClientConfig: &gotls.Config{
		RootCAs: roots, ServerName: masqueOwnerName, NextProtos: []string{http2.NextProtoTLS},
	}}
	defer h2.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: &gotls.Config{
		RootCAs: roots, ServerName: masqueOwnerName, NextProtos: []string{http3.NextProtoH3},
	}}
	defer h3.Close()

	type result struct {
		protocol string
		state    *gotls.ConnectionState
		status   int
		err      error
	}
	results := make(chan result, 2)
	for _, request := range []struct {
		protocol  string
		address   string
		transport http.RoundTripper
	}{
		{http2.NextProtoTLS, l.tcpListener.Addr().String(), h2},
		{http3.NextProtoH3, l.quicListener.Addr().String(), h3},
	} {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+request.address+"/outside-masque", nil)
			if err != nil {
				results <- result{protocol: request.protocol, err: err}
				return
			}
			resp, err := request.transport.RoundTrip(req)
			if err != nil {
				results <- result{protocol: request.protocol, err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil {
				err = readErr
			} else {
				err = closeErr
			}
			results <- result{request.protocol, resp.TLS, resp.StatusCode, err}
		}()
	}
	for range 2 {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatalf("%s exchange: %v", got.protocol, got.err)
			}
			if got.status != http.StatusNotFound {
				t.Fatalf("%s status=%d, want native unrelated-path 404", got.protocol, got.status)
			}
			if got.state == nil || got.state.NegotiatedProtocol != got.protocol {
				t.Fatalf("%s TLS state=%+v", got.protocol, got.state)
			}
			if len(got.state.VerifiedChains) == 0 || len(got.state.PeerCertificates) == 0 {
				t.Fatalf("%s peer was not verified against the fixture CA", got.protocol)
			}
			if !bytes.Equal(got.state.PeerCertificates[0].Raw, wantDER) {
				t.Fatalf("%s selected the wrong certificate", got.protocol)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("dual-protocol exchange did not return")
		}
	}
}

func TestMASQUEListenerSharedTLSReload(t *testing.T) {
	// The empty local response only lets native reload ticks proceed. This
	// fixture does not assert an OCSP status; existing TLS tests cover staples.
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(responder.Close)
	issuer, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	parsedIssuer, err := x509.ParseCertificate(issuer.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsedIssuer)
	entry, oldDER := masqueOwnerCertificate(t, issuer, responder.URL)
	replacement, newDER := masqueOwnerCertificate(t, issuer, responder.URL)
	initialCert, initialKey := bytes.Clone(entry.Certificate), bytes.Clone(entry.Key)
	entry.OcspStapling = 1
	directory := t.TempDir()
	entry.CertificatePath, entry.KeyPath = filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if err := os.WriteFile(entry.CertificatePath, initialCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.KeyPath, initialKey, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(context.Background(), net.LocalHostIP, 0, masqueOwnerSettings(entry), masqueOwnerUnexpectedHandler(t))
	if err != nil {
		t.Fatal(err)
	}
	l := listener.(*Listener)
	t.Cleanup(func() { _ = l.Close() })
	if l.tcpListener == nil || l.quicListener == nil || l.tlsConfig == nil {
		t.Fatal("dual-protocol listener or shared TLS owner is absent")
	}
	carrier, ok := l.tlsConfig.Rand.(*xraytls.RandCarrier)
	if !ok || carrier.Config != l.tlsConfig {
		t.Fatal("listener lost its base RandCarrier lifetime handle")
	}
	masqueOwnerCheckProtocols(t, l, roots, oldDER)
	if err := os.WriteFile(entry.CertificatePath, replacement.Certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.KeyPath, replacement.Key, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		selected, err := l.tlsConfig.GetCertificate(&gotls.ClientHelloInfo{ServerName: masqueOwnerName})
		if err == nil && bytes.Equal(selected.Certificate[0], newDER) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shared certificate selector did not publish replacement")
		}
		time.Sleep(time.Millisecond)
	}
	masqueOwnerCheckProtocols(t, l, roots, newDER)
	if !bytes.Equal(entry.Certificate, initialCert) || !bytes.Equal(entry.Key, initialKey) {
		t.Fatal("certificate worker mutated caller-owned configuration input")
	}
}

func TestMASQUEListenerTLSRetirement(t *testing.T) {
	for _, mode := range []string{"close", "partial_h2_bind_failure"} {
		t.Run(mode, func(t *testing.T) {
			entered, canceled, release := make(chan struct{}, 4), make(chan struct{}, 4), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var requests atomic.Int32
			responder := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				// Complete the request body so net/http can observe connection
				// closure while this handler is deliberately held.
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					return
				}
				_ = r.Body.Close()
				requests.Add(1)
				entered <- struct{}{}
				select {
				case <-r.Context().Done():
					canceled <- struct{}{}
				case <-release:
				}
			}))
			t.Cleanup(func() { unblock(); responder.Close() })
			issuer, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
			entry, _ := masqueOwnerCertificate(t, issuer, responder.URL)
			entry.OcspStapling = 3600
			settings := masqueOwnerSettings(entry)
			var port net.Port
			udpAddress := make(chan string, 1)
			if mode == "partial_h2_bind_failure" {
				guard, err := gonet.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = guard.Close() })
				port = net.Port(guard.Addr().(*gonet.TCPAddr).Port)
				// Use existing native FinalMask callbacks only as a barrier.
				// The final TCP operation is a real bind against the guard;
				// no production test hooks or synthetic socket errors are used.
				settings.FinalMask = finalmask.NewFinalMask(nil, nil, nil,
					func(ctx context.Context, addr net.Addr) (net.Listener, error) {
						select {
						case <-entered:
						case <-time.After(5 * time.Second):
							return nil, fmt.Errorf("OCSP did not start before TCP bind")
						}
						return internet.ListenSystem(ctx, addr, settings.SocketSettings)
					}, nil,
					func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
						packet, err := internet.ListenSystemPacket(ctx, addr, settings.SocketSettings)
						if err == nil {
							udpAddress <- packet.LocalAddr().String()
						}
						return packet, err
					})
			}
			type listenResult struct {
				listener internet.Listener
				err      error
			}
			done := make(chan listenResult, 1)
			go func() {
				listener, err := Listen(context.Background(), net.LocalHostIP, port, settings, masqueOwnerUnexpectedHandler(t))
				done <- listenResult{listener, err}
			}()
			var started listenResult
			select {
			case started = <-done:
			case <-time.After(6 * time.Second):
				unblock()
				t.Fatal("Listen did not finish its owned startup/cleanup")
			}
			if mode == "partial_h2_bind_failure" {
				if started.listener != nil {
					_ = started.listener.Close()
					t.Fatal("reserved TCP port unexpectedly admitted H2")
				}
				if started.err == nil || !strings.Contains(started.err.Error(), "failed to listen TCP") {
					t.Fatalf("expected second-branch native bind failure: %v", started.err)
				}
			} else {
				if started.err != nil {
					t.Fatal(started.err)
				}
				l := started.listener.(*Listener)
				t.Cleanup(func() { unblock(); _ = l.Close() })
				if l.tcpListener == nil || l.quicListener == nil || l.tlsConfig == nil {
					t.Fatal("close case did not start both native branches")
				}
				if carrier, ok := l.tlsConfig.Rand.(*xraytls.RandCarrier); !ok || carrier.Config != l.tlsConfig {
					t.Fatal("base TLS owner lost its RandCarrier")
				}
				udpAddress <- l.pktConn.LocalAddr().String()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("proactive OCSP request never started")
				}
				closed := make(chan error, 1)
				go func() { closed <- l.Close() }()
				select {
				case err := <-closed:
					// Native repeated resource closes can return an error.
					// This test asserts worker retirement, not a new nil-error
					// Close contract.
					if err != nil {
						t.Logf("native Close result: %v", err)
					}
				case <-time.After(5 * time.Second):
					unblock()
					t.Fatal("listener Close failed to cancel/join blocked OCSP")
				}
				tcp, err := gonet.DialTimeout("tcp4", l.tcpListener.Addr().String(), time.Second)
				if err == nil {
					_ = tcp.Close()
					t.Fatal("closed listener still accepts native TCP")
				}
			}
			// Request-context cancellation is observed remotely and may arrive
			// just after local Close returns; no synchronous remote completion
			// promise is introduced.
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("retired TLS owner left the OCSP request alive")
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("one listener created %d OCSP requests, want one shared owner", got)
			}
			address := <-udpAddress
			rebound, err := gonet.ListenPacket("udp4", address)
			if err != nil {
				t.Fatalf("native UDP socket survived retirement: %v", err)
			}
			_ = rebound.Close()
		})
	}
}
