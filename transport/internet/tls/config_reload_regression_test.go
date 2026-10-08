package tls

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func reloadHandshake(config *gotls.Config, name string, version uint16) (gotls.ConnectionState, error) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	serverTLS := gotls.Server(server, config)
	clientTLS := gotls.Client(client, &gotls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: version, MaxVersion: version}) // Local fixture only.
	done := make(chan error, 1)
	go func() { done <- serverTLS.HandshakeContext(ctx) }()
	err := clientTLS.HandshakeContext(ctx)
	if err != nil {
		server.Close()
	}
	return clientTLS.ConnectionState(), errors.Join(err, <-done)
}

func TestCertificateReloadAndOCSPImmutableHandshakes(t *testing.T) {
	var staple atomic.Value
	staple.Store([]byte("first-staple"))
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(staple.Load().([]byte)) }))
	defer endpoint.Close()
	issuer, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	leaf := func() *Certificate {
		ct, _ := cert.MustGenerate(issuer, cert.CommonName("fixture.invalid"), cert.DNSNames("fixture.invalid"), func(c *x509.Certificate) { c.OCSPServer = []string{endpoint.URL} })
		entry := ParseCertificate(ct)
		issuerPEM, _ := issuer.ToPEM()
		entry.Certificate = append(entry.Certificate, issuerPEM...)
		return entry
	}
	entry, replacement := leaf(), leaf()
	originalPEM, originalKey := bytes.Clone(entry.Certificate), bytes.Clone(entry.Key)
	directory := t.TempDir()
	entry.CertificatePath, entry.KeyPath, entry.OcspStapling = filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem"), 1
	write := func(certificate, key []byte) {
		t.Helper()
		if err := os.WriteFile(entry.CertificatePath, certificate, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry.KeyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(entry.Certificate, entry.Key)
	other, _ := cert.MustGenerate(issuer, cert.CommonName("second.invalid"), cert.DNSNames("second.invalid"))
	config := &Config{Certificate: []*Certificate{entry, ParseCertificate(other)}, RejectUnknownSni: true}
	snapshot := config.BuildCertificates()
	// Independent native configs share one immutable protobuf input.
	native := []*gotls.Config{config.GetTLSConfig(), config.GetTLSConfig()}
	defer func() {
		for _, c := range native {
			CloseConfig(c)
		}
	}()
	wait := func(predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for !predicate() {
			if time.Now().After(deadline) {
				t.Fatal("native certificate update did not arrive")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	selected := func(c *gotls.Config) *gotls.Certificate {
		t.Helper()
		p, err := c.GetCertificate(&gotls.ClientHelloInfo{ServerName: "fixture.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	wait(func() bool {
		return bytes.Equal(selected(native[0]).OCSPStaple, []byte("first-staple")) && bytes.Equal(selected(native[1]).OCSPStaple, []byte("first-staple"))
	})
	old := selected(native[0])
	stop := make(chan struct{})
	var workers sync.WaitGroup
	for _, c := range native {
		for _, version := range []uint16{gotls.VersionTLS12, gotls.VersionTLS13} {
			workers.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := reloadHandshake(c, "fixture.invalid", version); err != nil {
						t.Error(err)
						return
					}
				}
			})
		}
	}
	defer func() { close(stop); workers.Wait() }()
	write([]byte("invalid certificate"), replacement.Key)
	time.Sleep(1100 * time.Millisecond) // Native one-second refresh, with concurrent handshakes.
	if !bytes.Equal(selected(native[0]).Certificate[0], old.Certificate[0]) {
		t.Fatal("invalid reload replaced last valid certificate")
	}
	staple.Store([]byte("second-staple"))
	write(replacement.Certificate, replacement.Key)
	wait(func() bool {
		for _, c := range native {
			p := selected(c)
			if bytes.Equal(p.Certificate[0], old.Certificate[0]) || !bytes.Equal(p.OCSPStaple, []byte("second-staple")) {
				return false
			}
		}
		return true
	})
	for _, c := range native {
		for _, version := range []uint16{gotls.VersionTLS12, gotls.VersionTLS13} {
			state, err := reloadHandshake(c, "fixture.invalid", version)
			if err != nil || !bytes.Equal(state.OCSPResponse, []byte("second-staple")) || !bytes.Equal(state.PeerCertificates[0].Raw, selected(c).Certificate[0]) {
				t.Fatalf("published handshake: %v", err)
			}
		}
		if _, err := c.GetCertificate(&gotls.ClientHelloInfo{ServerName: "second.invalid"}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.GetCertificate(&gotls.ClientHelloInfo{ServerName: "unknown.invalid"}); err == nil {
			t.Fatal("unknown SNI accepted")
		}
	}
	if !bytes.Equal(old.OCSPStaple, []byte("first-staple")) || snapshot[0].OCSPStaple != nil || !bytes.Equal(snapshot[0].Certificate[0], old.Certificate[0]) {
		t.Fatal("previously returned certificate was mutated")
	}
	if !bytes.Equal(entry.Certificate, originalPEM) || !bytes.Equal(entry.Key, originalKey) {
		t.Fatal("shared protobuf input was mutated")
	}
}

func TestCertificateIssuanceConcurrentNativeHandshakes(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	entry := ParseCertificate(ca)
	entry.Usage = Certificate_AUTHORITY_ISSUE
	config := (&Config{Certificate: []*Certificate{entry}}).GetTLSConfig()
	defer CloseConfig(config)
	first, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "first.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for _, name := range []string{"first.invalid", "second.invalid", "third.invalid", ""} {
		workers.Go(func() {
			for range 8 {
				state, err := reloadHandshake(config.Clone(), name, gotls.VersionTLS13)
				if err != nil {
					t.Error(err)
					return
				}
				if name == "" && !bytes.Equal(state.PeerCertificates[0].Raw, first.Certificate[0]) {
					t.Error("empty-SNI first-certificate behavior changed")
				}
			}
		})
	}
	workers.Wait()
	if len(config.Certificates) != 0 || len(config.NameToCertificate) != 0 {
		t.Fatal("callback mutated native TLS transport fields")
	}
	cached, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "first.invalid"})
	if err != nil || !bytes.Equal(cached.Certificate[0], first.Certificate[0]) {
		t.Fatalf("private cache hit changed certificate: %v", err)
	}
}

func TestCertificateIssuanceColdSameDomain(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	entry := ParseCertificate(ca)
	entry.Usage = Certificate_AUTHORITY_ISSUE
	config := (&Config{Certificate: []*Certificate{entry}}).GetTLSConfig()
	defer CloseConfig(config)
	start := make(chan struct{})
	results := make(chan *gotls.Certificate, 16)
	var workers sync.WaitGroup
	for range cap(results) {
		workers.Go(func() {
			<-start
			p, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "cold.invalid"})
			if err != nil {
				t.Error(err)
			}
			results <- p
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var first *gotls.Certificate
	for p := range results {
		if p == nil {
			t.Fatal("cold issuance returned no certificate")
		}
		if first == nil {
			first = p
		}
		if p != first {
			t.Fatal("same-domain cold requests did not share one published certificate")
		}
	}
	if config.NameToCertificate != nil || len(config.Certificates) != 0 {
		t.Fatal("cold issuance published transport state")
	}
}

func TestCertificateIssuanceCustomizedCloneFallback(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	entry := ParseCertificate(ca)
	entry.Usage = Certificate_AUTHORITY_ISSUE
	config := (&Config{Certificate: []*Certificate{entry}}).GetTLSConfig()
	defer CloseConfig(config)
	a, _ := cert.MustGenerate(nil, cert.CommonName("static-a.invalid"), cert.DNSNames("static-a.invalid"))
	b, _ := cert.MustGenerate(nil, cert.CommonName("static-b.invalid"), cert.DNSNames("static-b.invalid"))
	static := (&Config{Certificate: []*Certificate{ParseCertificate(a), ParseCertificate(b)}}).BuildCertificates()
	clone := config.Clone()
	clone.Certificates = []gotls.Certificate{*static[0], *static[1]} // Customize before first use.
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := range 32 {
			if _, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: fmt.Sprintf("issued-%d.invalid", i)}); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Go(func() {
		for range 32 {
			state, err := reloadHandshake(clone, "", gotls.VersionTLS12)
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(state.PeerCertificates[0].Raw, static[0].Certificate[0]) {
				t.Error("customized clone lost static empty-SNI fallback")
			}
		}
	})
	workers.Wait()
	if config.NameToCertificate != nil || clone.NameToCertificate != nil {
		t.Fatal("issuance mutated shared public map")
	}
}

func TestCertificateIssuanceExpiredPrivateCache(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	entry := ParseCertificate(ca)
	entry.Usage = Certificate_AUTHORITY_ISSUE
	expired, _ := cert.MustGenerate(ca, cert.CommonName("expired.invalid"), cert.DNSNames("expired.invalid"), cert.NotAfter(time.Now().Add(-time.Minute)))
	initial := (&Config{Certificate: []*Certificate{ParseCertificate(expired)}}).BuildCertificates()[0]
	config := (&Config{Certificate: []*Certificate{entry}}).GetTLSConfig(func(c *gotls.Config) { c.Certificates = []gotls.Certificate{*initial}; c.BuildNameToCertificate() })
	state, err := reloadHandshake(config, "expired.invalid", gotls.VersionTLS13)
	if err != nil || bytes.Equal(state.PeerCertificates[0].Raw, initial.Certificate[0]) || !state.PeerCertificates[0].NotAfter.After(time.Now()) {
		t.Fatalf("expired private entry not replaced: %v", err)
	}
	cached, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "expired.invalid"})
	if err != nil || !bytes.Equal(cached.Certificate[0], state.PeerCertificates[0].Raw) {
		t.Fatalf("replacement not cached: %v", err)
	}
	if config.NameToCertificate["expired.invalid"] != &config.Certificates[0] || !bytes.Equal(config.Certificates[0].Certificate[0], initial.Certificate[0]) {
		t.Fatal("expiry mutated public static options")
	}
}

func TestCertificateIssuancePreservesStaticOptionFallback(t *testing.T) {
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	entry := ParseCertificate(ca)
	entry.Usage = Certificate_AUTHORITY_ISSUE
	a, _ := cert.MustGenerate(nil, cert.CommonName("static-a.invalid"), cert.DNSNames("static-san.invalid"))
	b, _ := cert.MustGenerate(nil, cert.CommonName("static-b.invalid"), cert.DNSNames("static-b.invalid"))
	static := (&Config{Certificate: []*Certificate{ParseCertificate(a), ParseCertificate(b)}}).BuildCertificates()
	config := (&Config{Certificate: []*Certificate{entry}}).GetTLSConfig(func(c *gotls.Config) {
		c.Certificates = []gotls.Certificate{*static[0], *static[1]}
		c.BuildNameToCertificate()
	})
	var workers sync.WaitGroup
	for _, name := range []string{"", "issued.invalid"} {
		workers.Go(func() {
			for range 8 {
				state, err := reloadHandshake(config, name, gotls.VersionTLS12)
				if err != nil {
					t.Error(err)
					return
				}
				if name == "" && !bytes.Equal(state.PeerCertificates[0].Raw, static[0].Certificate[0]) {
					t.Error("static fallback changed")
				}
			}
		})
	}
	workers.Wait()
	if _, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "static-a.invalid"}); err != nil {
		t.Fatal(err)
	}
	state, err := reloadHandshake(config, "static-san.invalid", gotls.VersionTLS12)
	if err != nil || !bytes.Equal(state.PeerCertificates[0].Raw, static[0].Certificate[0]) {
		t.Fatalf("CA issuance removed static SAN selection: %v", err)
	}
	if len(config.Certificates) != 2 || config.NameToCertificate["issued.invalid"] != nil {
		t.Fatal("static option fallback map mutated")
	}
}

func TestCertificateAuthorityReloadKeepsSharedInputAndIssuedFacts(t *testing.T) {
	firstCA, _ := cert.MustGenerate(nil, cert.Authority(true), cert.CommonName("first CA"), cert.KeyUsage(x509.KeyUsageCertSign))
	nextCA, _ := cert.MustGenerate(nil, cert.Authority(true), cert.CommonName("next CA"), cert.KeyUsage(x509.KeyUsageCertSign))
	entry := ParseCertificate(firstCA)
	entry.Usage, entry.OcspStapling = Certificate_AUTHORITY_ISSUE, 1
	dir := t.TempDir()
	entry.CertificatePath, entry.KeyPath = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	write := func(certificate *cert.Certificate) {
		t.Helper()
		pem, key := certificate.ToPEM()
		if err := os.WriteFile(entry.CertificatePath, pem, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry.KeyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(firstCA)
	config := &Config{Certificate: []*Certificate{entry}}
	native := []*gotls.Config{config.GetTLSConfig(), config.GetTLSConfig()}
	defer func() {
		for _, c := range native {
			CloseConfig(c)
		}
	}()
	old, err := native[0].GetCertificate(&gotls.ClientHelloInfo{ServerName: "old.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	oldIssuer := bytes.Clone(old.Leaf.RawIssuer)
	write(nextCA)
	expected, err := x509.ParseCertificate(nextCA.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for attempt := 0; ; attempt++ {
		updated := true
		for _, c := range native {
			state, err := reloadHandshake(c, fmt.Sprintf("fresh-%d.invalid", attempt), gotls.VersionTLS13)
			if err != nil {
				t.Fatal(err)
			}
			updated = updated && bytes.Equal(state.PeerCertificates[0].RawIssuer, expected.RawSubject)
		}
		if updated {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("CA reload did not reach native handshake")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !bytes.Equal(old.Leaf.RawIssuer, oldIssuer) {
		t.Fatal("existing issued certificate changed")
	}
	pem, key := firstCA.ToPEM()
	if !bytes.Equal(entry.Certificate, pem) || !bytes.Equal(entry.Key, key) {
		t.Fatal("CA reload mutated shared input")
	}
}
