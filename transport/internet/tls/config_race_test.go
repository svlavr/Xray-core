package tls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func handshakeCertificate(serverConfig *tls.Config, serverName string) (*x509.Certificate, error) {
	serverSide, clientSide := net.Pipe()
	serverSide.SetDeadline(time.Now().Add(5 * time.Second))
	clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	serverResult := make(chan error, 1)
	go func() {
		server := tls.Server(serverSide, serverConfig)
		serverResult <- server.Handshake()
		_ = serverSide.Close()
	}()

	client := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true, ServerName: serverName}) //nolint:gosec // The generated peer is asserted below.
	clientErr := client.Handshake()
	state := client.ConnectionState()
	_ = clientSide.Close()
	serverErr := <-serverResult
	if clientErr != nil {
		return nil, clientErr
	}
	if serverErr != nil {
		return nil, serverErr
	}
	if len(state.PeerCertificates) != 1 {
		return nil, fmt.Errorf("peer certificates=%d", len(state.PeerCertificates))
	}
	return state.PeerCertificates[0], nil
}

func testCertificate(t *testing.T, commonName string, names ...string) (*Certificate, *tls.Certificate) {
	t.Helper()
	generated, _ := cert.MustGenerate(nil, cert.CommonName(commonName), cert.DNSNames(names...))
	config := ParseCertificate(generated)
	parsed := parseCertificateEntry(config)
	if parsed == nil {
		t.Fatal("failed to parse generated certificate")
	}
	return config, parsed
}

func TestCertificateSetConcurrentPublish(t *testing.T) {
	_, exact := testCertificate(t, "exact.example", "exact.example")
	_, wildcard := testCertificate(t, "*.wild.example", "*.wild.example")
	set := new(certificateSet)
	set.append(exact)
	set.append(wildcard)
	selectCertificate := getNewGetCertificateFunc(set, false)
	rejectCertificate := getNewGetCertificateFunc(set, true)

	var failed atomic.Bool
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 2000 {
				selected, err := selectCertificate(&tls.ClientHelloInfo{ServerName: "EXACT.EXAMPLE"})
				if err != nil || selected.Leaf.Subject.CommonName != "exact.example" {
					failed.Store(true)
					return
				}
				selected, err = selectCertificate(&tls.ClientHelloInfo{ServerName: "node.wild.example"})
				if err != nil || selected.Leaf.Subject.CommonName != "*.wild.example" {
					failed.Store(true)
					return
				}
				selected, err = selectCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example"})
				if err != nil || selected.Leaf.Subject.CommonName != "exact.example" {
					failed.Store(true)
					return
				}
				if _, err = rejectCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example"}); !errors.Is(err, errNoCertificates) {
					failed.Store(true)
					return
				}
			}
		})
	}
	group.Go(func() {
		for i := range 2000 {
			set.replace(0, withOCSPStaple(exact, []byte{byte(i), byte(i >> 8)}))
		}
	})
	group.Wait()
	if failed.Load() {
		t.Fatal("concurrent certificate selection returned an incomplete or mismatched certificate")
	}
	if len(exact.OCSPStaple) != 0 {
		t.Fatal("published OCSP update mutated an earlier certificate snapshot")
	}
}

func TestBuildCertificatesAndCACloneConfigInput(t *testing.T) {
	entry, _ := testCertificate(t, "snapshot.example", "snapshot.example")
	config := &Config{Certificate: []*Certificate{entry}}
	snapshot := config.BuildCertificates()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot certificates=%d", len(snapshot))
	}
	snapshotDER := bytes.Clone(snapshot[0].Certificate[0])
	entry.Certificate[0] ^= 0xff
	if !bytes.Equal(snapshot[0].Certificate[0], snapshotDER) {
		t.Fatal("certificate snapshot changed with protobuf input")
	}

	caEntry, _ := testCertificate(t, "ca.example", "ca.example")
	caEntry.Usage = Certificate_AUTHORITY_ISSUE
	caConfig := &Config{Certificate: []*Certificate{caEntry}}
	caSet := caConfig.getCustomCA()
	caSnapshot := caSet.snapshot()
	if len(caSnapshot) != 1 {
		t.Fatalf("CA certificates=%d", len(caSnapshot))
	}
	caEntry.Key[0] ^= 0xff
	if caSnapshot[0].Key[0] == caEntry.Key[0] {
		t.Fatal("CA snapshot aliases mutable protobuf input")
	}
}

func TestCertificateSetPathReloadPublishesImmutableReplacement(t *testing.T) {
	oldEntry, _ := testCertificate(t, "old.example", "old.example")
	newEntry, _ := testCertificate(t, "new.example", "new.example")
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certPath, newEntry.Certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, newEntry.Key, 0o600); err != nil {
		t.Fatal(err)
	}
	oldEntry.CertificatePath, oldEntry.KeyPath = certPath, keyPath
	set := (&Config{Certificate: []*Certificate{oldEntry}}).buildCertificateSet(true)
	initial := set.load(0)
	selector := getNewGetCertificateFunc(set, false)

	var failed atomic.Bool
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				selected, err := selector(&tls.ClientHelloInfo{})
				if err != nil || selected.Leaf == nil {
					failed.Store(true)
					return
				}
				name := selected.Leaf.Subject.CommonName
				if name != "old.example" && name != "new.example" {
					failed.Store(true)
					return
				}
			}
		})
	}
	deadline := time.Now().Add(time.Second)
	for {
		selected, err := selector(&tls.ClientHelloInfo{})
		if err == nil && selected.Leaf.Subject.CommonName == "new.example" {
			break
		}
		if time.Now().After(deadline) {
			close(stop)
			readers.Wait()
			t.Fatal("certificate reload was not published")
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	readers.Wait()
	if failed.Load() {
		t.Fatal("reader observed an incomplete certificate during reload")
	}
	if initial.Leaf.Subject.CommonName != "old.example" {
		t.Fatal("reload mutated the previously published certificate")
	}
	oldEntry.Certificate[0] ^= 0xff
	if initial.Leaf.Subject.CommonName != "old.example" {
		t.Fatal("reload state aliases source protobuf")
	}
}

func TestCertificateAuthorityConcurrentHandshakesAndReload(t *testing.T) {
	firstCA, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	firstEntry := ParseCertificate(firstCA)
	firstEntry.Usage = Certificate_AUTHORITY_ISSUE
	secondCA, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	secondEntry := ParseCertificate(secondCA)
	secondEntry.Usage = Certificate_AUTHORITY_ISSUE

	authorities := new(certificateAuthoritySet)
	authorities.append(cloneCertificateConfig(firstEntry))
	serverConfig := &tls.Config{GetCertificate: getGetCertificateFunc(authorities)}

	cached, err := handshakeCertificate(serverConfig, "cached.example")
	if err != nil {
		t.Fatal(err)
	}
	firstParsed, err := x509.ParseCertificate(firstCA.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := cached.CheckSignatureFrom(firstParsed); err != nil {
		t.Fatalf("initial certificate was not issued by first CA: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 24)
	var handshakes sync.WaitGroup
	for i := range 24 {
		name := fmt.Sprintf("parallel-%d.example", i%6)
		handshakes.Go(func() {
			<-start
			_, err := handshakeCertificate(serverConfig, name)
			results <- err
		})
	}
	close(start)
	authorities.replace(0, cloneCertificateConfig(secondEntry))
	handshakes.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}

	cachedAgain, err := handshakeCertificate(serverConfig, "cached.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cached.Raw, cachedAgain.Raw) {
		t.Fatal("exact hostname cache did not retain its unexpired certificate across CA reload")
	}
	if _, err := handshakeCertificate(serverConfig, ""); err != nil {
		t.Fatalf("empty-SNI handshake after cache warm-up: %v", err)
	}
	fresh, err := handshakeCertificate(serverConfig, "fresh-after-reload.example")
	if err != nil {
		t.Fatal(err)
	}
	secondParsed, err := x509.ParseCertificate(secondCA.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.CheckSignatureFrom(secondParsed); err != nil {
		t.Fatalf("fresh certificate was not issued by reloaded CA: %v", err)
	}
	if len(serverConfig.Certificates) != 0 || serverConfig.NameToCertificate != nil {
		t.Fatal("CA issuance mutated published tls.Config certificate fields")
	}
}

func TestCertificateAuthorityPathReloadPublishesClone(t *testing.T) {
	firstCA, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	firstEntry := ParseCertificate(firstCA)
	firstEntry.Usage = Certificate_AUTHORITY_ISSUE
	secondCA, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	secondEntry := ParseCertificate(secondCA)
	secondEntry.Usage = Certificate_AUTHORITY_ISSUE
	directory := t.TempDir()
	firstEntry.CertificatePath = filepath.Join(directory, "ca.pem")
	firstEntry.KeyPath = filepath.Join(directory, "ca-key.pem")
	if err := os.WriteFile(firstEntry.CertificatePath, secondEntry.Certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstEntry.KeyPath, secondEntry.Key, 0o600); err != nil {
		t.Fatal(err)
	}

	authorities := (&Config{Certificate: []*Certificate{firstEntry}}).getCustomCA()
	deadline := time.Now().Add(time.Second)
	for !bytes.Equal(authorities.snapshot()[0].Certificate, secondEntry.Certificate) {
		if time.Now().After(deadline) {
			t.Fatal("CA path reload was not published")
		}
		time.Sleep(time.Millisecond)
	}
	if bytes.Equal(firstEntry.Certificate, secondEntry.Certificate) {
		t.Fatal("CA path reload mutated the source protobuf")
	}

	serverConfig := &tls.Config{GetCertificate: getGetCertificateFunc(authorities)}
	issued, err := handshakeCertificate(serverConfig, "path-reload.example")
	if err != nil {
		t.Fatal(err)
	}
	secondParsed, err := x509.ParseCertificate(secondCA.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := issued.CheckSignatureFrom(secondParsed); err != nil {
		t.Fatalf("path-reloaded CA did not issue the handshake certificate: %v", err)
	}
}

func TestIssuedCertificateCacheReplacesExpiredHostname(t *testing.T) {
	caCertificate, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	caEntry := ParseCertificate(caCertificate)
	caEntry.Usage = Certificate_AUTHORITY_ISSUE
	expiredCertificate, _ := cert.MustGenerate(
		caCertificate,
		cert.CommonName("expired.example"),
		cert.DNSNames("expired.example"),
		cert.NotAfter(time.Now().Add(-2*time.Minute)),
	)
	expiredPEM, expiredKey := expiredCertificate.ToPEM()
	expired, err := tls.X509KeyPair(expiredPEM, expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	expired.Leaf, err = x509.ParseCertificate(expired.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	cache := &issuedCertificateCache{byName: map[string]*tls.Certificate{"expired.example": &expired, "inactive-expired.example": &expired}}

	replacement, err := cache.getOrIssue("expired.example", []*Certificate{caEntry})
	if err != nil {
		t.Fatal(err)
	}
	if replacement == &expired || !replacement.Leaf.NotAfter.After(time.Now()) {
		t.Fatal("expired exact-host cache entry was not replaced")
	}
	if len(cache.byName) != 1 {
		t.Fatal("expiry sweep retained other expired hostname entries")
	}
}
