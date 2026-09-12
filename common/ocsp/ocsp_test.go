package ocsp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	stderrors "errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetOCSPForCertContextCancelsHTTP(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	ocspEntered := make(chan struct{})
	releaseServer := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/issuer":
			_, _ = w.Write(issuerDER)
		case "/ocsp":
			close(ocspEntered)
			select {
			case <-req.Context().Done():
			case <-releaseServer:
			}
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		OCSPServer:            []string{server.URL + "/ocsp"},
		IssuingCertificateURL: []string{server.URL + "/issuer"},
		AuthorityKeyId:        issuer.SubjectKeyId,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := GetOCSPForCertContext(ctx, [][]byte{leafDER})
		done <- err
	}()
	select {
	case <-ocspEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("OCSP request did not start")
	}
	cancel()
	select {
	case err := <-done:
		close(releaseServer)
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("GetOCSPForCertContext error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		close(releaseServer)
		t.Fatal("context cancellation did not unblock OCSP HTTP")
	}
}
