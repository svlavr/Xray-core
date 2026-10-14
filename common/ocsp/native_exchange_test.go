package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xocsp "golang.org/x/crypto/ocsp"
)

func TestNativeOCSPExchangeAndFileStaple(t *testing.T) {
	issuer, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	issuerCert, err := x509.ParseCertificate(issuer.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var response []byte
	var leafCert *x509.Certificate
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
			t.Error("native OCSP request changed")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		request, err := xocsp.ParseRequest(data)
		if err != nil || request.SerialNumber.Cmp(leafCert.SerialNumber) != 0 {
			t.Errorf("native OCSP serial: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
	t.Cleanup(responder.Close)
	leaf, _ := cert.MustGenerate(issuer, cert.CommonName("ocsp-native.local"), func(c *x509.Certificate) { c.OCSPServer = []string{responder.URL} })
	leafCert, err = x509.ParseCertificate(leaf.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	response, err = xocsp.CreateResponse(issuerCert, issuerCert, xocsp.Response{Status: xocsp.Good, SerialNumber: leafCert.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{leaf.Certificate, issuer.Certificate}
	got, err := GetOCSPForCert(chain)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("native OCSP exchange: %v", err)
	}
	if parsed, err := xocsp.ParseResponseForCert(got, leafCert, issuerCert); err != nil || parsed.Status != xocsp.Good {
		t.Fatalf("signed native staple: %v", err)
	}
	path := filepath.Join(t.TempDir(), "staple")
	got, err = GetOCSPStapling(chain, path)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("native staple write: %v", err)
	}
	if got, err := GetOCSPForFile(path); err != nil || !bytes.Equal(got, response) {
		t.Fatalf("native staple file: %v", err)
	}
}
