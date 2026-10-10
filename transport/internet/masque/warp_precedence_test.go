package masque

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestWarpVerifierPrecedence(t *testing.T) {
	key, privateKey := newWarpKey(t)
	server, publicKey, _ := warpServerTLS(t, &key.PublicKey, "h3")
	_, otherKey, _ := warpServerTLS(t, &key.PublicKey, "h3")
	raw := server.Certificates[0].Certificate
	for _, tc := range []struct {
		name            string
		key             []byte
		verifier        bool
		wantSetupError  bool
		wantVerifyError bool
	}{
		{"matching key", publicKey, false, false, false},
		{"wrong key", otherKey, false, false, true},
		{"missing key", nil, false, true, false},
		{"malformed key", []byte("invalid"), false, true, false},
		{"verifier overrides wrong key", otherKey, true, false, false},
		{"verifier overrides absent key", nil, true, false, false},
		{"verifier overrides malformed key", []byte("invalid"), true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &tls.Config{InsecureSkipVerify: tc.verifier}
			denied := errors.New("configured verifier rejected peer")
			var reject bool
			calls := 0
			if tc.verifier {
				config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
					calls++
					if reject {
						return denied
					}
					return nil
				}
			}
			err := useWarp(&Config{Warp: &Warp{PrivateKey: privateKey, PublicKey: tc.key}}, config)
			if (err != nil) != tc.wantSetupError {
				t.Fatalf("setup: %v", err)
			}
			if err != nil {
				return
			}
			if err := config.VerifyPeerCertificate(raw, nil); (err != nil) != tc.wantVerifyError {
				t.Fatalf("verification: %v", err)
			}
			if tc.verifier {
				reject = true
				if err := config.VerifyPeerCertificate(raw, nil); !errors.Is(err, denied) || calls != 2 {
					t.Fatalf("configured verifier bypassed: calls=%d error=%v", calls, err)
				}
			} else {
				for _, invalid := range [][][]byte{nil, {[]byte("invalid")}} {
					if config.VerifyPeerCertificate(invalid, nil) == nil {
						t.Fatal("invalid chain accepted")
					}
				}
			}
			identity, err := config.GetClientCertificate(&tls.CertificateRequestInfo{})
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(identity.Certificate[0])
			if err != nil || !key.PublicKey.Equal(leaf.PublicKey) {
				t.Fatalf("client identity: %v", err)
			}
		})
	}
}

func TestWarpConfiguredPinAndNameVerification(t *testing.T) {
	key, privateKey := newWarpKey(t)
	server, publicKey, pin := warpServerTLS(t, &key.PublicKey, "h3")
	_, otherKey, _ := warpServerTLS(t, &key.PublicKey, "h3")
	raw := server.Certificates[0].Certificate
	root := &xraytls.Certificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw[0]}), Usage: xraytls.Certificate_AUTHORITY_VERIFY}
	for _, tc := range []struct {
		name      string
		pin       []byte
		names     []string
		trusted   bool
		key       []byte
		wantError bool
	}{
		{"valid pin ignores wrong key", pin, nil, false, otherKey, false},
		{"valid pin ignores missing key", pin, nil, false, nil, false},
		{"valid pin ignores malformed key", pin, nil, false, []byte("invalid"), false},
		{"invalid pin overrides valid key", make([]byte, 32), nil, false, publicKey, true},
		{"trusted name ignores wrong key", nil, []string{"localhost"}, true, otherKey, false},
		{"wrong name rejects valid key", nil, []string{"wrong.invalid"}, true, publicKey, true},
		{"untrusted name rejects valid key", nil, []string{"localhost"}, false, publicKey, true},
		{"leaf pin retains native name precedence", pin, []string{"wrong.invalid"}, false, otherKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := &xraytls.Config{DisableSystemRoot: true, VerifyPeerCertByName: tc.names}
			if tc.pin != nil {
				settings.PinnedPeerCertSha256 = [][]byte{tc.pin}
			}
			if tc.trusted {
				settings.Certificate = []*xraytls.Certificate{root}
			}
			config := settings.GetTLSConfig(xraytls.WithClient())
			defer xraytls.CloseConfig(config)
			if err := useWarp(&Config{Warp: &Warp{PrivateKey: privateKey, PublicKey: tc.key}}, config); err != nil {
				t.Fatal(err)
			}
			if err := config.VerifyPeerCertificate(raw, nil); (err != nil) != tc.wantError {
				t.Fatalf("verification: %v", err)
			}
		})
	}
}
