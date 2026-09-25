package tls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

var globalSessionCache = tls.NewLRUClientSessionCache(128)

// ParseCertificate converts a cert.Certificate to Certificate.
func ParseCertificate(c *cert.Certificate) *Certificate {
	if c != nil {
		certPEM, keyPEM := c.ToPEM()
		return &Certificate{
			Certificate: certPEM,
			Key:         keyPEM,
		}
	}
	return nil
}

func (c *Config) loadSelfCertPool() (*x509.CertPool, error) {
	root := x509.NewCertPool()
	for _, cert := range c.Certificate {
		if !root.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("failed to append cert").AtWarning()
		}
	}
	return root, nil
}

type certificateSet struct {
	access sync.RWMutex
	certs  []*tls.Certificate
}

func (s *certificateSet) append(cert *tls.Certificate) int {
	s.access.Lock()
	defer s.access.Unlock()
	s.certs = append(s.certs, cert)
	return len(s.certs) - 1
}

func (s *certificateSet) load(index int) *tls.Certificate {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.certs[index]
}

func (s *certificateSet) replace(index int, cert *tls.Certificate) {
	s.access.Lock()
	s.certs[index] = cert
	s.access.Unlock()
}

func (s *certificateSet) snapshot() []*tls.Certificate {
	s.access.RLock()
	defer s.access.RUnlock()
	return slices.Clone(s.certs)
}

func cloneCertificateConfig(entry *Certificate) *Certificate {
	return proto.Clone(entry).(*Certificate)
}

func parseCertificateEntry(entry *Certificate) *tls.Certificate {
	keyPair, err := tls.X509KeyPair(entry.Certificate, entry.Key)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid X509 key pair")
		return nil
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid certificate")
		return nil
	}
	return &keyPair
}

func withOCSPStaple(cert *tls.Certificate, staple []byte) *tls.Certificate {
	cloned := *cert
	cloned.OCSPStaple = slices.Clone(staple)
	return &cloned
}

func (c *Config) buildCertificateSet(watch bool) *certificateSet {
	set := new(certificateSet)
	for _, source := range c.Certificate {
		entry := cloneCertificateConfig(source)
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		keyPair := parseCertificateEntry(entry)
		if keyPair == nil {
			continue
		}
		index := set.append(keyPair)
		if !watch {
			continue
		}
		setupOcspTicker(entry, func(isReloaded, isOcspstapling bool) {
			current := set.load(index)
			next := current
			if isReloaded {
				if newKeyPair := parseCertificateEntry(entry); newKeyPair != nil {
					next = newKeyPair
				} else {
					return
				}
			}
			if isOcspstapling {
				if newOCSPData, err := ocsp.GetOCSPForCert(next.Certificate); err != nil {
					errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
				} else if !slices.Equal(newOCSPData, next.OCSPStaple) {
					next = withOCSPStaple(next, newOCSPData)
				}
			}
			if next != current {
				set.replace(index, next)
			}
		})
	}
	return set
}

// BuildCertificates returns an immutable point-in-time snapshot. GetTLSConfig
// owns the live reload selector used by server handshakes.
func (c *Config) BuildCertificates() []*tls.Certificate {
	return c.buildCertificateSet(false).snapshot()
}

func setupOcspTicker(entry *Certificate, callback func(isReloaded, isOcspstapling bool)) {
	hasReloadPaths := entry.CertificatePath != "" && entry.KeyPath != ""
	if entry.OneTimeLoading || !hasReloadPaths && entry.OcspStapling == 0 {
		return
	}
	go func() {
		var isOcspstapling bool
		hotReloadCertInterval := uint64(3600)
		if entry.OcspStapling != 0 {
			hotReloadCertInterval = entry.OcspStapling
			isOcspstapling = true
		}
		t := time.NewTicker(time.Duration(hotReloadCertInterval) * time.Second)
		defer t.Stop()
		for {
			var isReloaded bool
			if hasReloadPaths {
				newCert, err := filesystem.ReadCert(entry.CertificatePath)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "failed to parse certificate")
					return
				}
				newKey, err := filesystem.ReadCert(entry.KeyPath)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "failed to parse key")
					return
				}
				if string(newCert) != string(entry.Certificate) || string(newKey) != string(entry.Key) {
					entry.Certificate = newCert
					entry.Key = newKey
					isReloaded = true
				}
			}
			callback(isReloaded, isOcspstapling)
			<-t.C
		}
	}()
}

func isCertificateExpired(c *tls.Certificate) bool {
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return leaf != nil && leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
}

func issueCertificate(rawCA *Certificate, domain string) (*tls.Certificate, error) {
	parent, err := cert.ParseCertificate(rawCA.Certificate, rawCA.Key)
	if err != nil {
		return nil, errors.New("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, errors.New("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	if rawCA.BuildChain {
		newCertPEM = bytes.Join([][]byte{newCertPEM, rawCA.Certificate}, []byte("\n"))
	}
	issued, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	if err != nil {
		return nil, err
	}
	issued.Leaf, err = x509.ParseCertificate(issued.Certificate[0])
	if err != nil {
		return nil, errors.New("failed to parse new certificate for ", domain).Base(err)
	}
	return &issued, nil
}

type certificateAuthoritySet struct {
	access sync.RWMutex
	certs  []*Certificate
}

func (s *certificateAuthoritySet) append(cert *Certificate) int {
	s.access.Lock()
	defer s.access.Unlock()
	s.certs = append(s.certs, cert)
	return len(s.certs) - 1
}

func (s *certificateAuthoritySet) replace(index int, cert *Certificate) {
	s.access.Lock()
	s.certs[index] = cert
	s.access.Unlock()
}

func (s *certificateAuthoritySet) snapshot() []*Certificate {
	s.access.RLock()
	defer s.access.RUnlock()
	return slices.Clone(s.certs)
}

func (s *certificateAuthoritySet) len() int {
	s.access.RLock()
	defer s.access.RUnlock()
	return len(s.certs)
}

func (c *Config) getCustomCA() *certificateAuthoritySet {
	set := new(certificateAuthoritySet)
	for _, source := range c.Certificate {
		if source.Usage != Certificate_AUTHORITY_ISSUE {
			continue
		}
		entry := cloneCertificateConfig(source)
		index := set.append(cloneCertificateConfig(entry))
		setupOcspTicker(entry, func(isReloaded, _ bool) {
			if isReloaded {
				set.replace(index, cloneCertificateConfig(entry))
			}
		})
	}
	return set
}

type issuedCertificateCache struct {
	access sync.Mutex
	byName map[string]*tls.Certificate
}

func (c *issuedCertificateCache) getOrIssue(domain string, authorities []*Certificate) (*tls.Certificate, error) {
	c.access.Lock()
	if c.byName == nil {
		c.byName = make(map[string]*tls.Certificate)
	}
	if cached := c.byName[domain]; cached != nil {
		if !isCertificateExpired(cached) {
			c.access.Unlock()
			return cached, nil
		}
		expTime := cached.Leaf.NotAfter.Format(time.RFC3339)
		errors.LogInfo(context.Background(), "old certificate for ", domain, " (expire on ", expTime, ") discarded")
		for name, certificate := range c.byName {
			if isCertificateExpired(certificate) {
				delete(c.byName, name)
			}
		}
	}
	c.access.Unlock()

	// Key generation must not hold up unrelated cached handshakes.
	for _, rawCert := range authorities {
		if rawCert.Usage != Certificate_AUTHORITY_ISSUE {
			continue
		}
		issued, err := issueCertificate(rawCert, domain)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to issue new certificate for ", domain)
			continue
		}
		expTime := issued.Leaf.NotAfter.Format(time.RFC3339)
		errors.LogInfo(context.Background(), "new certificate for ", domain, " (expire on ", expTime, ") issued")
		c.access.Lock()
		if cached := c.byName[domain]; cached != nil && !isCertificateExpired(cached) {
			c.access.Unlock()
			return cached, nil
		}
		c.byName[domain] = issued
		c.access.Unlock()
		return issued, nil
	}
	return nil, errors.New("failed to create a new certificate for ", domain)
}

func getGetCertificateFunc(ca *certificateAuthoritySet) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cache := new(issuedCertificateCache)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return cache.getOrIssue(hello.ServerName, ca.snapshot())
	}
}

func getNewGetCertificateFunc(certs *certificateSet, rejectUnknownSNI bool) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certs.access.RLock()
		defer certs.access.RUnlock()
		if len(certs.certs) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
		if !rejectUnknownSNI && (len(certs.certs) == 1 || sni == "") {
			return certs.certs[0], nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, keyPair := range certs.certs {
			if keyPair.Leaf.Subject.CommonName == sni || keyPair.Leaf.Subject.CommonName == gsni {
				return keyPair, nil
			}
			for _, name := range keyPair.Leaf.DNSNames {
				if name == sni || name == gsni {
					return keyPair, nil
				}
			}
		}
		if rejectUnknownSNI {
			return nil, errNoCertificates
		}
		return certs.certs[0], nil
	}
}

func (c *Config) parseServerName() string {
	if IsFromMitm(c.ServerName) {
		return ""
	}
	return c.ServerName
}

func (r *RandCarrier) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
	// extract x509 certificates from rawCerts (verifiedChains will be nil if InsecureSkipVerify is true)
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		certs[i], _ = x509.ParseCertificate(asn1Data)
	}
	if len(certs) == 0 {
		return errors.New("unexpected certs")
	}

	// directly return success if pinned cert is leaf
	// or replace RootCAs if pinned cert is CA (and can be used in VerifyPeerCertByName)
	CAs := r.RootCAs
	var verifyResult verifyResult
	var verifiedCert *x509.Certificate
	if r.PinnedPeerCertSha256 != nil {
		verifyResult, verifiedCert = verifyChain(certs, r.PinnedPeerCertSha256)
		switch verifyResult {
		case certNotFound:
			return errors.New("peer cert is unrecognized (against pinnedPeerCertSha256)")
		case foundLeaf:
			return nil
		case foundCA:
			CAs = x509.NewCertPool()
			CAs.AddCert(verifiedCert)
		default:
			panic("impossible pinnedPeerCertSha256 verify result")
		}
	}

	if r.VerifyPeerCertByName != nil { // RAW's Dial() may make it empty but not nil
		opts := x509.VerifyOptions{
			Roots:         CAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		for _, opts.DNSName = range r.VerifyPeerCertByName {
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}
		}
		if verifyResult == foundCA {
			errors.New("peer cert is invalid (against pinned CA and verifyPeerCertByName)")
		}
		return errors.New("peer cert is invalid (against root CAs and verifyPeerCertByName)")
	}

	if verifyResult == foundCA { // if found CA, we need to verify here
		if len(r.Config.ServerName) == 0 {
			return errors.New("Pinning CA needs a valid ServerName")
		}
		opts := x509.VerifyOptions{
			Roots:         CAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			DNSName:       r.Config.ServerName,
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := certs[0].Verify(opts); err == nil {
			return nil
		}
		return errors.New("peer cert is invalid (against pinned CA and serverName)")
	}

	return nil // r.PinnedPeerCertSha256==nil && r.verifyPeerCertByName==nil
}

type RandCarrier struct {
	Config               *tls.Config
	RootCAs              *x509.CertPool
	VerifyPeerCertByName []string
	PinnedPeerCertSha256 [][]byte
}

func (r *RandCarrier) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// GetTLSConfig converts this Config into tls.Config.
func (c *Config) GetTLSConfig(opts ...Option) *tls.Config {
	root, err := c.getCertPool()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to load system root certificate")
	}

	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			SessionTicketsDisabled: true,
		}
	}

	randCarrier := &RandCarrier{
		RootCAs:              root,
		VerifyPeerCertByName: slices.Clone(c.VerifyPeerCertByName),
		PinnedPeerCertSha256: c.PinnedPeerCertSha256,
	}
	config := &tls.Config{
		Rand:                   randCarrier,
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		NextProtos:             slices.Clone(c.NextProtocol),
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyPeerCertificate:  randCarrier.verifyPeerCert,
	}
	randCarrier.Config = config
	if len(c.VerifyPeerCertByName) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.VerifyPeerCertByName = nil
	}
	if len(c.PinnedPeerCertSha256) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.PinnedPeerCertSha256 = nil
	}

	for _, opt := range opts {
		opt(config)
	}

	caCerts := c.getCustomCA()
	if caCerts.len() > 0 {
		config.GetCertificate = getGetCertificateFunc(caCerts)
	} else {
		config.GetCertificate = getNewGetCertificateFunc(c.buildCertificateSet(true), c.RejectUnknownSni)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(c.CurvePreferences) > 0 {
		config.CurvePreferences = ParseCurveName(c.CurvePreferences)
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	switch c.MinVersion {
	case "1.0":
		config.MinVersion = tls.VersionTLS10
	case "1.1":
		config.MinVersion = tls.VersionTLS11
	case "1.2":
		config.MinVersion = tls.VersionTLS12
	case "1.3":
		config.MinVersion = tls.VersionTLS13
	}

	switch c.MaxVersion {
	case "1.0":
		config.MaxVersion = tls.VersionTLS10
	case "1.1":
		config.MaxVersion = tls.VersionTLS11
	case "1.2":
		config.MaxVersion = tls.VersionTLS12
	case "1.3":
		config.MaxVersion = tls.VersionTLS13
	}

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range tls.CipherSuites() {
			id[s.Name] = s.ID
		}
		for _, s := range tls.InsecureCipherSuites() {
			id[s.Name] = s.ID
		}
		for n := range strings.SplitSeq(c.CipherSuites, ":") {
			n = strings.TrimSpace(n)
			if v, ok := id[n]; ok {
				config.CipherSuites = append(config.CipherSuites, v)
			}
		}
	}

	if len(c.MasterKeyLog) > 0 && c.MasterKeyLog != "none" {
		writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
		} else {
			config.KeyLogWriter = writer
		}
	}
	if len(c.EchConfigList) > 0 || len(c.EchServerKeys) > 0 {
		err := ApplyECH(c, config)
		if err != nil {
			errors.LogError(context.Background(), err)
		}
	}

	return config
}

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
// Due to the incorrect structure of GetTLSConfig(), the config.ServerName will always be empty.
// So the real logic for SNI is:
// set it to dest -> overwrite it with servername(if it's len>0).
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if config.ServerName == "" {
			config.ServerName = dest.Address.String()
		}
	}
}

func WithOverrideName(serverName string) Option {
	return func(config *tls.Config) {
		config.ServerName = serverName
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}

// ConfigFromStreamSettings fetches Config from stream settings. Nil if not found.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

func ParseCurveName(curveNames []string) []tls.CurveID {
	curveMap := map[string]tls.CurveID{
		"curvep256":          tls.CurveP256,
		"curvep384":          tls.CurveP384,
		"curvep521":          tls.CurveP521,
		"x25519":             tls.X25519,
		"x25519mlkem768":     tls.X25519MLKEM768,
		"secp256r1mlkem768":  tls.SecP256r1MLKEM768,
		"secp384r1mlkem1024": tls.SecP384r1MLKEM1024,
	}

	var curveIDs []tls.CurveID
	for _, name := range curveNames {
		if curveID, ok := curveMap[strings.ToLower(name)]; ok {
			curveIDs = append(curveIDs, curveID)
		} else {
			errors.LogWarning(context.Background(), "unsupported curve name: "+name)
		}
	}
	return curveIDs
}

func IsFromMitm(str string) bool {
	return strings.ToLower(str) == "frommitm"
}

type verifyResult int

const (
	certNotFound verifyResult = iota
	foundLeaf
	foundCA
)

func verifyChain(certs []*x509.Certificate, pinnedPeerCertSha256 [][]byte) (verifyResult, *x509.Certificate) {
	leafHash := GenerateCertHash(certs[0])
	for _, c := range pinnedPeerCertSha256 {
		if hmac.Equal(leafHash, c) {
			return foundLeaf, nil
		}
	}
	certs = certs[1:] // skip leaf
	for _, cert := range certs {
		certHash := GenerateCertHash(cert)
		for _, c := range pinnedPeerCertSha256 {
			if hmac.Equal(certHash, c) {
				if cert.IsCA {
					return foundCA, cert
				}
			}
		}
	}
	return certNotFound, nil
}
