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
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	globalSessionCache = tls.NewLRUClientSessionCache(128)
	configLifecycles   sync.Map
)

type configLifecycleKey struct {
	ownerID uint64
	config  *Config
}

type configLifecycle struct {
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	tasks             task.Lifecycle
	sealed            bool
	files             map[*os.File]struct{}
	key               configLifecycleKey
	unregister        func()
	materialOnce      sync.Once
	sourceAccess      *sync.RWMutex
	certificates      []*tls.Certificate
	certificateAccess *sync.RWMutex
	customCA          []*Certificate
	customCAAccess    *sync.RWMutex
	keyLogOnce        sync.Once
	keyLogWriter      *os.File
	closeOnce         sync.Once
	closeDone         chan struct{}
	closeErr          error
}

func newConfigLifecycle(ctx context.Context, config *Config) *configLifecycle {
	owner := internet.ResourceLifecycleFromContext(ctx)
	if owner == nil {
		return nil
	}
	key := configLifecycleKey{ownerID: owner.ID(), config: config}
	if existing, ok := configLifecycles.Load(key); ok {
		return existing.(*configLifecycle)
	}
	resourceCtx, cancel := context.WithCancel(owner.Context())
	resource := &configLifecycle{
		ctx:       resourceCtx,
		cancel:    cancel,
		files:     make(map[*os.File]struct{}),
		key:       key,
		closeDone: make(chan struct{}),
	}
	err := owner.RegisterBound(resource, func(unregister func()) {
		resource.unregister = unregister
	})
	if err != nil {
		resource.sealed = true
		resource.tasks.Seal()
		cancel()
		return resource
	}
	actual, loaded := configLifecycles.LoadOrStore(key, resource)
	if loaded {
		_ = resource.Close()
		return actual.(*configLifecycle)
	}
	resource.mu.Lock()
	publishable := !resource.sealed && resource.ctx.Err() == nil
	resource.mu.Unlock()
	if !publishable {
		configLifecycles.CompareAndDelete(key, resource)
		_ = resource.Close()
	}
	return resource
}

func (r *configLifecycle) SignalStop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.sealed {
		r.sealed = true
		r.tasks.Seal()
		r.cancel()
	}
	r.mu.Unlock()
}

func (r *configLifecycle) Close() error {
	if r == nil {
		return nil
	}
	r.SignalStop()
	r.closeOnce.Do(func() {
		r.tasks.Wait()
		r.mu.Lock()
		files := r.files
		r.files = nil
		r.mu.Unlock()
		var closeErrors []error
		for file := range files {
			if err := file.Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		configLifecycles.CompareAndDelete(r.key, r)
		if r.unregister != nil {
			r.unregister()
			r.unregister = nil
		}
		r.closeErr = errors.Combine(closeErrors...)
		close(r.closeDone)
	})
	<-r.closeDone
	return r.closeErr
}

func (r *configLifecycle) materials(config *Config) ([]*Certificate, *sync.RWMutex, []*tls.Certificate, *sync.RWMutex) {
	r.materialOnce.Do(func() {
		r.sourceAccess = new(sync.RWMutex)
		r.sourceAccess.Lock()
		r.customCA, r.customCAAccess = config.getCustomCAContext(r, r.sourceAccess)
		r.certificates, r.certificateAccess = config.buildCertificates(r, r.sourceAccess)
		r.sourceAccess.Unlock()
	})
	return r.customCA, r.customCAAccess, r.certificates, r.certificateAccess
}

func (r *configLifecycle) keyLog(path string) *os.File {
	r.keyLogOnce.Do(func() {
		writer, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to open ", path, " as master key log")
			return
		}
		if r.adoptFile(writer) {
			r.keyLogWriter = writer
		}
	})
	return r.keyLogWriter
}

func (r *configLifecycle) adoptFile(file *os.File) bool {
	if r == nil || file == nil {
		return r == nil
	}
	r.mu.Lock()
	if r.sealed || r.ctx.Err() != nil || r.files == nil {
		r.mu.Unlock()
		_ = file.Close()
		return false
	}
	r.files[file] = struct{}{}
	r.mu.Unlock()
	return true
}

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

// BuildCertificates builds a list of TLS certificates from proto definition.
func (c *Config) BuildCertificates() []*tls.Certificate {
	certificates, _ := c.buildCertificates(nil, nil)
	return certificates
}

func (c *Config) buildCertificates(lifecycle *configLifecycle, access *sync.RWMutex) ([]*tls.Certificate, *sync.RWMutex) {
	certs := make([]*tls.Certificate, 0, len(c.Certificate))
	if access == nil {
		access = new(sync.RWMutex)
	}
	type reloadEntry struct {
		entry       *Certificate
		index       int
		loadKeyPair func() *tls.Certificate
	}
	var reloads []reloadEntry
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		getX509KeyPair := func() *tls.Certificate {
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
		if keyPair := getX509KeyPair(); keyPair != nil {
			certs = append(certs, keyPair)
		} else {
			continue
		}
		reloads = append(reloads, reloadEntry{entry: entry, index: len(certs) - 1, loadKeyPair: getX509KeyPair})
	}
	for _, reload := range reloads {
		entry := reload.entry
		index := reload.index
		getX509KeyPair := reload.loadKeyPair
		setupOcspTickerContext(lifecycle, entry, access, func(ctx context.Context, isReloaded, isOcspstapling bool) {
			access.RLock()
			cert := certs[index]
			if isReloaded {
				if newKeyPair := getX509KeyPair(); newKeyPair != nil {
					cert = newKeyPair
				} else {
					access.RUnlock()
					return
				}
			}
			access.RUnlock()
			if isOcspstapling {
				if newOCSPData, err := ocsp.GetOCSPForCertContext(ctx, cert.Certificate); err != nil {
					errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
				} else if string(newOCSPData) != string(cert.OCSPStaple) {
					updated := *cert
					updated.OCSPStaple = newOCSPData
					cert = &updated
				}
			}
			access.Lock()
			certs[index] = cert
			access.Unlock()
		})
	}
	return certs, access
}

func setupOcspTicker(entry *Certificate, callback func(isReloaded, isOcspstapling bool)) {
	setupOcspTickerContext(nil, entry, new(sync.RWMutex), func(_ context.Context, isReloaded, isOcspstapling bool) {
		callback(isReloaded, isOcspstapling)
	})
}

func setupOcspTickerContext(lifecycle *configLifecycle, entry *Certificate, access *sync.RWMutex, callback func(context.Context, bool, bool)) {
	if entry.OneTimeLoading {
		return
	}
	ctx := context.Background()
	if lifecycle != nil {
		if !lifecycle.tasks.Acquire() {
			return
		}
		ctx = lifecycle.ctx
	}
	go func() {
		if lifecycle != nil {
			defer lifecycle.tasks.Release()
		}
		var isOcspstapling bool
		hotReloadCertInterval := uint64(3600)
		if entry.OcspStapling != 0 {
			hotReloadCertInterval = entry.OcspStapling
			isOcspstapling = true
		}
		t := time.NewTicker(time.Duration(hotReloadCertInterval) * time.Second)
		defer t.Stop()
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			var isReloaded bool
			if entry.CertificatePath != "" && entry.KeyPath != "" {
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
				access.Lock()
				if string(newCert) != string(entry.Certificate) || string(newKey) != string(entry.Key) {
					entry.Certificate = newCert
					entry.Key = newKey
					isReloaded = true
				}
				access.Unlock()
			}
			callback(ctx, isReloaded, isOcspstapling)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func isCertificateExpired(c *tls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
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
	cert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	return &cert, err
}

func (c *Config) getCustomCA() []*Certificate {
	certificates, _ := c.getCustomCAContext(nil, nil)
	return certificates
}

func (c *Config) getCustomCAContext(lifecycle *configLifecycle, access *sync.RWMutex) ([]*Certificate, *sync.RWMutex) {
	certs := make([]*Certificate, 0, len(c.Certificate))
	if access == nil {
		access = new(sync.RWMutex)
	}
	for _, certificate := range c.Certificate {
		if certificate.Usage == Certificate_AUTHORITY_ISSUE {
			certs = append(certs, certificate)
			setupOcspTickerContext(lifecycle, certificate, access, func(context.Context, bool, bool) {})
		}
	}
	return certs, access
}

func getGetCertificateFunc(c *tls.Config, ca []*Certificate, caAccess *sync.RWMutex) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := hello.ServerName
		certExpired := false

		access.RLock()
		certificate, found := c.NameToCertificate[domain]
		access.RUnlock()

		if found {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			certExpired = true
		}

		if certExpired {
			newCerts := make([]tls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				if !isCertificateExpired(&certificate) {
					newCerts = append(newCerts, certificate)
				} else if certificate.Leaf != nil {
					expTime := certificate.Leaf.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "old certificate for ", domain, " (expire on ", expTime, ") discarded")
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *tls.Certificate

		// Create a new certificate from existing CA if possible
		for _, rawCert := range ca {
			if rawCert.Usage == Certificate_AUTHORITY_ISSUE {
				caAccess.RLock()
				newCert, err := issueCertificate(rawCert, domain)
				caAccess.RUnlock()
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to issue new certificate for ", domain)
					continue
				}
				parsed, err := x509.ParseCertificate(newCert.Certificate[0])
				if err == nil {
					newCert.Leaf = parsed
					expTime := parsed.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "new certificate for ", domain, " (expire on ", expTime, ") issued")
				} else {
					errors.LogInfoInner(context.Background(), err, "failed to parse new certificate for ", domain)
				}

				access.Lock()
				c.Certificates = append(c.Certificates, *newCert)
				issuedCertificate = &c.Certificates[len(c.Certificates)-1]
				access.Unlock()
				break
			}
		}

		if issuedCertificate == nil {
			return nil, errors.New("failed to create a new certificate for ", domain)
		}

		access.Lock()
		c.BuildNameToCertificate()
		access.Unlock()

		return issuedCertificate, nil
	}
}

func getNewGetCertificateFunc(certs []*tls.Certificate, rejectUnknownSNI bool, access *sync.RWMutex) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		access.RLock()
		defer access.RUnlock()
		if len(certs) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
		if !rejectUnknownSNI && (len(certs) == 1 || sni == "") {
			return certs[0], nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, keyPair := range certs {
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
		return certs[0], nil
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
	return c.GetTLSConfigContext(context.Background(), opts...)
}

// GetTLSConfigContext preserves the caller's Instance/config-generation
// lifecycle for ECH lookup and refresh while retaining the legacy wrapper.
func (c *Config) GetTLSConfigContext(ctx context.Context, opts ...Option) *tls.Config {
	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			SessionTicketsDisabled: true,
		}
	}
	resources := newConfigLifecycle(ctx, c)
	var caCerts []*Certificate
	var caAccess *sync.RWMutex
	var certificates []*tls.Certificate
	var certificateAccess *sync.RWMutex
	if resources != nil {
		caCerts, caAccess, certificates, certificateAccess = resources.materials(c)
		resources.sourceAccess.RLock()
	}
	root, err := c.getCertPool()
	if resources != nil {
		resources.sourceAccess.RUnlock()
	}
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to load system root certificate")
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

	if resources == nil {
		caCerts, caAccess = c.getCustomCAContext(nil, nil)
		certificates, certificateAccess = c.buildCertificates(nil, nil)
	}
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts, caAccess)
	} else {
		config.GetCertificate = getNewGetCertificateFunc(certificates, c.RejectUnknownSni, certificateAccess)
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
		if resources != nil {
			config.KeyLogWriter = resources.keyLog(c.MasterKeyLog)
		} else {
			writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
			} else {
				config.KeyLogWriter = writer
			}
		}
	}
	if len(c.EchConfigList) > 0 || len(c.EchServerKeys) > 0 {
		err := ApplyECHContext(ctx, c, config)
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
