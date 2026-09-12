package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

type Conn struct {
	*reality.Conn
}

func (c *Conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func Server(c net.Conn, config *reality.Config) (net.Conn, error) {
	realityConn, err := reality.Server(context.Background(), c, config)
	return &Conn{Conn: realityConn}, err
}

type UConn struct {
	*utls.UConn
	Config     *Config
	ServerName string
	AuthKey    []byte
	Verified   bool
}

type invalidPeerSpiderError struct {
	err *errors.Error
}

func newInvalidPeerSpiderError() error {
	return &invalidPeerSpiderError{err: errors.New("REALITY: processed invalid connection").AtWarning()}
}

func (e *invalidPeerSpiderError) Error() string          { return e.err.Error() }
func (e *invalidPeerSpiderError) Severity() log.Severity { return e.err.Severity() }

// IsInvalidPeerSpiderError reports that the invalid-peer connection has either
// been transferred to the registered spider owner or was already closed when
// that transfer could not be made. A transport caller must not close its old
// raw alias after this error.
func IsInvalidPeerSpiderError(err error) bool {
	var target *invalidPeerSpiderError
	return goerrors.As(err, &target)
}

// spiderLifecycle owns the deliberately retained invalid-peer connection and
// every spider worker derived from it. Its one published root receipt joins
// children internally, so Close never races a WaitGroup Add.
type spiderLifecycle struct {
	conn       net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	rootDone   chan struct{}
	unregister func()
	stopOnce   sync.Once
	closeOnce  sync.Once
}

func (s *spiderLifecycle) SignalStop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		s.cancel()
		_ = s.conn.Close()
	})
}

func (s *spiderLifecycle) Close() error {
	if s == nil {
		return nil
	}
	s.SignalStop()
	<-s.rootDone
	return nil
}

func waitSpider(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *UConn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.Config.Show {
		localAddr := c.LocalAddr().String()
		fmt.Printf("REALITY localAddr: %v\tis using X25519MLKEM768 for TLS' communication: %v\n", localAddr, c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
		fmt.Printf("REALITY localAddr: %v\tis using ML-DSA-65 for cert's extra verification: %v\n", localAddr, len(c.Config.Mldsa65Verify) > 0)
	}
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if len(c.Config.Mldsa65Verify) > 0 {
				if len(certs[0].Extensions) > 0 {
					h.Write(c.HandshakeState.Hello.Raw)
					h.Write(c.HandshakeState.ServerHello.Raw)
					verify, _ := mldsa65.Scheme().UnmarshalBinaryPublicKey(c.Config.Mldsa65Verify)
					if mldsa65.Verify(verify.(*mldsa65.PublicKey), h.Sum(nil), nil, certs[0].Extensions[0].Value) {
						c.Verified = true
						return nil
					}
				}
			} else {
				c.Verified = true
				return nil
			}
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func UClient(c net.Conn, config *Config, ctx context.Context, dest net.Destination) (net.Conn, error) {
	localAddr := c.LocalAddr().String()
	uConn := &UConn{
		Config: config,
	}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		KeyLogWriter:           KeyLogWriterFromConfig(config),
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = dest.Address.String()
	}
	uConn.ServerName = utlsConfig.ServerName
	fingerprint := tls.GetFingerprint(config.Fingerprint)
	if fingerprint == nil {
		return nil, errors.New("REALITY: failed to get fingerprint").AtError()
	}
	uConn.UConn = utls.UClient(c, utlsConfig, *fingerprint)
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
		hello.SessionId[0] = core.Version_x
		hello.SessionId[1] = core.Version_y
		hello.SessionId[2] = core.Version_z
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], config.ShortId)
		if config.Show {
			fmt.Printf("REALITY localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16])
		}
		publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
		if err != nil {
			return nil, errors.New("REALITY: publicKey == nil")
		}
		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe == nil {
			return nil, errors.New("Current fingerprint ", uConn.ClientHelloID.Client, uConn.ClientHelloID.Version, " does not support TLS 1.3, REALITY handshake cannot establish.")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, errors.New("REALITY: SharedKey == nil")
		}
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
			return nil, err
		}
		aead := crypto.NewAesGcm(uConn.AuthKey)
		if config.Show {
			fmt.Printf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD: %T\n", localAddr, uConn.AuthKey[:16], aead)
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if config.Show {
		fmt.Printf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)
	}
	if !uConn.Verified {
		errors.LogError(ctx, "REALITY: received real certificate (potential MITM or redirection)")
		owner := internet.ResourceLifecycleFromContext(ctx)
		if owner == nil {
			_ = uConn.Close()
			return nil, newInvalidPeerSpiderError()
		}
		spiderCtx, cancel := context.WithCancel(owner.Context())
		spider := &spiderLifecycle{conn: uConn, ctx: spiderCtx, cancel: cancel, rootDone: make(chan struct{})}
		if err := owner.RegisterBound(spider, func(unregister func()) { spider.unregister = unregister }); err != nil {
			cancel()
			_ = uConn.Close()
			return nil, newInvalidPeerSpiderError()
		}
		go func() {
			defer func() {
				spider.SignalStop()
				spider.closeOnce.Do(func() {
					close(spider.rootDone)
					if spider.unregister != nil {
						spider.unregister()
					}
				})
			}()
			client := &http.Client{
				Transport: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
						if config.Show {
							fmt.Printf("REALITY localAddr: %v\tDialTLSContext\n", localAddr)
						}
						return uConn, nil
					},
				},
			}
			prefix := []byte("https://" + uConn.ServerName)
			maps.Lock()
			if maps.maps == nil {
				maps.maps = make(map[string]map[string]struct{})
			}
			paths := maps.maps[uConn.ServerName]
			if paths == nil {
				paths = make(map[string]struct{})
				paths[config.SpiderX] = struct{}{}
				maps.maps[uConn.ServerName] = paths
			}
			firstURL := string(prefix) + getPathLocked(paths)
			maps.Unlock()
			get := func(first bool) {
				var (
					req  *http.Request
					resp *http.Response
					err  error
					body []byte
				)
				if first {
					req, _ = http.NewRequestWithContext(spider.ctx, "GET", firstURL, nil)
				} else {
					maps.Lock()
					req, _ = http.NewRequestWithContext(spider.ctx, "GET", string(prefix)+getPathLocked(paths), nil)
					maps.Unlock()
				}
				if req == nil {
					return
				}
				utils.TryDefaultHeadersWith(req.Header, "nav")
				if first && config.Show {
					fmt.Printf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())
				}
				times := 1
				if !first {
					times = int(crypto.RandBetween(config.SpiderY[4], config.SpiderY[5]))
				}
				for j := 0; j < times; j++ {
					if spider.ctx.Err() != nil {
						return
					}
					if !first && j == 0 {
						req.Header.Set("Referer", firstURL)
					}
					req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(crypto.RandBetween(config.SpiderY[0], config.SpiderY[1])))})
					if resp, err = client.Do(req); err != nil {
						break
					}
					req.Header.Set("Referer", req.URL.String())
					if body, err = io.ReadAll(resp.Body); err != nil {
						_ = resp.Body.Close()
						break
					}
					_ = resp.Body.Close()
					maps.Lock()
					for _, m := range href.FindAllSubmatch(body, -1) {
						m[1] = bytes.TrimPrefix(m[1], prefix)
						if !bytes.Contains(m[1], dot) {
							paths[string(m[1])] = struct{}{}
						}
					}
					req.URL.Path = getPathLocked(paths)
					if config.Show {
						fmt.Printf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())
						fmt.Printf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))
						fmt.Printf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))
					}
					maps.Unlock()
					if !first {
						if !waitSpider(spider.ctx, time.Duration(crypto.RandBetween(config.SpiderY[6], config.SpiderY[7]))*time.Millisecond) {
							return
						}
					}
				}
			}
			get(true)
			if spider.ctx.Err() != nil {
				return
			}
			concurrency := int(crypto.RandBetween(config.SpiderY[2], config.SpiderY[3]))
			var workers sync.WaitGroup
			for i := 0; i < concurrency; i++ {
				if spider.ctx.Err() != nil {
					break
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					get(false)
				}()
			}
			workers.Wait()
		}()
		if !waitSpider(spiderCtx, time.Duration(crypto.RandBetween(config.SpiderY[8], config.SpiderY[9]))*time.Millisecond) {
			return nil, newInvalidPeerSpiderError()
		}
		return nil, newInvalidPeerSpiderError()
	}
	return uConn, nil
}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]struct{}
}

func getPathLocked(paths map[string]struct{}) string {
	stopAt := int(crypto.RandBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}
