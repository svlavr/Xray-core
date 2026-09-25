package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	go_errors "errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http2"
)

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	cacheController *CacheController
	httpClient      *http.Client
	dohURL          string
	destination     net.Destination
	routed          bool
	clientIP        net.IP
	mu              sync.Mutex
	connections     map[net.Conn]struct{}
	closed          bool
	dialing         sync.WaitGroup
}

// NewDoHNameServer creates DOH/DOHL client object for remote/local resolving.
func NewDoHNameServer(url *url.URL, dispatcher routing.Dispatcher, h2c bool, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *DoHNameServer {
	url.Scheme = "https"
	mode := "DOH"
	if dispatcher == nil {
		mode = "DOHL"
	}
	errors.LogInfo(context.Background(), "DNS: created ", mode, " client for ", url.String(), ", with h2c ", h2c)
	s := &DoHNameServer{
		cacheController: NewCacheController(mode+"//"+url.Host, disableCache, serveStale, serveExpiredTTL),
		dohURL:          url.String(),
		destination:     dohDestination(url.Hostname(), url.Port()),
		routed:          dispatcher != nil,
		clientIP:        clientIP,
		connections:     make(map[net.Conn]struct{}),
	}
	s.httpClient = &http.Client{
		Transport: &http2.Transport{
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				if !s.beginDial() {
					return nil, context.Canceled
				}
				defer s.dialing.Done()
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				var conn net.Conn
				var routeReceipt *dohRouteReceipt
				if dispatcher != nil {
					dnsCtx := toDnsContext(ctx, s.dohURL)
					if dohObservationAvailable(ctx) {
						routeReceipt = newDoHRouteReceipt()
						dnsCtx = session.ContextWithRouteOnlyReceipt(dnsCtx, routeReceipt)
					}
					if h2c {
						dnsCtx = session.ContextWithMitmAlpn11(dnsCtx, false) // for insurance
						dnsCtx = session.ContextWithMitmServerName(dnsCtx, url.Hostname())
					}
					link, err := dispatcher.Dispatch(dnsCtx, dest)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					default:
					}
					if err != nil {
						return nil, err
					}
					cc := common.ChainedClosable{}
					if cw, ok := link.Writer.(common.Closable); ok {
						cc = append(cc, cw)
					}
					if cr, ok := link.Reader.(common.Closable); ok {
						cc = append(cc, cr)
					}
					conn = cnc.NewConnection(
						cnc.ConnectionInputMulti(link.Writer),
						cnc.ConnectionOutputMulti(link.Reader),
						cnc.ConnectionOnClose(cc),
					)
				} else {
					log.Record(&log.AccessMessage{
						From:   "DNS",
						To:     s.dohURL,
						Status: log.AccessAccepted,
						Detour: "local",
					})
					conn, err = internet.DialSystem(ctx, dest, nil)
					if err != nil {
						return nil, err
					}
				}
				tracked, ok := s.trackConnection(conn)
				if !ok {
					return nil, context.Canceled
				}
				conn = tracked
				if routeReceipt != nil {
					step, waitErr := routeReceipt.WaitOffer(ctx)
					if waitErr != nil {
						_ = conn.Close()
						return nil, waitErr
					}
					if step.Selection == stats.SelectionRejected {
						_ = conn.Close()
						return nil, &dohRouteError{step: step}
					}
				}
				if !h2c {
					conn = utls.UClient(conn, &utls.Config{ServerName: url.Hostname()}, utls.HelloChrome_Auto)
					if err := conn.(*utls.UConn).HandshakeContext(ctx); err != nil {
						return nil, classifyDoHTLSHandshakeError(ctx, conn, routeReceipt, err)
					}
				}
				if routeReceipt != nil {
					conn = &dohCarrierConn{Conn: conn, route: routeReceipt}
				}
				return conn, nil
			},
		},
	}
	return s
}

func (s *DoHNameServer) beginDial() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.dialing.Add(1)
	return true
}

// Name implements Server.
func (s *DoHNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *DoHNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *DoHNameServer) newReqID() uint16 {
	return 0
}

// getCacheController implements CachedNameserver.
func (s *DoHNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *DoHNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", fqdn)

	if s.Name()+"." == "DOH//"+fqdn {
		errors.LogError(ctx, s.Name(), " tries to resolve itself! Use IP or set \"hosts\" instead")
		if noResponseErrCh != nil {
			err := errors.New("tries to resolve itself!", s.Name())
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	// As we don't want our traffic pattern looks like DoH, we use Random-Length Padding instead of Block-Length Padding recommended in RFC 8467
	// Although DoH server like 1.1.1.1 will pad the response to Block-Length 468, at least it is better than no padding for response at all
	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, int(crypto.RandBetween(100, 300))))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		reserved, release, reserveErr := dns_feature.ReserveContextBinding(ctx)
		if reserveErr != nil {
			if noResponseErrCh != nil {
				noResponseErrCh <- reserveErr
			}
			continue
		}
		go func(r *dnsRequest, ctx context.Context, release func()) {
			defer release()
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "https",
				SkipDNSResolve: true,
			})

			// forced to use mux for DOH
			// dnsCtx = session.ContextWithMuxPreferred(dnsCtx, true)

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			payload := append([]byte(nil), b.Bytes()...)
			b.Release()
			resp, observation, err := s.dohHTTPSContextObserved(dnsCtx, payload)
			if err != nil {
				if observation != nil {
					observation.finish(false)
				}
				errors.LogErrorInner(ctx, err, "failed to retrieve response for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			rec, err := parseObservedDoHResponse(resp, observation)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle DOH response for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			s.cacheController.updateRecord(r, rec)
		}(req, reserved, release)
	}
}

type dohTrackedConn struct {
	net.Conn
	state resourceCloseState
	done  func()
}

func (c *dohTrackedConn) Close() error {
	return c.state.close(func() error {
		err := c.Conn.Close()
		if go_errors.Is(err, stdnet.ErrClosed) {
			return nil
		}
		return err
	}, c.done)
}

func (s *DoHNameServer) trackConnection(conn net.Conn) (net.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	accepted := !s.closed
	var tracked *dohTrackedConn
	tracked = &dohTrackedConn{Conn: conn, done: func() {
		s.mu.Lock()
		delete(s.connections, tracked)
		s.mu.Unlock()
	}}
	s.connections[tracked] = struct{}{}
	return tracked, accepted
}

func (s *DoHNameServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.dialing.Wait()
	s.mu.Lock()
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	if transport, ok := s.httpClient.Transport.(*http2.Transport); ok {
		transport.CloseIdleConnections()
	}
	var errs []error
	for _, conn := range connections {
		if err := conn.Close(); err != nil && !go_errors.Is(err, stdnet.ErrClosed) {
			errs = append(errs, err)
		}
	}
	errs = append(errs, s.cacheController.Close())
	return go_errors.Join(errs...)
}

func (s *DoHNameServer) dohHTTPSContext(ctx context.Context, b []byte) ([]byte, error) {
	response, observation, err := s.dohHTTPSContextObserved(ctx, b)
	if observation != nil {
		observation.finish(err == nil)
	}
	return response, err
}

func (s *DoHNameServer) dohHTTPSContextObserved(ctx context.Context, b []byte) ([]byte, *dohRequestObservation, error) {
	var store stats.AdmissionStore
	if s.routed {
		store = dohObservationStore(ctx)
	}
	return s.dohHTTPSContextWithStore(ctx, b, store)
}

func (s *DoHNameServer) dohHTTPSContextWithStore(ctx context.Context, b []byte, store stats.AdmissionStore) ([]byte, *dohRequestObservation, error) {
	var observation *dohRequestObservation
	if store != nil {
		ctx, observation = beginRoutedDoHObservation(ctx, store, s.destination, len(b))
	}
	if ctx.Err() != nil {
		return nil, observation, ctx.Err()
	}

	var req *http.Request
	var err error
	if observation != nil {
		req, err = newObservedDoHRequest(ctx, "POST", s.dohURL, b, observation)
	} else {
		req, err = http.NewRequestWithContext(ctx, "POST", s.dohURL, bytes.NewBuffer(b))
	}
	if err != nil {
		return nil, observation, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")
	utils.TryDefaultHeadersWith(req.Header, "fetch")
	req.Header.Set("X-Padding", utils.H2Base62Pad(crypto.RandBetween(100, 1000)))

	hc := s.httpClient

	resp, err := hc.Do(req)
	if err != nil {
		if step, rejected := dohRejectedRoute(err); rejected && observation != nil {
			observation.reject(step)
		}
		return nil, observation, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, observation, fmt.Errorf("DOH server returned code %d", resp.StatusCode)
	}

	response, err := io.ReadAll(resp.Body)
	if observation != nil {
		observation.recordResponseRead(len(response), err)
	}
	return response, observation, err
}

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
