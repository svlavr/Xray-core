package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	stdnet "net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// TCPNameServer implemented DNS over TCP (RFC7766).
type TCPNameServer struct {
	cacheController *CacheController
	destination     *net.Destination
	reqID           uint32
	dial            func(context.Context) (net.Conn, error)
	routed          bool
	clientIP        net.IP
	mu              sync.Mutex
	connections     map[net.Conn]struct{}
	closed          bool
	dialing         sync.WaitGroup
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
	dispatcher routing.Dispatcher,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	clientIP net.IP,
) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCP", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}

	s.routed = true
	s.dial = func(ctx context.Context) (net.Conn, error) {
		link, err := dispatcher.Dispatch(ctx, *s.destination)
		if err != nil {
			return nil, err
		}

		return cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		), nil
	}

	errors.LogInfo(context.Background(), "DNS: created TCP client initialized for ", url.String())
	return s, nil
}

// NewTCPLocalNameServer creates DNS over TCP client object for local resolving
func NewTCPLocalNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCPL", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		return internet.DialSystem(ctx, *s.destination, nil)
	}

	errors.LogInfo(context.Background(), "DNS: created Local TCP client initialized for ", url.String())
	return s, nil
}

func baseTCPNameServer(url *url.URL, prefix string, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	dest := net.TCPDestination(net.ParseAddress(url.Hostname()), port)

	s := &TCPNameServer{
		cacheController: NewCacheController(prefix+"//"+dest.NetAddr(), disableCache, serveStale, serveExpiredTTL),
		destination:     &dest,
		clientIP:        clientIP,
		connections:     make(map[net.Conn]struct{}),
	}

	return s, nil
}

// Name implements Server.
func (s *TCPNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *TCPNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

// getCacheController implements CachedNameserver.
func (s *TCPNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *TCPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
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
			dnsCtx := ctx

			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "dns",
				SkipDNSResolve: true,
			})

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			defer b.Release()

			var owner *dnsTCPQueryOwner
			if s.routed {
				dnsCtx = toDnsContext(dnsCtx, s.destination.String())
				dnsCtx, owner = beginRoutedDNSTCPObservation(dnsCtx, *s.destination, uint64(b.Len()))
				if owner != nil {
					defer owner.finish()
				}
			}

			if !s.beginDial() {
				if noResponseErrCh != nil {
					noResponseErrCh <- context.Canceled
				}
				return
			}
			conn, err := s.dial(dnsCtx)
			if err != nil {
				s.dialing.Done()
				errors.LogErrorInner(ctx, err, "failed to dial namesever")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			tracked, ok := s.trackConnection(conn)
			s.dialing.Done()
			if !ok {
				if noResponseErrCh != nil {
					noResponseErrCh <- context.Canceled
				}
				return
			}
			conn = tracked
			if owner != nil {
				if err = owner.attach(conn); err != nil {
					errors.LogErrorInner(ctx, err, "failed to attach routed DNS connection")
					if noResponseErrCh != nil {
						noResponseErrCh <- err
					}
					return
				}
			} else {
				defer conn.Close()
			}
			dnsReqBuf := buf.New()
			defer dnsReqBuf.Release()
			err = binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			if err != nil {
				owner.markWriteError()
				errors.LogErrorInner(ctx, err, "binary write failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			_, err = dnsReqBuf.Write(b.Bytes())
			if err != nil {
				owner.markWriteError()
				errors.LogErrorInner(ctx, err, "buffer write failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			b.Release()

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				owner.markWriteError()
				errors.LogErrorInner(ctx, err, "failed to send query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			dnsReqBuf.Release()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				owner.markResponseError()
				errors.LogErrorInner(ctx, err, "failed to read response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			var length uint16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				owner.markResponseError()
				errors.LogErrorInner(ctx, err, "failed to parse response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			owner.recordResponseRead(n, int64(length), err)
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				owner.markResponseDecodeError()
				errors.LogErrorInner(ctx, err, "failed to parse DNS over TCP response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			s.cacheController.updateRecord(r, rec)
		}(req, reserved, release)
	}
}

func (s *TCPNameServer) beginDial() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.dialing.Add(1)
	return true
}

type tcpTrackedConn struct {
	net.Conn
	state resourceCloseState
	done  func()
}

func (c *tcpTrackedConn) Close() error {
	return c.state.close(func() error {
		err := c.Conn.Close()
		if go_errors.Is(err, stdnet.ErrClosed) {
			return nil
		}
		return err
	}, c.done)
}

func (s *TCPNameServer) trackConnection(conn net.Conn) (net.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	accepted := !s.closed
	var tracked *tcpTrackedConn
	tracked = &tcpTrackedConn{Conn: conn, done: func() {
		s.mu.Lock()
		delete(s.connections, tracked)
		s.mu.Unlock()
	}}
	s.connections[tracked] = struct{}{}
	return tracked, accepted
}

func (s *TCPNameServer) Close() error {
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
	var errs []error
	for _, conn := range connections {
		if err := conn.Close(); err != nil && !go_errors.Is(err, stdnet.ErrClosed) {
			errs = append(errs, err)
		}
	}
	errs = append(errs, s.cacheController.Close())
	return go_errors.Join(errs...)
}

// QueryIP implements Server.
func (s *TCPNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
