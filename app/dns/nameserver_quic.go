package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	stdnet "net"
	"net/url"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "doq"

const handshakeTimeout = time.Second * 8

// QUICNameServer implemented DNS over QUIC
type QUICNameServer struct {
	sync.RWMutex
	cacheController *CacheController
	destination     *net.Destination
	connection      *quic.Conn
	clientIP        net.IP
	transport       *quic.Transport
	packetConn      stdnet.PacketConn
	closed          bool
}

// NewQUICNameServer creates DNS-over-QUIC client object for local resolving
func NewQUICNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*QUICNameServer, error) {
	var err error
	port := net.Port(853)
	if url.Port() != "" {
		port, err = net.PortFromString(url.Port())
		if err != nil {
			return nil, err
		}
	}
	dest := net.UDPDestination(net.ParseAddress(url.Hostname()), port)

	s := &QUICNameServer{
		cacheController: NewCacheController(url.String(), disableCache, serveStale, serveExpiredTTL),
		destination:     &dest,
		clientIP:        clientIP,
	}

	errors.LogInfo(context.Background(), "DNS: created Local DNS-over-QUIC client for ", url.String())
	return s, nil
}

// Name implements Server.
func (s *QUICNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *QUICNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *QUICNameServer) newReqID() uint16 {
	return 0
}

// getCacheController implements CachedNameServer.
func (s *QUICNameServer) getCacheController() *CacheController { return s.cacheController }

// sendQuery implements CachedNameServer.
func (s *QUICNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", fqdn)

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
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "quic",
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

			dnsReqBuf := buf.New()
			defer dnsReqBuf.Release()
			err = binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			if err != nil {
				errors.LogErrorInner(ctx, err, "binary write failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			_, err = dnsReqBuf.Write(b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "buffer write failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			b.Release()

			conn, err := s.openStream(dnsCtx)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to open quic connection")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to send query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			_ = conn.Close()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			var length uint16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			s.cacheController.updateRecord(r, rec)
		}(req, reserved, release)
	}
}

// QueryIP implements Server.
func (s *QUICNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

func isActive(s *quic.Conn) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func (s *QUICNameServer) getConnection(ctx context.Context) (*quic.Conn, error) {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return nil, context.Canceled
	}
	conn := s.connection
	if conn != nil && isActive(conn) {
		return conn, nil
	}
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}

	var err error
	conn, err = s.openConnection(ctx)
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC connection.
		conn, err = s.openConnection(ctx)
		if err != nil {
			return nil, err
		}
	}
	s.connection = conn
	return conn, nil
}

func (s *QUICNameServer) openConnection(ctx context.Context) (*quic.Conn, error) {
	tlsConfig := tls.Config{}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	}
	tlsConfig.ServerName = s.destination.Address.String()
	remote := &stdnet.UDPAddr{Port: int(s.destination.Port)}
	if s.destination.Address.Family().IsIP() {
		remote.IP = stdnet.IP(s.destination.Address.IP())
	} else {
		addresses, err := stdnet.DefaultResolver.LookupIP(ctx, "ip", s.destination.Address.Domain())
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, dns_feature.ErrEmptyResponse
		}
		remote.IP = selectQUICRemoteIP(addresses)
	}
	if s.transport == nil {
		packetConn, err := stdnet.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		s.packetConn = packetConn
		s.transport = &quic.Transport{Conn: packetConn}
	}
	conn, err := s.transport.Dial(ctx, remote, tlsConfig.GetTLSConfig(tls.WithNextProto("http/1.1", http2.NextProtoTLS, NextProtoDQ)), quicConfig)
	log.Record(&log.AccessMessage{
		From:   "DNS",
		To:     s.destination,
		Status: log.AccessAccepted,
		Detour: "local",
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func selectQUICRemoteIP(addresses []stdnet.IP) stdnet.IP {
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			return ipv4
		}
	}
	if len(addresses) != 0 {
		return addresses[0]
	}
	return nil
}

func (s *QUICNameServer) openStream(ctx context.Context) (*quic.Stream, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	// open a new stream
	return conn.OpenStreamSync(ctx)
}

func (s *QUICNameServer) Close() error {
	s.Lock()
	s.closed = true
	conn, transport, packetConn := s.connection, s.transport, s.packetConn
	s.Unlock()
	var errs []error
	if conn != nil {
		if err := conn.CloseWithError(0, "DNS generation retired"); err != nil {
			errs = append(errs, err)
		} else {
			s.Lock()
			if s.connection == conn {
				s.connection = nil
			}
			s.Unlock()
		}
	}
	if transport != nil {
		if err := transport.Close(); err != nil {
			errs = append(errs, err)
		} else {
			s.Lock()
			if s.transport == transport {
				s.transport = nil
			}
			s.Unlock()
		}
	}
	if packetConn != nil {
		if err := packetConn.Close(); err != nil && !go_errors.Is(err, stdnet.ErrClosed) {
			errs = append(errs, err)
		} else {
			s.Lock()
			if s.packetConn == packetConn {
				s.packetConn = nil
			}
			s.Unlock()
		}
	}
	errs = append(errs, s.cacheController.Close())
	return go_errors.Join(errs...)
}
