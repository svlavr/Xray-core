package dns

import (
	"context"
	go_errors "errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer uses the native shared UDP ray for its configured server.
type ClassicNameServer struct {
	sync.RWMutex
	cacheController *CacheController
	address         *net.Destination
	requests        map[uint16]*udpDnsRequest
	udpServer       *udp.Dispatcher
	requestsCleanup *ownedPeriodic
	reqID           uint32
	clientIP        net.IP
	closed          bool
	rayCtx          context.Context
	cancelRay       context.CancelFunc
}

type udpDnsRequest struct {
	dnsRequest
	ctx  context.Context
	stop func() bool // guarded by ClassicNameServer lock
}

func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	if address.Port == 0 {
		address.Port = net.Port(53)
	}
	rayCtx, cancelRay := context.WithCancel(context.Background())
	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         &address, requests: make(map[uint16]*udpDnsRequest), clientIP: clientIP,
		rayCtx: rayCtx, cancelRay: cancelRay,
	}
	s.requestsCleanup = newOwnedPeriodic(time.Second, s.RequestsCleanup)
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)
	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

func (s *ClassicNameServer) Name() string         { return s.cacheController.name }
func (s *ClassicNameServer) IsDisableCache() bool { return s.cacheController.disableCache }

func (s *ClassicNameServer) forgetRequest(req *udpDnsRequest) {
	s.Lock()
	if s.requests[req.msg.ID] == req {
		delete(s.requests, req.msg.ID)
	}
	s.Unlock()
}

func (s *ClassicNameServer) RequestsCleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()
	if len(s.requests) == 0 {
		return errors.New(s.Name(), " nothing to do. stopping...")
	}
	for id, req := range s.requests {
		if req.expire.Before(now) {
			delete(s.requests, id)
			if req.stop != nil {
				req.stop()
			}
		}
	}
	return nil
}

func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	payload := packet.Payload
	var questionParser dnsmessage.Parser
	_, questionErr := questionParser.Start(payload.Bytes())
	var question dnsmessage.Question
	if questionErr == nil {
		question, questionErr = questionParser.Question()
	}
	// Native resolvers also accept replies which omit the question section.
	// Validate an echoed question when present without requiring a new wire form.
	hasQuestion := questionErr == nil
	if questionErr == dnsmessage.ErrSectionDone {
		questionErr = nil
	}
	ipRec, err := parseResponse(payload.Bytes())
	payload.Release()
	if err != nil || questionErr != nil {
		errors.LogErrorInner(ctx, go_errors.Join(err, questionErr), s.Name(), " fail to parse responded DNS udp")
		return
	}
	s.Lock()
	req := s.requests[ipRec.ReqID]
	if req != nil && hasQuestion && (!strings.EqualFold(question.Name.String(), req.domain) || question.Type != req.reqType) {
		req = nil
	}
	if req != nil {
		delete(s.requests, ipRec.ReqID)
		if req.stop != nil {
			req.stop()
		}
	}
	s.Unlock()
	if req == nil {
		errors.LogError(ctx, s.Name(), " cannot find the pending request")
		return
	}
	if req.ctx.Err() != nil {
		return
	}
	if ipRec.RawHeader.Truncated && len(req.msg.Additionals) == 0 {
		opt := new(dnsmessage.Resource)
		common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
		opt.Body = &dnsmessage.OPTResource{}
		newMsg := *req.msg
		newMsg.Additionals = append(newMsg.Additionals, *opt)
		newMsg.ID = s.newReqID()
		retry := &udpDnsRequest{dnsRequest: req.dnsRequest, ctx: req.ctx}
		retry.msg = &newMsg
		b, err := dns.PackMessage(retry.msg)
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to pack DNS retry")
			return
		}
		if !s.addPendingRequest(retry) {
			b.Release()
			return
		}
		s.udpServer.Dispatch(s.dispatchContext(retry.ctx), *s.address, b)
		return
	}
	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

func (s *ClassicNameServer) newReqID() uint16 { return uint16(atomic.AddUint32(&s.reqID, 1)) }

func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) bool {
	s.Lock()
	if s.closed || req.ctx.Err() != nil || s.requests[req.msg.ID] != nil {
		s.Unlock()
		return false
	}
	req.expire = time.Now().Add(8 * time.Second)
	s.requests[req.msg.ID] = req
	req.stop = context.AfterFunc(req.ctx, func() { s.forgetRequest(req) })
	s.Unlock()
	common.Must(s.requestsCleanup.Start())
	return true
}

func (s *ClassicNameServer) getCacheController() *CacheController { return s.cacheController }

func (s *ClassicNameServer) dispatchContext(ctx context.Context) context.Context {
	// The shared ray carries the initial routing metadata but belongs to this
	// nameserver. Canceling one request must not terminate sibling requests.
	return toDnsContext(&dnsRequestContext{Context: context.WithoutCancel(ctx), caller: s.rayCtx}, s.address.String())
}

func (s *ClassicNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
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
	for _, req := range reqs {
		b, err := dns.PackMessage(req.msg)
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to pack dns query")
			if noResponseErrCh != nil {
				noResponseErrCh <- err
			}
			continue
		}
		pending := &udpDnsRequest{dnsRequest: *req, ctx: ctx}
		if !s.addPendingRequest(pending) {
			b.Release()
			if noResponseErrCh != nil {
				noResponseErrCh <- context.Canceled
			}
			continue
		}
		s.udpServer.Dispatch(s.dispatchContext(ctx), *s.address, b)
	}
}

func (s *ClassicNameServer) Close() error {
	s.Lock()
	s.closed = true
	for id, req := range s.requests {
		delete(s.requests, id)
		if req.stop != nil {
			req.stop()
		}
	}
	s.Unlock()
	s.cancelRay()
	_ = s.requestsCleanup.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return go_errors.Join(s.udpServer.CloseAndWait(ctx), s.cacheController.Close())
}

func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
