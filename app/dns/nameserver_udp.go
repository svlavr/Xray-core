package dns

import (
	"context"
	go_errors "errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer implemented traditional UDP DNS.
type ClassicNameServer struct {
	sync.RWMutex
	cacheController *CacheController
	address         *net.Destination
	requests        map[uint16]*udpDnsRequest
	udpServer       *udp.Dispatcher
	dispatcher      routing.Dispatcher
	requestsCleanup *ownedPeriodic
	reqID           uint32
	clientIP        net.IP
	closed          bool
	resourceOwners  map[*dnsUDPResourceOwner]struct{}
}

type udpDnsRequest struct {
	dnsRequest
	ctx      context.Context
	owner    *dnsUDPQueryOwner
	release  func()
	resource *dnsUDPResourceOwner
	retired  bool // guarded by ClassicNameServer.Lock
}

type dnsUDPRequestRetirement struct {
	owner        *dnsUDPQueryOwner
	done         bool
	release      func()
	resource     *dnsUDPResourceOwner
	resourceDone bool
}

type dnsUDPResourceOwner struct {
	server     *ClassicNameServer
	dispatcher *udp.Dispatcher
	unresolved int // guarded by server.Lock
	mu         sync.Mutex
	running    bool
	terminal   bool
	done       chan struct{}
	err        error
}

var errDNSUDPRequestIDCollision = errors.New("DNS UDP request ID collision")

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(53)
	}

	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         &address,
		requests:        make(map[uint16]*udpDnsRequest),
		dispatcher:      dispatcher,
		clientIP:        clientIP,
		resourceOwners:  make(map[*dnsUDPResourceOwner]struct{}),
	}
	// Pending requests carry generation leases. Check expiry promptly so an old
	// generation is not retained for the former minute-wide cleanup granularity.
	s.requestsCleanup = newOwnedPeriodic(time.Second, s.RequestsCleanup)
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)

	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

func (s *ClassicNameServer) newResourceOwner(unresolved int) *dnsUDPResourceOwner {
	dispatcher := udp.NewDispatcher(s.dispatcher, s.HandleResponse)
	return s.registerResourceOwner(unresolved, dispatcher)
}

func (s *ClassicNameServer) registerResourceOwner(unresolved int, dispatcher *udp.Dispatcher) *dnsUDPResourceOwner {
	owner := &dnsUDPResourceOwner{server: s, dispatcher: dispatcher, unresolved: unresolved, done: make(chan struct{})}
	s.Lock()
	if s.closed {
		s.Unlock()
		return nil
	}
	s.resourceOwners[owner] = struct{}{}
	s.Unlock()
	return owner
}

func (o *dnsUDPResourceOwner) finishAsync() <-chan struct{} {
	if o == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	o.mu.Lock()
	if o.running || o.terminal {
		done := o.done
		o.mu.Unlock()
		return done
	}
	o.running = true
	o.done = make(chan struct{})
	done := o.done
	o.mu.Unlock()
	go func() {
		err := o.dispatcher.CloseAndWait(context.Background())
		if err == nil {
			o.server.Lock()
			delete(o.server.resourceOwners, o)
			o.server.Unlock()
		}
		o.mu.Lock()
		o.err = err
		o.running = false
		o.terminal = err == nil
		close(done)
		o.mu.Unlock()
	}()
	return done
}

func (o *dnsUDPResourceOwner) result() error { o.mu.Lock(); defer o.mu.Unlock(); return o.err }

func (o *dnsUDPResourceOwner) abandon() {
	if o == nil {
		return
	}
	o.server.Lock()
	if o.unresolved > 0 {
		o.unresolved--
	}
	done := o.unresolved == 0
	o.server.Unlock()
	if done {
		o.finishAsync()
	}
}

// Name implements Server.
func (s *ClassicNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *ClassicNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

// RequestsCleanup clears expired items from cache
func (s *ClassicNameServer) RequestsCleanup() error {
	now := time.Now()
	s.Lock()

	if len(s.requests) == 0 {
		s.Unlock()
		return errors.New(s.Name(), " nothing to do. stopping...")
	}

	var retired []dnsUDPRequestRetirement
	for id, req := range s.requests {
		if req.expire.Before(now) {
			if s.requests[id] == req {
				delete(s.requests, id)
			}
			if retirement := s.retireObservedRequestLocked(req, true); retirement.owner != nil || retirement.release != nil {
				retired = append(retired, retirement)
			}
		}
	}

	if len(s.requests) == 0 {
		s.requests = make(map[uint16]*udpDnsRequest)
	}
	s.Unlock()
	for _, retirement := range retired {
		if retirement.release != nil {
			retirement.release()
		}
		if retirement.resourceDone {
			retirement.resource.finishAsync()
		}
		if retirement.owner != nil {
			retirement.owner.requestLost(context.DeadlineExceeded, retirement.done)
		}
	}

	return nil
}

// HandleResponse handles udp response packet from remote DNS server.
func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	s.handleResponse(ctx, packet, nil)
}

func (s *ClassicNameServer) handleResponse(ctx context.Context, packet *udp_proto.Packet, owner *dnsUDPQueryOwner) {
	payload := packet.Payload
	payloadSize := uint64(payload.Len())
	ipRec, err := parseResponse(payload.Bytes())
	payload.Release()
	if err != nil {
		errors.LogErrorInner(ctx, err, s.Name(), " fail to parse responded DNS udp")
		return
	}

	s.Lock()
	id := ipRec.ReqID
	req, ok := s.requests[id]
	if ok && (req.owner != owner || owner != nil && owner.requests[id] != req) {
		ok = false
	}
	retry := ok && ipRec.RawHeader.Truncated && len(req.msg.Additionals) == 0
	var retirement dnsUDPRequestRetirement
	if ok {
		if s.requests[id] == req {
			delete(s.requests, id)
		} else {
			ok = false
		}
		if ok && (req.owner != nil || req.resource != nil || req.release != nil) {
			if retry {
				if req.owner != nil {
					delete(req.owner.requests, id)
				}
			} else {
				retirement = s.retireObservedRequestLocked(req, false)
			}
		}
	}
	s.Unlock()
	if !ok {
		errors.LogErrorInner(ctx, err, s.Name(), " cannot find the pending request")
		return
	}
	if !retry && retirement.release != nil {
		defer retirement.release()
	}
	if !retry && retirement.resourceDone {
		retirement.resource.finishAsync()
	}

	// if truncated, retry with EDNS0 option(udp payload size: 1350)
	if ipRec.RawHeader.Truncated {
		// if already has EDNS0 option, no need to retry
		if len(req.msg.Additionals) == 0 {
			// copy necessary meta data from original request
			// and add EDNS0 option
			opt := new(dnsmessage.Resource)
			common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
			opt.Body = &dnsmessage.OPTResource{}
			newMsg := *req.msg
			s.Lock()
			newReq := *req
			req.retired = true // ownership is transferred, not released
			req.release = nil
			req.resource = nil
			s.Unlock()
			newReq.retired = false
			newMsg.Additionals = append(newMsg.Additionals, *opt)
			newMsg.ID = s.newReqID()
			newReq.msg = &newMsg
			if !s.addPendingRequest(&newReq) {
				s.Lock()
				failed := s.retireObservedRequestLocked(&newReq, true)
				s.Unlock()
				s.finishRequestRetirement(failed, context.Canceled)
				if newReq.owner != nil {
					newReq.owner.recordDownlink(ctx, payloadSize)
				}
				return
			}
			b, _ := dns.PackMessage(newReq.msg)
			if newReq.owner != nil {
				newReq.owner.recordDownlink(ctx, payloadSize)
				newReq.owner.dispatcher.Dispatch(newReq.owner.ctx, *s.address, b)
			} else if newReq.resource != nil {
				newReq.resource.dispatcher.Dispatch(toDnsContext(newReq.ctx, s.address.String()), *s.address, b)
			} else {
				s.udpServer.Dispatch(toDnsContext(newReq.ctx, s.address.String()), *s.address, b)
			}
			return
		}
	}

	if req.owner != nil {
		req.owner.responseMatched(ctx, payloadSize, retirement.done)
	}
	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) bool {
	s.Lock()
	if s.closed {
		s.Unlock()
		return false
	}
	if req.owner != nil {
		if req.owner.closed {
			s.Unlock()
			return false
		}
	}
	id := req.msg.ID
	var displaced dnsUDPRequestRetirement
	if previous := s.requests[id]; previous != nil && previous != req {
		displaced = s.retireObservedRequestLocked(previous, true)
	}
	req.expire = time.Now().Add(time.Second * 8)
	if req.owner != nil {
		req.owner.requests[id] = req
	}
	s.requests[id] = req
	s.Unlock()
	common.Must(s.requestsCleanup.Start())
	if displaced.owner != nil {
		if displaced.release != nil {
			displaced.release()
		}
		displaced.owner.requestLost(errDNSUDPRequestIDCollision, displaced.done)
	} else if displaced.release != nil {
		displaced.release()
	}
	if displaced.resourceDone {
		displaced.resource.finishAsync()
	}
	return true
}

func (s *ClassicNameServer) retireObservedRequestLocked(req *udpDnsRequest, partialLoss bool) dnsUDPRequestRetirement {
	if req == nil || req.retired {
		return dnsUDPRequestRetirement{}
	}
	req.retired = true
	retirement := dnsUDPRequestRetirement{owner: req.owner, release: req.release, resource: req.resource}
	req.release = nil
	if req.owner != nil {
		if req.owner.requests[req.msg.ID] == req {
			delete(req.owner.requests, req.msg.ID)
		}
		if partialLoss {
			req.owner.partialLoss = true
		}
		if req.owner.unresolved > 0 {
			req.owner.unresolved--
		}
		retirement.done = req.owner.unresolved == 0
	}
	if req.resource != nil && req.resource.unresolved > 0 {
		req.resource.unresolved--
		retirement.resourceDone = req.resource.unresolved == 0
	}
	return retirement
}

func (s *ClassicNameServer) finishRequestRetirement(retirement dnsUDPRequestRetirement, err error) {
	if retirement.release != nil {
		retirement.release()
	}
	if retirement.resourceDone {
		retirement.resource.finishAsync()
	}
	if retirement.owner != nil {
		retirement.owner.requestLost(err, retirement.done)
	}
}

// getCacheController implements CachedNameserver.
func (s *ClassicNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
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

	if !routedDNSUDPObservationAvailable(ctx) {
		resource := s.newResourceOwner(len(reqs))
		if resource == nil {
			return
		}
		for _, req := range reqs {
			reserved, release, reserveErr := dns_feature.ReserveContextBinding(ctx)
			if reserveErr != nil {
				resource.abandon()
				if noResponseErrCh != nil {
					noResponseErrCh <- reserveErr
				}
				continue
			}
			udpReq := &udpDnsRequest{dnsRequest: *req, ctx: reserved, release: release, resource: resource}
			if !s.addPendingRequest(udpReq) {
				release()
				resource.abandon()
				continue
			}
			b, err := dns.PackMessage(req.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			resource.dispatcher.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, b)
		}
		return
	}
	dnsCtx := toDnsContext(ctx, s.address.String())

	type packedRequest struct {
		req *dnsRequest
		buf *buf.Buffer
	}
	packed := make([]packedRequest, 0, len(reqs))
	for _, req := range reqs {
		b, err := dns.PackMessage(req.msg)
		if err != nil {
			for _, item := range packed {
				item.buf.Release()
			}
			errors.LogErrorInner(ctx, err, "failed to pack dns query")
			if noResponseErrCh != nil {
				noResponseErrCh <- err
			}
			return
		}
		packed = append(packed, packedRequest{req: req, buf: b})
	}

	dnsCtx, owner := beginRoutedDNSUDPObservation(dnsCtx, ctx, s, *s.address, len(packed), noResponseErrCh)
	if owner == nil {
		resource := s.newResourceOwner(len(packed))
		if resource == nil {
			for _, item := range packed {
				item.buf.Release()
			}
			return
		}
		for _, item := range packed {
			reserved, release, reserveErr := dns_feature.ReserveContextBinding(ctx)
			if reserveErr != nil {
				resource.abandon()
				item.buf.Release()
				if noResponseErrCh != nil {
					noResponseErrCh <- reserveErr
				}
				continue
			}
			udpReq := &udpDnsRequest{dnsRequest: *item.req, ctx: reserved, release: release, resource: resource}
			if !s.addPendingRequest(udpReq) {
				release()
				resource.abandon()
				item.buf.Release()
				continue
			}
			resource.dispatcher.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, item.buf)
		}
		return
	}
	s.RLock()
	ownerClosed := owner.closed
	s.RUnlock()
	if ownerClosed {
		for _, item := range packed {
			item.buf.Release()
		}
		return
	}
	for _, item := range packed {
		reserved, release, reserveErr := dns_feature.ReserveContextBinding(ctx)
		if reserveErr != nil {
			item.buf.Release()
			owner.rejectUnadmitted(reserveErr)
			continue
		}
		udpReq := &udpDnsRequest{
			dnsRequest: *item.req,
			ctx:        reserved,
			owner:      owner,
			release:    release,
			resource:   owner.resource,
		}
		if !s.addPendingRequest(udpReq) {
			s.Lock()
			failed := s.retireObservedRequestLocked(udpReq, true)
			s.Unlock()
			s.finishRequestRetirement(failed, context.Canceled)
			item.buf.Release()
			continue
		}
		if owner != nil {
			owner.dispatcher.Dispatch(dnsCtx, *s.address, item.buf)
		} else {
			s.udpServer.Dispatch(dnsCtx, *s.address, item.buf)
		}
	}
}

func (s *ClassicNameServer) Close() error {
	_ = s.requestsCleanup.Close()
	s.Lock()
	s.closed = true
	retired := make([]dnsUDPRequestRetirement, 0, len(s.requests))
	for id, req := range s.requests {
		delete(s.requests, id)
		retired = append(retired, s.retireObservedRequestLocked(req, true))
	}
	owners := make([]*dnsUDPResourceOwner, 0, len(s.resourceOwners))
	for owner := range s.resourceOwners {
		owners = append(owners, owner)
	}
	s.Unlock()
	for _, retirement := range retired {
		if retirement.release != nil {
			retirement.release()
		}
		if retirement.owner != nil {
			retirement.owner.requestLost(context.Canceled, retirement.done)
		}
		if retirement.resourceDone {
			retirement.resource.finishAsync()
		}
	}
	waits := make([]<-chan struct{}, 0, len(owners))
	for _, owner := range owners {
		waits = append(waits, owner.finishAsync())
	}
	var errs []error
	for i, owner := range owners {
		<-waits[i]
		errs = append(errs, owner.result())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errs = append(errs, s.udpServer.CloseAndWait(ctx), s.cacheController.Close())
	return go_errors.Join(errs...)
}

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
