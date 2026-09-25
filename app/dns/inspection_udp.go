package dns

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/udp"
)

// dnsUDPQueryOwner owns one actual ClassicNameServer sendQuery execution. Its
// dispatcher is deliberately not shared with sibling or future queries, so an
// exact local stop cannot retire their native UDP ray.
type dnsUDPQueryOwner struct {
	server        *ClassicNameServer
	exchange      stats.Exchange
	dispatcher    *udp.Dispatcher
	ctx           context.Context
	cancel        context.CancelFunc
	stopParent    func() bool               // guarded by server.Lock
	requests      map[uint16]*udpDnsRequest // guarded by server.Lock
	unresolved    int                       // guarded by server.Lock
	errors        chan<- error
	closed        bool // guarded by server.Lock
	partialLoss   bool // guarded by server.Lock
	finishOnce    sync.Once
	resource      *dnsUDPResourceOwner
	exchangeReady chan struct{}
}

func routedDNSUDPObservationAvailable(ctx context.Context) bool {
	instance := core.FromContext(ctx)
	if instance == nil {
		return false
	}
	provider, ok := instance.GetFeature(stats.ManagerType()).(stats.ObservationProvider)
	return ok && provider.Observation() != nil
}

func beginRoutedDNSUDPObservation(routedCtx, callerCtx context.Context, server *ClassicNameServer, destination net.Destination, unresolved int, responseErrors chan<- error) (context.Context, *dnsUDPQueryOwner) {
	// A resolver query is a new INTERNAL root. It never inherits the USER or
	// measurement observation which caused name resolution.
	routedCtx = session.ContextWithLogicalObservation(routedCtx, nil)
	instance := core.FromContext(routedCtx)
	if instance == nil {
		return routedCtx, nil
	}
	provider, ok := instance.GetFeature(stats.ManagerType()).(stats.ObservationProvider)
	if !ok {
		return routedCtx, nil
	}
	store := provider.Observation()
	if store == nil {
		return routedCtx, nil
	}
	return beginRoutedDNSUDPObservationWithStore(routedCtx, callerCtx, server, destination, unresolved, responseErrors, store)
}

func beginRoutedDNSUDPObservationWithStore(routedCtx, callerCtx context.Context, server *ClassicNameServer, destination net.Destination, unresolved int, responseErrors chan<- error, store stats.AdmissionStore) (context.Context, *dnsUDPQueryOwner) {
	queryCtx, cancel := context.WithCancel(routedCtx)
	owner := &dnsUDPQueryOwner{
		server:        server,
		ctx:           queryCtx,
		cancel:        cancel,
		requests:      make(map[uint16]*udpDnsRequest),
		unresolved:    unresolved,
		errors:        responseErrors,
		exchangeReady: make(chan struct{}),
	}
	// Install cancellation and the exact stopping resource before Begin makes
	// its close callback addressable through the live store.
	owner.dispatcher = udp.NewDispatcher(server.dispatcher, owner.handleResponse)
	owner.resource = server.registerResourceOwner(unresolved, owner.dispatcher)
	if owner.resource == nil {
		cancel()
		return routedCtx, nil
	}
	exchange := store.Begin(stats.FlowKindUDPAssociation, stats.TrafficOriginInternal, net.Destination{}, destination, owner.Close)
	owner.exchange = exchange
	close(owner.exchangeReady)
	if exchange == nil || exchange.Ref() == (stats.FlowRef{}) {
		owner.cleanupForFallback()
		return routedCtx, nil
	}
	owner.dispatcher.Observation = exchange
	owner.dispatcher.InputAtExecution = true
	server.RLock()
	stoppedDuringBegin := owner.closed
	server.RUnlock()
	if stoppedDuringBegin {
		exchange.Finish()
		return queryCtx, owner
	}

	stopParent := context.AfterFunc(callerCtx, owner.finishCanceled)
	server.Lock()
	if owner.closed {
		server.Unlock()
		stopParent()
	} else {
		owner.stopParent = stopParent
		server.Unlock()
	}
	return queryCtx, owner
}

func (o *dnsUDPQueryOwner) exchangeIfReady() stats.Exchange {
	if o.exchangeReady == nil {
		return o.exchange
	}
	select {
	case <-o.exchangeReady:
		return o.exchange
	default:
		return nil
	}
}

func (o *dnsUDPQueryOwner) cleanupForFallback() {
	if o.cancel != nil {
		o.cancel()
	}
	o.server.Lock()
	o.closed = true
	o.unresolved = 0
	o.server.Unlock()
	o.resource.finishAsync()
}

func (o *dnsUDPQueryOwner) handleResponse(ctx context.Context, packet *udp_proto.Packet) {
	o.server.handleResponse(ctx, packet, o)
}

func (o *dnsUDPQueryOwner) Close() error {
	o.finishOnce.Do(func() {
		o.closeResources()
		// Once the pending IDs are removed, no further collision or expiry can
		// add a loss that this exact-stop terminal would miss.
		o.applyPartialLoss(nil)
	})
	return nil
}

func (o *dnsUDPQueryOwner) closeResources() {
	// Cancellation must unblock a routing.Dispatcher which has not returned its
	// link yet. Do it before either the nameserver or UDP-dispatcher lock.
	if o.cancel != nil {
		o.cancel()
	}

	o.server.Lock()
	if o.closed {
		o.server.Unlock()
		return
	}
	o.closed = true
	stopParent := o.stopParent
	o.stopParent = nil
	unresolved := o.unresolved
	var retired []dnsUDPRequestRetirement
	for id, req := range o.requests {
		if o.server.requests[id] == req {
			delete(o.server.requests, id)
		}
		retired = append(retired, o.server.retireObservedRequestLocked(req, true))
	}
	o.unresolved = 0
	o.server.Unlock()

	if stopParent != nil {
		stopParent()
	}
	for _, retirement := range retired {
		if retirement.release != nil {
			retirement.release()
		}
		if retirement.resourceDone {
			retirement.resource.finishAsync()
		}
	}
	o.resource.finishAsync()
	o.signalErrors(unresolved, io.ErrClosedPipe)
}

func (o *dnsUDPQueryOwner) signalErrors(count int, err error) {
	if o.errors == nil || err == nil {
		return
	}
	for range count {
		select {
		case o.errors <- err:
		default:
			return
		}
	}
}

func (o *dnsUDPQueryOwner) rejectUnadmitted(err error) {
	o.resource.abandon()
	o.server.Lock()
	if o.unresolved == 0 {
		o.server.Unlock()
		return
	}
	o.unresolved--
	done := o.unresolved == 0
	o.server.Unlock()
	o.requestLost(err, done)
}

func (o *dnsUDPQueryOwner) finishCanceled() {
	o.finishOnce.Do(func() {
		o.applyPartialLoss(nil)
		if exchange := o.exchangeIfReady(); exchange != nil {
			exchange.MarkUplinkIncomplete()
			exchange.MarkDownlinkIncomplete()
		}
		o.closeResources()
		if exchange := o.exchangeIfReady(); exchange != nil {
			exchange.Finish()
		}
	})
}

func (o *dnsUDPQueryOwner) responseMatched(ctx context.Context, payloadSize uint64, done bool) {
	o.recordDownlink(ctx, payloadSize)
	if !done {
		return
	}
	o.finishOnce.Do(func() {
		// The response callback is the last consumer of the decoded payload.
		// Settle the sole native ray and root before cache publication can wake
		// QueryIP and cancel its caller context.
		o.applyPartialLoss(ctx)
		if observation := session.LogicalObservationFromContext(ctx); observation != nil && observation.Exchange != nil {
			observation.Exchange.Finish()
		}
		o.closeResources()
		if exchange := o.exchangeIfReady(); exchange != nil {
			exchange.Finish()
		}
	})
}

func (o *dnsUDPQueryOwner) applyPartialLoss(ctx context.Context) {
	o.server.RLock()
	partialLoss := o.partialLoss
	o.server.RUnlock()
	if !partialLoss {
		return
	}
	exchange := o.exchangeIfReady()
	if exchange == nil {
		return
	}
	exchange.MarkDownlinkIncomplete()
	if ctx != nil {
		if observation := session.LogicalObservationFromContext(ctx); observation != nil && observation.Exchange != nil {
			observation.Exchange.MarkDownlinkIncomplete()
		}
	}
}

func (o *dnsUDPQueryOwner) recordDownlink(ctx context.Context, payloadSize uint64) {
	if payloadSize == 0 {
		return
	}
	receipt := o.exchangeIfReady()
	if receipt == nil {
		return
	}
	if observation := session.LogicalObservationFromContext(ctx); observation != nil && observation.Exchange != nil {
		receipt = observation.Exchange
	}
	receipt.AddDownlink(payloadSize)
}

func (o *dnsUDPQueryOwner) requestLost(err error, done bool) {
	exchange := o.exchangeIfReady()
	if !done {
		if exchange != nil {
			exchange.MarkDownlinkIncomplete()
		}
		o.signalErrors(1, err)
		return
	}
	o.finishOnce.Do(func() {
		o.applyPartialLoss(nil)
		if exchange != nil {
			exchange.MarkDownlinkIncomplete()
		}
		o.closeResources()
		if exchange != nil {
			exchange.Finish()
		}
	})
	o.signalErrors(1, err)
}
