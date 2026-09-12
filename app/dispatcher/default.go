package dispatcher

import (
	"context"
	goerrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var errSniffingTimeout = errors.New("timeout on sniffing")

var ErrObservationShutdownOwned = goerrors.New("dispatcher observation shutdown is owned by core.Instance")

type dispatcherShutdownOwner uint8

const (
	dispatcherShutdownUnowned dispatcherShutdownOwner = iota
	dispatcherShutdownStandalone
	dispatcherShutdownInstance
)

type dispatcherObservationShutdown struct{ dispatcher *DefaultDispatcher }

type cachedReader struct {
	sync.Mutex
	reader buf.TimeoutReader // *pipe.Reader or *buf.TimeoutWrapperReader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer, deadline time.Duration) error {
	mb, err := r.reader.ReadMultiBufferTimeout(deadline)
	if err != nil {
		return err
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(min(r.cache.Len(), b.Cap()))
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
	return nil
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	if p, ok := r.reader.(*pipe.Reader); ok {
		p.Interrupt()
	}
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm       outbound.Manager
	router    routing.Router
	policy    policy.Manager
	stats     stats.Manager
	fdns      dns.FakeDNSEngine
	flows     *flow_observation.Registry
	lifecycle task.Lifecycle
	joinOnce  sync.Once
	closeOnce sync.Once
	joinErr   error
	closeErr  error

	shutdownMu       sync.Mutex
	shutdownOwner    dispatcherShutdownOwner
	shutdownDone     chan struct{}
	shutdownComplete bool
	shutdownErr      error
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	registry, err := flow_observation.NewRegistry(flow_observation.Config{})
	if err == nil {
		d.flows = registry
		if binder, ok := om.(session.MuxClientCarrierAuthorityBinder); ok {
			binder.BindMuxClientCarrierAuthority(registry)
		}
	}
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (d *DefaultDispatcher) Close() error {
	d.shutdownMu.Lock()
	switch d.shutdownOwner {
	case dispatcherShutdownInstance:
		if d.shutdownComplete {
			err := d.shutdownErr
			d.shutdownMu.Unlock()
			return err
		}
		d.shutdownMu.Unlock()
		return ErrObservationShutdownOwned
	case dispatcherShutdownStandalone:
		done := d.shutdownDone
		d.shutdownMu.Unlock()
		<-done
		d.shutdownMu.Lock()
		err := d.shutdownErr
		d.shutdownMu.Unlock()
		return err
	default:
		d.shutdownOwner = dispatcherShutdownStandalone
		d.shutdownDone = make(chan struct{})
	}
	d.shutdownMu.Unlock()

	shutdown := &dispatcherObservationShutdown{dispatcher: d}
	err := shutdown.FinalizeObservation()
	return err
}

// AdoptObservationShutdown transfers exclusive finalization authority to an
// Instance before the dispatcher is published as a Feature.
func (d *DefaultDispatcher) AdoptObservationShutdown() (features.ObservationShutdown, error) {
	if d == nil {
		return nil, errors.New("cannot adopt nil dispatcher observation shutdown")
	}
	d.shutdownMu.Lock()
	defer d.shutdownMu.Unlock()
	if d.shutdownOwner != dispatcherShutdownUnowned {
		return nil, errors.New("dispatcher observation shutdown already has an owner")
	}
	d.shutdownOwner = dispatcherShutdownInstance
	d.shutdownDone = make(chan struct{})
	return &dispatcherObservationShutdown{dispatcher: d}, nil
}

// JoinShutdown seals dispatcher publication and waits for every admitted
// routed-dispatch task while the dependencies and flow registry remain alive.
func (s *dispatcherObservationShutdown) JoinShutdown() error {
	if s == nil || s.dispatcher == nil {
		return errors.New("nil dispatcher observation shutdown")
	}
	d := s.dispatcher
	d.SignalStop()
	d.joinOnce.Do(func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				d.joinErr = errors.New("dispatcher shutdown join panic: ", recovered)
			}
		}()
		d.lifecycle.Wait()
	})
	return d.joinErr
}

// FinalizeObservation closes the flow registry only after all traffic owners
// have published their final receipts. Only the adopted capability exposes it.
func (s *dispatcherObservationShutdown) FinalizeObservation() error {
	if s == nil || s.dispatcher == nil {
		return errors.New("nil dispatcher observation shutdown")
	}
	d := s.dispatcher
	joinErr := s.JoinShutdown()
	if joinErr == nil {
		d.closeOnce.Do(func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					d.closeErr = errors.New("dispatcher observation finalization panic: ", recovered)
				}
			}()
			if d.flows != nil {
				d.flows.Close()
			}
		})
	}
	err := errors.Combine(joinErr, d.closeErr)
	d.completeShutdown(err)
	return err
}

func (d *DefaultDispatcher) completeShutdown(err error) {
	d.shutdownMu.Lock()
	defer d.shutdownMu.Unlock()
	if d.shutdownComplete {
		return
	}
	d.shutdownErr = err
	d.shutdownComplete = true
	close(d.shutdownDone)
}

func (*DefaultDispatcher) ShutdownPhase() features.ShutdownPhase {
	return features.ShutdownPhaseDispatcher
}

func (d *DefaultDispatcher) SignalStop() {
	if d != nil {
		d.lifecycle.Seal()
	}
}

// FlowObserver exposes the bounded raw observation surface when registry
// initialization succeeded. It does not affect dispatcher availability.
func (d *DefaultDispatcher) FlowObserver() flow_observation.Observer {
	if d == nil || d.flows == nil {
		return nil
	}
	return d.flows
}

func (d *DefaultDispatcher) NewMuxCarrierObservation() session.MuxCarrierObservation {
	if d == nil || d.flows == nil {
		return nil
	}
	carrier := d.flows.NewMuxCarrierObservation()
	if carrier == nil {
		return nil
	}
	return carrier
}

// NewXUDPObservation is the additive nonzero-ID retained-link seam. It only
// delegates registry authority; it never changes dispatch or carrier traffic.
func (d *DefaultDispatcher) NewXUDPObservation(destination net.Destination, source string) session.XUDPEpochObservation {
	if d == nil || d.flows == nil {
		return nil
	}
	return d.flows.NewXUDPObservation(destination, source)
}

var (
	_ flow_observation.Provider             = (*DefaultDispatcher)(nil)
	_ session.MuxCarrierObservationProvider = (*DefaultDispatcher)(nil)
	_ session.MuxXUDPObservationProvider    = (*DefaultDispatcher)(nil)
)

func (d *DefaultDispatcher) getLink(ctx context.Context, handle *flow_observation.Handle) (*transport.Link, *transport.Link) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkOptions := append([]pipe.Option(nil), opt...)
	downlinkOptions := append([]pipe.Option(nil), opt...)
	if handle != nil && handle.LogicalRoot() != nil {
		uplinkOptions = append(uplinkOptions, pipe.WithWriteLifecycle(flow_observation.NativePipeLifecycle(handle.LogicalRoot().Uplink())))
		downlinkOptions = append(downlinkOptions, pipe.WithWriteLifecycle(flow_observation.NativePipeLifecycle(handle.LogicalRoot().Downlink())))
	}
	uplinkReader, uplinkWriter := pipe.New(uplinkOptions...)
	downlinkReader, downlinkWriter := pipe.New(downlinkOptions...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		p := d.policy.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := d.stats.GetOrRegisterCounter(name); c != nil {
				inboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  inboundLink.Writer,
				}
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := d.stats.GetOrRegisterCounter(name); c != nil {
				outboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  outboundLink.Writer,
				}
			}
		}

		if p.Stats.UserOnline {
			trackOnlineIP(ctx, d.stats, user.Email, sessionInbound.Source.Address.String())
		}
	}

	return inboundLink, outboundLink
}

func WrapLink(ctx context.Context, policyManager policy.Manager, statsManager stats.Manager, link *transport.Link) *transport.Link {
	var readLifecycle buf.ReadLifecycle
	if scope := flow_observation.ExternalOwnerScopeFromContext(ctx); scope != nil && scope.Handle() != nil {
		var bound bool
		readLifecycle, bound = flow_observation.BindExternalLinkIO(ctx, link)
		if !bound {
			scope.Handle().MarkAccountingBoundaryUnproven()
		}
	}
	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	link.Reader = &buf.TimeoutWrapperReader{
		Reader:             link.Reader,
		ParticipantTracker: task.ParticipantTrackerFromContext(ctx),
		ReadLifecycle:      readLifecycle,
	}

	if user != nil && len(user.Email) > 0 {
		p := policyManager.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := statsManager.GetOrRegisterCounter(name); c != nil {
				link.Reader.(*buf.TimeoutWrapperReader).Counter = c
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := statsManager.GetOrRegisterCounter(name); c != nil {
				link.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  link.Writer,
				}
			}
		}
		if p.Stats.UserOnline {
			trackOnlineIP(ctx, statsManager, user.Email, sessionInbound.Source.Address.String())
		}
	}

	return link
}

func trackOnlineIP(ctx context.Context, sm stats.Manager, email, ip string) {
	name := "user>>>" + email + ">>>online"
	if om, _ := sm.GetOrRegisterOnlineMap(name); om != nil {
		om.AddIP(ip)
		context.AfterFunc(ctx, func() { om.RemoveIP(ip) })
	}
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	if domain == "" {
		return false
	}
	if request.ExcludeForDomain != nil && request.ExcludeForDomain.MatchAny(strings.ToLower(domain)) {
		return false
	}
	if request.ExcludeForIP != nil && destination.Address.Family().IsIP() && request.ExcludeForIP.Match(destination.Address.IP()) {
		return false
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	muxSessionScope := flow_observation.MuxSessionScopeFromContext(ctx)
	xudpScope := flow_observation.XUDPObservationFromContext(ctx)
	if flow_observation.HasFlowObservation(ctx) || flow_observation.ExternalOwnerScopeFromContext(ctx) != nil {
		ctx = flow_observation.ContextWithoutFlowObservation(ctx)
	}
	if muxSessionScope != nil {
		ctx = flow_observation.ContextWithMuxSessionScope(ctx, muxSessionScope)
	}
	if xudpScope != nil {
		ctx = xudpScope.Context(ctx)
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sniffingRequest := content.SniffingRequest
	var flowHandle *flow_observation.Handle
	if d.flows != nil {
		switch destination.Network {
		case net.Network_TCP:
			if muxSessionScope != nil {
				flowHandle = d.flows.AdmitMuxTCP(muxSessionScope, destination)
			} else if !session.IsMultiplexedLogicalSession(ctx) {
				source := ""
				if inbound := session.InboundFromContext(ctx); inbound != nil {
					source = inbound.Source.String()
				}
				flowHandle = d.flows.AdmitTCP(ctx, source, destination.String(), content.Protocol, flow_observation.ByteScopeLogicalLinkAccepted)
			}
		case net.Network_UDP:
			if xudpScope != nil {
				flowHandle = d.flows.AdmitXUDP(xudpScope, destination)
			} else if muxSessionScope != nil {
				flowHandle = d.flows.AdmitMuxUDP(muxSessionScope, destination)
			} else if !session.IsMultiplexedLogicalSession(ctx) {
				source := ""
				if inbound := session.InboundFromContext(ctx); inbound != nil {
					source = inbound.Source.String()
				}
				flowHandle = d.flows.AdmitUDPAssociation(ctx, source, destination.String(), content.Protocol)
			}
		}
		if flowHandle != nil {
			flowHandle.TrackOwnedRootLink()
			ctx = flow_observation.ContextWithHandle(ctx, flowHandle)
			if muxSessionScope == nil {
				ctx = flow_observation.ContextWithRootDispatchOwner(ctx, flowHandle)
			}
		}
	}
	inbound, outbound := d.getLink(ctx, flowHandle)
	runAsync := func(action func()) bool {
		if !d.lifecycle.Acquire() {
			return false
		}
		var participant task.ParticipantLease
		if muxSessionScope != nil && flowHandle != nil {
			participant = muxSessionScope.AcquireParticipant()
		}
		go func() {
			defer d.lifecycle.Release()
			if participant != nil {
				defer participant.Release(nil)
			}
			action()
		}()
		return true
	}
	if !sniffingRequest.Enabled {
		if !runAsync(func() { d.routedDispatch(ctx, outbound, destination) }) {
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
		}
	} else {
		if !runAsync(func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				protocol := result.Protocol()
				if resComp, ok := result.(SnifferResultComposite); ok {
					protocol = resComp.ProtocolForDomainResult()
				}
				isFakeIP := false
				if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
					isFakeIP = true
				}
				if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}) {
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
		}
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) (dispatchErr error) {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}
	externalOwnerScope := flow_observation.ExternalOwnerScopeFromContext(ctx)
	redispatchScope, internalContinuation := flow_observation.ConsumeLoopbackContinuation(ctx, outbound)
	if redispatchScope != nil {
		externalOwnerScope = nil
		ctx = redispatchScope.Context(ctx)
		defer func() { redispatchScope.Release(dispatchErr) }()
	} else if internalContinuation {
		externalOwnerScope = nil
		ctx = flow_observation.ContextWithoutFlowObservation(ctx)
	} else if flow_observation.HasFlowObservation(ctx) {
		externalOwnerScope = nil
		ctx = flow_observation.ContextWithoutUnprovenRedispatch(ctx)
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	if externalOwnerScope != nil {
		var handle *flow_observation.Handle
		if d.flows != nil && destination.Network == net.Network_TCP {
			source := ""
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				source = inbound.Source.String()
			}
			handle = d.flows.AdmitExternalTCP(ctx, source, destination.String(), content.Protocol, externalOwnerScope, outbound)
		} else if d.flows != nil && destination.Network == net.Network_UDP {
			source := ""
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				source = inbound.Source.String()
			}
			handle = d.flows.AdmitExternalUDP(ctx, source, destination.String(), content.Protocol, externalOwnerScope, outbound)
		}
		if handle != nil {
			ctx = flow_observation.ContextWithHandle(ctx, handle)
		} else {
			externalOwnerScope = nil
			ctx = flow_observation.ContextWithoutFlowObservation(ctx)
		}
	}
	outbound = WrapLink(ctx, d.policy, d.stats, outbound)
	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled {
		d.routedDispatch(ctx, outbound, destination)
	} else {
		cReader := &cachedReader{
			reader: outbound.Reader.(buf.TimeoutReader),
		}
		outbound.Reader = cReader
		result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
		if err == nil {
			content.Protocol = result.Protocol()
		}
		if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
			domain := result.Domain()
			errors.LogInfo(ctx, "sniffed domain: ", domain)
			destination.Address = net.ParseAddress(domain)
			protocol := result.Protocol()
			if resComp, ok := result.(SnifferResultComposite); ok {
				protocol = resComp.ProtocolForDomainResult()
			}
			isFakeIP := false
			if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
				isFakeIP = true
			}
			if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
		d.routedDispatch(ctx, outbound, destination)
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := buf.NewWithSize(32767)
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		cacheDeadline := 200 * time.Millisecond
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				cachingStartingTimeStamp := time.Now()
				err := cReader.Cache(payload, cacheDeadline)
				if err != nil {
					return nil, err
				}
				cachingTimeElapsed := time.Since(cachingStartingTimeStamp)
				cacheDeadline -= cachingTimeElapsed

				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					switch err {
					case common.ErrNoClue: // No Clue: protocol not matches, and sniffer cannot determine whether there will be a match or not
						totalAttempt++
					case protocol.ErrProtoNeedMoreData: // Protocol Need More Data: protocol matches, but need more data to complete sniffing
						// in this case, do not add totalAttempt(allow to read until timeout)
					default:
						return result, err
					}
				} else {
					totalAttempt++
				}
				if totalAttempt >= 2 || cacheDeadline <= 0 {
					return nil, errSniffingTimeout
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	rootOwner := flow_observation.RootDispatchOwnerFromContext(ctx)
	redispatchScope := flow_observation.RedispatchScopeFromContext(ctx)
	externalOwnerScope := flow_observation.ExternalOwnerScopeFromContext(ctx)
	muxSessionScope := flow_observation.MuxSessionScopeFromContext(ctx)
	flowHandle := rootOwner
	flowDepth := uint32(0)
	if redispatchScope != nil {
		flowHandle = redispatchScope.Handle()
		flowDepth = redispatchScope.Depth()
	} else if externalOwnerScope != nil {
		flowHandle = externalOwnerScope.Handle()
	} else if muxSessionScope != nil {
		flowHandle = flow_observation.HandleFromContext(ctx)
	}
	if rootOwner != nil {
		defer flowHandle.HandlerReturned(ctx, destination.String())
	}
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]

	var handler outbound.Handler
	var handlerEntry outbound.HandlerEntry
	matchedRuleTag := ""
	enterTagged := func(tag string) outbound.Handler {
		if manager, ok := d.ohm.(outbound.GenerationManager); ok {
			entry, err := manager.EnterHandler(ctx, tag)
			if err != nil {
				return nil
			}
			handlerEntry = entry
			ctx = entry.Context()
			return entry.Handler()
		}
		return d.ohm.GetHandler(tag)
	}
	enterDefault := func() outbound.Handler {
		if manager, ok := d.ohm.(outbound.GenerationManager); ok {
			entry, err := manager.EnterDefaultHandler(ctx)
			if err != nil {
				return nil
			}
			handlerEntry = entry
			ctx = entry.Context()
			return entry.Handler()
		}
		return d.ohm.GetDefaultHandler()
	}

	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := enterTagged(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			if rootOwner != nil {
				flowHandle.Rejected("MISSING_FORCED_OUTBOUND")
			} else if redispatchScope != nil {
				flowHandle.RecordOutcome(flow_observation.TerminalClassLocalError, "MISSING_FORCED_OUTBOUND")
			} else if externalOwnerScope != nil && flowHandle != nil {
				flowHandle.RejectedByExternalOwner("MISSING_FORCED_OUTBOUND")
			} else if muxSessionScope != nil && flowHandle != nil {
				flowHandle.RecordOutcome(flow_observation.TerminalClassLocalRejection, "MISSING_FORCED_OUTBOUND")
			}
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			matchedRuleTag = route.GetRuleTag()
			if h := enterTagged(outTag); h != nil {
				isPickRoute = 2
				if route.GetRuleTag() == "" {
					errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				} else {
					errors.LogInfo(ctx, "Hit route rule: [", route.GetRuleTag(), "] so taking detour [", outTag, "] for [", destination, "]")
				}
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				if rootOwner != nil {
					flowHandle.Rejected("MISSING_ROUTED_OUTBOUND")
				} else if redispatchScope != nil {
					flowHandle.RecordOutcome(flow_observation.TerminalClassLocalError, "MISSING_ROUTED_OUTBOUND")
				} else if externalOwnerScope != nil && flowHandle != nil {
					flowHandle.RejectedByExternalOwner("MISSING_ROUTED_OUTBOUND")
				} else if muxSessionScope != nil && flowHandle != nil {
					flowHandle.RecordOutcome(flow_observation.TerminalClassLocalRejection, "MISSING_ROUTED_OUTBOUND")
				}
				return // DO NOT CHANGE: the traffic shouldn't be processed by default outbound if the specified outbound tag doesn't exist (yet), e.g., VLESS Reverse Proxy
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = enterDefault()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		if rootOwner != nil {
			flowHandle.Rejected("MISSING_DEFAULT_OUTBOUND")
		} else if redispatchScope != nil {
			flowHandle.RecordOutcome(flow_observation.TerminalClassLocalError, "MISSING_DEFAULT_OUTBOUND")
		} else if externalOwnerScope != nil && flowHandle != nil {
			flowHandle.RejectedByExternalOwner("MISSING_DEFAULT_OUTBOUND")
		} else if muxSessionScope != nil && flowHandle != nil {
			flowHandle.RecordOutcome(flow_observation.TerminalClassLocalRejection, "MISSING_DEFAULT_OUTBOUND")
		}
		return
	}
	if handlerEntry != nil {
		defer handlerEntry.Release()
	}

	ob.Tag = handler.Tag()
	if flowHandle != nil {
		protocolName := ""
		if content := session.ContentFromContext(ctx); content != nil {
			protocolName = content.Protocol
		}
		handlerType := fmt.Sprintf("%T", handler)
		var carrierProof flow_observation.CarrierProof
		var observationIssues []flow_observation.Issue
		if muxSessionScope == nil {
			carrierProof, observationIssues = inspectHandlerCarrier(handler)
		}
		if rootOwner != nil {
			flowHandle.SelectRoot(matchedRuleTag, handler.Tag(), handlerType, ob.Target.String(), protocolName, true, carrierProof, observationIssues...)
		} else if muxSessionScope != nil {
			flowHandle.SelectRoot(matchedRuleTag, handler.Tag(), handlerType, ob.Target.String(), "", true, "")
		} else if externalOwnerScope != nil {
			if externalOwnerScope.AccountingBound() {
				flowHandle.SelectRoot(matchedRuleTag, handler.Tag(), handlerType, ob.Target.String(), protocolName, true, carrierProof, observationIssues...)
			} else {
				observationIssues = append(observationIssues, flow_observation.IssueExternalLinkUnsupported)
				flowHandle.SelectRoot(matchedRuleTag, handler.Tag(), handlerType, ob.Target.String(), protocolName, false, carrierProof, observationIssues...)
			}
		} else if redispatchScope != nil {
			flowHandle.BeginRedispatch(handler.Tag(), handlerType, matchedRuleTag, true, carrierProof, observationIssues...)
		}
	}
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	if flowHandle != nil {
		ctx = flow_observation.ContextWithLinkBinding(ctx, flowHandle, link, flowDepth)
	}
	handler.Dispatch(ctx, link)
}

// inspectHandlerCarrier reads only the immutable descriptor exposed by a
// cooperating owner class. Unknown/custom handlers fail carrier proof closed;
// the dispatch path never serializes their settings to obtain telemetry.
func inspectHandlerCarrier(handler outbound.Handler) (flow_observation.CarrierProof, []flow_observation.Issue) {
	observation, ok := flow_observation.HandlerCarrierObservation(handler)
	if !ok {
		return flow_observation.CarrierProofUnknown, []flow_observation.Issue{flow_observation.IssueCarrierProofUnknown}
	}
	return carrierObservationIssues(observation)
}

func carrierObservationIssues(observation flow_observation.CarrierObservation) (flow_observation.CarrierProof, []flow_observation.Issue) {
	proof := observation.Proof
	if proof != flow_observation.CarrierProofProven && proof != flow_observation.CarrierProofNotApplicable && proof != flow_observation.CarrierProofUnknown {
		proof = flow_observation.CarrierProofUnknown
	}
	if observation.MuxF2Required || observation.CarrierF2Required || observation.DialerProxyCarrierUnknown {
		proof = flow_observation.CarrierProofUnknown
	}
	issues := make([]flow_observation.Issue, 0, 3)
	if observation.MuxF2Required {
		issues = append(issues, flow_observation.IssueMuxCarrierF2Required)
	}
	if observation.CarrierF2Required {
		issues = append(issues, flow_observation.IssueCarrierF2Required)
	}
	if observation.DialerProxyCarrierUnknown {
		issues = append(issues, flow_observation.IssueDialerProxyCarrierUnknown)
	}
	if proof == flow_observation.CarrierProofUnknown && len(issues) == 0 {
		issues = append(issues, flow_observation.IssueCarrierProofUnknown)
	}
	return proof, issues
}
