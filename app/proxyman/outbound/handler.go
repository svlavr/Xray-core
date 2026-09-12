package outbound

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/dice"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

// Handler implements outbound.Handler.
type Handler struct {
	tag             string
	senderSettings  *proxyman.SenderConfig
	streamSettings  *internet.MemoryStreamConfig
	proxyConfig     proto.Message
	proxy           proxy.Outbound
	mux             *mux.ClientManager
	xudp            *mux.ClientManager
	udp443          string
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
	flowCarrier     flow_observation.CarrierObservation
	generation      atomic.Pointer[core.RetirementGeneration]
	stopOnce        sync.Once
	waitOnce        sync.Once
	proxyCloseDone  chan struct{}
	closeErr        error
	lifecycleCtx    context.Context
	resources       *internet.ResourceLifecycle
}

// NewHandler creates a new Handler based on the given configuration.
func NewHandler(ctx context.Context, config *core.OutboundHandlerConfig) (outbound.Handler, error) {
	v := core.MustFromContext(ctx)
	uplinkCounter, downlinkCounter := getStatCounter(v, config.Tag)
	resourceLifecycle := internet.NewResourceLifecycle(ctx)
	ctx = internet.ContextWithResourceLifecycle(ctx, resourceLifecycle)
	committed := false
	defer func() {
		if !committed {
			_ = resourceLifecycle.CloseAndWait()
		}
	}()
	h := &Handler{
		tag:             config.Tag,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
		lifecycleCtx:    ctx,
		resources:       resourceLifecycle,
	}

	if config.SenderSettings != nil {
		senderSettings, err := config.SenderSettings.GetInstance()
		if err != nil {
			return nil, err
		}
		switch s := senderSettings.(type) {
		case *proxyman.SenderConfig:
			h.senderSettings = s
			mss, err := internet.ToMemoryStreamConfig(s.StreamSettings)
			if err != nil {
				return nil, errors.New("failed to parse stream settings").Base(err).AtWarning()
			}
			h.streamSettings = mss
			h.streamSettings.ResourceLifecycle = resourceLifecycle
		default:
			return nil, errors.New("settings is not SenderConfig")
		}
	}

	proxyConfig, err := config.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	h.proxyConfig = proxyConfig

	ctx = session.ContextWithFullHandler(ctx, h)

	if h.streamSettings != nil {
		ctx = session.ContextWithStreamSettings(ctx, h.streamSettings)
	}

	rawProxyHandler, err := common.CreateObject(ctx, proxyConfig)
	if err != nil {
		return nil, err
	}

	proxyHandler, ok := rawProxyHandler.(proxy.Outbound)
	if !ok {
		return nil, errors.New("not an outbound handler")
	}

	if h.senderSettings != nil && h.senderSettings.MultiplexSettings != nil {
		if config := h.senderSettings.MultiplexSettings; config.Enabled {
			if config.Concurrency < 0 {
				h.mux = &mux.ClientManager{Enabled: false}
			}
			if config.Concurrency == 0 {
				config.Concurrency = 8 // same as before
			}
			if config.Concurrency > 0 {
				h.mux = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:   proxyHandler,
							Dialer:  h,
							Context: ctx,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.Concurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			if config.XudpConcurrency < 0 {
				h.xudp = &mux.ClientManager{Enabled: false}
			}
			if config.XudpConcurrency == 0 {
				h.xudp = nil // same as before
			}
			if config.XudpConcurrency > 0 {
				h.xudp = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:   proxyHandler,
							Dialer:  h,
							Context: ctx,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.XudpConcurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			h.udp443 = config.XudpProxyUDP443
		}
	}

	h.proxy = proxyHandler
	h.flowCarrier = classifyFlowCarrierObservation(h.streamSettings, h.mux != nil && h.mux.Enabled)
	committed = true
	return h, nil
}

func classifyFlowCarrierObservation(stream *internet.MemoryStreamConfig, muxEnabled bool) flow_observation.CarrierObservation {
	observation := flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofNotApplicable}
	markUnknown := func() {
		observation.Proof = flow_observation.CarrierProofUnknown
	}
	if muxEnabled {
		markUnknown()
		observation.MuxF2Required = true
	}
	if stream == nil {
		return observation
	}
	switch stream.ProtocolName {
	case "tcp", "websocket", "httpupgrade":
	case "udp", "mkcp", "hysteria", "splithttp", "grpc":
		markUnknown()
		observation.CarrierF2Required = true
	default:
		markUnknown()
	}
	if stream.SocketSettings != nil && stream.SocketSettings.GetDialerProxy() != "" {
		markUnknown()
		observation.DialerProxyCarrierUnknown = true
	}
	return observation
}

// Tag implements outbound.Handler.
func (h *Handler) Tag() string {
	return h.tag
}

// Dispatch implements proxy.Outbound.Dispatch.
func (h *Handler) Dispatch(ctx context.Context, link *transport.Link) {
	ctx = internet.ContextWithResourceLifecycle(ctx, h.resources)
	if generation := h.generation.Load(); generation != nil {
		if right := core.RetirementRightFromContext(ctx); right == nil || !right.LiveFor(generation) {
			enteredCtx, entered, err := core.EnterRetirement(ctx, generation)
			if err != nil {
				common.Interrupt(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
			ctx = enteredCtx
			defer entered.Release()
		} else if ctx.Err() != nil {
			common.Interrupt(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	}
	stopOnGenerationSeal := context.AfterFunc(ctx, func() {
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	})
	defer stopOnGenerationSeal()
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	content := session.ContentFromContext(ctx)
	if h.senderSettings != nil && h.senderSettings.TargetStrategy.HasStrategy() && ob.Target.Address.Family().IsDomain() && (content == nil || !content.SkipDNSResolve) {
		strategy := h.senderSettings.TargetStrategy
		if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil {
			strategy = strategy.GetDynamicStrategy(ob.OriginalTarget.Address.Family())
		}
		ips, err := internet.LookupForIPContext(ctx, ob.Target.Address.Domain(), strategy, nil)
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to resolve ip for target ", ob.Target.Address.Domain())
			if h.senderSettings.TargetStrategy.ForceIP() {
				err := errors.New("failed to resolve ip for target ", ob.Target.Address.Domain()).Base(err)
				submitOutboundError(ctx, err)
				common.Interrupt(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
		} else {
			unchangedDomain := ob.Target.Address.Domain()
			ob.Target.Address = net.IPAddress(ips[dice.Roll(len(ips))])
			errors.LogInfo(ctx, "target: ", unchangedDomain, " resolved to: ", ob.Target.Address.String())
		}
	}
	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}
	if h.mux != nil {
		test := func(err error) {
			if err != nil {
				err := errors.New("failed to process mux outbound traffic").Base(err)
				submitOutboundError(ctx, err)
				errors.LogInfo(ctx, err.Error())
				common.Interrupt(link.Writer)
				common.Interrupt(link.Reader)
			}
		}
		if ob.Target.Network == net.Network_UDP && ob.Target.Port == 443 {
			switch h.udp443 {
			case "reject":
				test(errors.New("XUDP rejected UDP/443 traffic").AtInfo())
				return
			case "skip":
				goto out
			}
		}
		if h.xudp != nil && ob.Target.Network == net.Network_UDP {
			if !h.xudp.Enabled {
				goto out
			}
			test(h.xudp.Dispatch(ctx, link))
			return
		}
		if h.mux.Enabled {
			muxCtx := flow_observation.ContextWithMuxClientSessionObservation(ctx, h.tag)
			test(h.mux.Dispatch(muxCtx, link))
			return
		}
	}
out:
	err := h.proxy.Process(ctx, link, h)
	var errC error
	if err != nil {
		errC = errors.Cause(err)
		if goerrors.Is(errC, io.EOF) || goerrors.Is(errC, io.ErrClosedPipe) || goerrors.Is(errC, context.Canceled) {
			err = nil
		}
	}
	if err != nil {
		// Ensure outbound ray is properly closed.
		err := errors.New("failed to process outbound traffic").Base(err)
		submitOutboundError(ctx, err)
		errors.LogInfo(ctx, err.Error())
		common.Interrupt(link.Writer)
	} else {
		if errC != nil && goerrors.Is(errC, io.ErrClosedPipe) {
			common.Interrupt(link.Writer)
		} else {
			common.Close(link.Writer)
		}
	}
	common.Interrupt(link.Reader)
}

func submitOutboundError(ctx context.Context, err error) {
	flow_observation.SubmitErrorFromContext(ctx, err)
	session.SubmitOutboundErrorToOriginator(ctx, err)
}

func (h *Handler) DestIpAddress() net.IP {
	return internet.DestIpAddressForContext(h.lifecycleCtx)
}

// Dial implements internet.Dialer.
func (h *Handler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	if h.senderSettings != nil && h.senderSettings.Via != nil {
		outbounds := session.OutboundsFromContext(ctx)
		ob := outbounds[len(outbounds)-1]
		h.SetOutboundGateway(ctx, ob)
	}

	conn, err := internet.Dial(ctx, dest, h.streamSettings)
	conn = h.getStatCouterConnection(conn)
	return conn, err
}

func (h *Handler) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {
	if ob.Gateway == nil && h.senderSettings != nil && h.senderSettings.Via != nil &&
		(h.streamSettings.SocketSettings == nil || len(h.streamSettings.SocketSettings.DialerProxy) == 0) {
		var domain string
		addr := h.senderSettings.Via.AsAddress()
		domain = h.senderSettings.Via.GetDomain()
		switch {
		case h.senderSettings.ViaCidr != "":
			ob.Gateway = ParseRandomIP(addr, h.senderSettings.ViaCidr)
		case domain == "origin":
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				if inbound.Local.IsValid() && inbound.Local.Address.Family().IsIP() {
					ob.Gateway = inbound.Local.Address
					errors.LogDebug(ctx, "use inbound local ip as sendthrough: ", inbound.Local.Address.String())
				}
			}
		case domain == "srcip":
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				if inbound.Source.IsValid() && inbound.Source.Address.Family().IsIP() {
					ob.Gateway = inbound.Source.Address
					errors.LogDebug(ctx, "use inbound source ip as sendthrough: ", inbound.Source.Address.String())
				}
			}
		default: // case addr.Family().IsDomain():
			ob.Gateway = addr
		}
	}
}

func (h *Handler) getStatCouterConnection(conn stat.Connection) stat.Connection {
	if h.uplinkCounter != nil || h.downlinkCounter != nil {
		return &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  h.downlinkCounter,
			WriteCounter: h.uplinkCounter,
		}
	}
	return conn
}

// GetOutbound implements proxy.GetOutbound.
func (h *Handler) GetOutbound() proxy.Outbound {
	return h.proxy
}

// Start implements common.Runnable.
func (h *Handler) Start() error {
	return nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	h.SignalStop()
	h.waitOnce.Do(func() {
		// Proxy close has already been issued asynchronously, so either pool
		// may wait without preventing another handler's unblock phase.
		h.mux.Wait()
		h.xudp.Wait()
		<-h.proxyCloseDone
		if err := h.resources.CloseAndWait(); err != nil {
			h.closeErr = errors.Combine(h.closeErr, err)
		}
	})
	return h.closeErr
}

// SignalStop is the non-joining half of Handler shutdown. Manager invokes it
// for every exact generation before any closer waits.
func (h *Handler) SignalStop() {
	if h == nil {
		return
	}
	h.stopOnce.Do(func() {
		h.resources.SignalStop()
		h.mux.SignalStop()
		h.xudp.SignalStop()
		h.proxyCloseDone = make(chan struct{})
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					h.closeErr = errors.New("outbound proxy close panic: ", recovered)
				}
				close(h.proxyCloseDone)
			}()
			h.closeErr = common.Close(h.proxy)
		}()
	})
}

// Retire seals new picker invocations but does not cancel admitted work.
func (h *Handler) Retire() {
	if h == nil {
		return
	}
	h.mux.Retire()
	h.xudp.Retire()
}

func (h *Handler) BindRetirementGeneration(generation *core.RetirementGeneration) bool {
	return h != nil && generation != nil && h.generation.CompareAndSwap(nil, generation)
}

// BindMuxClientCarrierAuthority is write-once and deliberately affects only
// standard mux; xudp retains its existing unbound behavior.
func (h *Handler) BindMuxClientCarrierAuthority(provider session.MuxClientCarrierAuthorityProvider) bool {
	if h == nil || h.mux == nil || !h.mux.Enabled {
		return false
	}
	return h.mux.BindMuxClientCarrierAuthority(provider)
}

// SenderSettings implements outbound.Handler.
func (h *Handler) SenderSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.senderSettings)
}

// FlowCarrierObservation returns the immutable carrier descriptor prepared at
// construction time. It intentionally performs no serialization or I/O.
func (h *Handler) FlowCarrierObservation() flow_observation.CarrierObservation {
	return h.flowCarrier
}

// ProxySettings implements outbound.Handler.
func (h *Handler) ProxySettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.proxyConfig)
}

func ParseRandomIP(addr net.Address, prefix string) net.Address {
	_, ipnet, _ := net.ParseCIDR(addr.IP().String() + "/" + prefix)

	ones, bits := ipnet.Mask.Size()
	subnetSize := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))

	rnd, _ := rand.Int(rand.Reader, subnetSize)

	startInt := new(big.Int).SetBytes(ipnet.IP)
	rndInt := new(big.Int).Add(startInt, rnd)

	rndBytes := rndInt.Bytes()
	padded := make([]byte, len(ipnet.IP))
	copy(padded[len(padded)-len(rndBytes):], rndBytes)

	return net.ParseAddress(net.IP(padded).String())
}
