package inbound

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.InboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.InboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

type AlwaysOnInboundHandler struct {
	proxyConfig    interface{}
	receiverConfig *proxyman.ReceiverConfig
	proxy          proxy.Inbound
	workers        []worker
	mux            *mux.Server
	tag            string
	closeMu        sync.Mutex
	closePrepared  bool
	closed         bool
	closing        bool
	closeDone      chan struct{}
	closeErr       error
	started        []worker
	starting       bool
	startDone      chan struct{}
	startFailed    bool
}

func NewAlwaysOnInboundHandler(ctx context.Context, tag string, receiverConfig *proxyman.ReceiverConfig, proxyConfig interface{}) (*AlwaysOnInboundHandler, error) {
	sniffingRequest, err := proxyman.BuildSniffingRequest(receiverConfig.SniffingSettings)
	if err != nil {
		return nil, err
	}
	src := net.TCPDestination(net.AnyIP, 0)
	if receiverConfig.Listen != nil {
		src.Address = receiverConfig.Listen.AsAddress()
	}
	if receiverConfig.PortList != nil && len(receiverConfig.PortList.Range) > 0 {
		src.Port = net.Port(receiverConfig.PortList.Range[0].From)
	}
	mss, err := internet.ToMemoryStreamConfig(receiverConfig.StreamSettings)
	if err != nil {
		return nil, errors.New("failed to parse stream config").Base(err).AtWarning()
	}

	newCtx := session.ContextWithInbound(ctx, &session.Inbound{Tag: tag, Source: src})
	newCtx = session.ContextWithContent(newCtx, &session.Content{SniffingRequest: sniffingRequest})
	newCtx = session.ContextWithStreamSettings(newCtx, mss)

	rawProxy, err := common.CreateObject(newCtx, proxyConfig)
	if err != nil {
		return nil, err
	}
	p, ok := rawProxy.(proxy.Inbound)
	if !ok {
		return nil, errors.New("not an inbound proxy.")
	}

	h := &AlwaysOnInboundHandler{
		receiverConfig: receiverConfig,
		proxyConfig:    proxyConfig,
		proxy:          p,
		mux:            mux.NewServer(ctx),
		tag:            tag,
	}

	uplinkCounter, downlinkCounter := getStatCounter(core.MustFromContext(ctx), tag)

	nl := p.Network()
	pl := receiverConfig.PortList
	address := receiverConfig.Listen.AsAddress()
	if address == nil {
		address = net.AnyIP
	}

	if receiverConfig.ReceiveOriginalDestination {
		if mss.SocketSettings == nil {
			mss.SocketSettings = &internet.SocketConfig{}
		}
		if mss.SocketSettings.Tproxy == internet.SocketConfig_Off {
			mss.SocketSettings.Tproxy = internet.SocketConfig_Redirect
		}
		mss.SocketSettings.ReceiveOriginalDestAddress = true
	}
	if pl == nil {
		if net.HasNetwork(nl, net.Network_UNIX) {
			errors.LogDebug(ctx, "creating unix domain socket worker on ", address)

			worker := &dsWorker{
				address:         address,
				proxy:           p,
				stream:          mss,
				tag:             tag,
				dispatcher:      h.mux,
				sniffingRequest: sniffingRequest,
				uplinkCounter:   uplinkCounter,
				downlinkCounter: downlinkCounter,
				ctx:             ctx,
			}
			h.workers = append(h.workers, worker)
		}
	}
	if pl != nil {
		for _, pr := range pl.Range {
			for port := pr.From; port <= pr.To; port++ {
				if net.HasNetwork(nl, net.Network_TCP) {
					errors.LogDebug(ctx, "creating stream worker on ", address, ":", port)

					worker := &tcpWorker{
						address:         address,
						port:            net.Port(port),
						proxy:           p,
						stream:          mss,
						recvOrigDest:    receiverConfig.ReceiveOriginalDestination,
						tag:             tag,
						dispatcher:      h.mux,
						sniffingRequest: sniffingRequest,
						uplinkCounter:   uplinkCounter,
						downlinkCounter: downlinkCounter,
						ctx:             ctx,
					}
					h.workers = append(h.workers, worker)
				}

				if net.HasNetwork(nl, net.Network_UDP) {
					worker := &udpWorker{
						tag:             tag,
						proxy:           p,
						address:         address,
						port:            net.Port(port),
						dispatcher:      h.mux,
						sniffingRequest: sniffingRequest,
						uplinkCounter:   uplinkCounter,
						downlinkCounter: downlinkCounter,
						stream:          mss,
						ctx:             ctx,
					}
					h.workers = append(h.workers, worker)
				}
			}
		}
	}

	return h, nil
}

// Start implements common.Runnable.
func (h *AlwaysOnInboundHandler) Start() error {
	h.closeMu.Lock()
	if h.closePrepared || h.closed || h.closing || h.starting || h.startFailed {
		h.closeMu.Unlock()
		return errors.New("inbound handler is closing")
	}
	h.starting = true
	h.startDone = make(chan struct{})
	h.closeMu.Unlock()
	defer func() {
		h.closeMu.Lock()
		h.starting = false
		close(h.startDone)
		h.closeMu.Unlock()
	}()
	// for inbound without worker (TUN)
	if run, ok := h.proxy.(common.Runnable); ok {
		if err := run.Start(); err != nil {
			startErr := errors.New("failed to start proxy").Base(err)
			return errors.Combine(startErr, h.rollbackStart(h.workers))
		}
	}
	for _, worker := range h.workers {
		h.closeMu.Lock()
		h.started = append(h.started, worker)
		h.closeMu.Unlock()
		if err := worker.Start(); err != nil {
			return errors.Combine(err, h.rollbackStart(h.started))
		}
	}
	return nil
}

// Close implements common.Closable.
func (h *AlwaysOnInboundHandler) Close() error {
	h.closeMu.Lock()
	if h.starting {
		done := h.startDone
		h.closeMu.Unlock()
		<-done
		return h.Close()
	}
	if h.closed {
		err := h.closeErr
		h.closeMu.Unlock()
		return err
	}
	if h.closing {
		done := h.closeDone
		h.closeMu.Unlock()
		<-done
		h.closeMu.Lock()
		err := h.closeErr
		h.closeMu.Unlock()
		return err
	}
	h.closing = true
	h.closeDone = make(chan struct{})
	if !h.closePrepared {
		if preparer, ok := h.proxy.(interface{ PrepareClose() error }); ok {
			if err := preparer.PrepareClose(); err != nil {
				h.closeErr = err
				h.closing = false
				close(h.closeDone)
				h.closeMu.Unlock()
				return err
			}
		}
		h.closePrepared = true
	}
	workers := append([]worker(nil), h.started...)
	if len(workers) == 0 {
		workers = append(workers, h.workers...)
	}
	sealWorkers(workers)
	h.closeMu.Unlock()
	var errs []error
	errs = append(errs, stopWorkers(workers)...)
	errs = append(errs, h.mux.Close())
	errs = append(errs, common.Close(h.proxy))
	errs = append(errs, waitWorkers(workers)...)
	err := errors.Combine(errs...)
	var result error
	if err != nil {
		result = errors.New("failed to close all resources").Base(err)
	}
	h.closeMu.Lock()
	h.closed = true
	h.closing = false
	h.closeErr = result
	close(h.closeDone)
	h.closeMu.Unlock()
	return result
}

func (h *AlwaysOnInboundHandler) rollbackStart(workers []worker) error {
	h.closeMu.Lock()
	h.startFailed = true
	if !h.closePrepared {
		if preparer, ok := h.proxy.(interface{ PrepareClose() error }); ok {
			if err := preparer.PrepareClose(); err != nil {
				h.closeErr = err
				h.closeMu.Unlock()
				return err
			}
		}
		h.closePrepared = true
	}
	workers = append([]worker(nil), workers...)
	sealWorkers(workers)
	h.closeMu.Unlock()
	var errs []error
	errs = append(errs, stopWorkers(workers)...)
	errs = append(errs, h.mux.Close())
	errs = append(errs, common.Close(h.proxy))
	errs = append(errs, waitWorkers(workers)...)
	err := errors.Combine(errs...)
	h.closeMu.Lock()
	h.closed = true
	h.closeErr = err
	h.closeMu.Unlock()
	return err
}

func sealWorkers(workers []worker) {
	for _, worker := range workers {
		worker.Seal()
	}
}

func stopWorkers(workers []worker) []error {
	errs := make([]error, 0, len(workers))
	for _, worker := range workers {
		errs = append(errs, worker.Stop())
	}
	return errs
}

func waitWorkers(workers []worker) []error {
	errs := make([]error, 0, len(workers))
	for _, worker := range workers {
		errs = append(errs, worker.Wait())
	}
	return errs
}

func (h *AlwaysOnInboundHandler) Tag() string {
	return h.tag
}

func (h *AlwaysOnInboundHandler) GetInbound() proxy.Inbound {
	return h.proxy
}

// ReceiverSettings implements inbound.Handler.
func (h *AlwaysOnInboundHandler) ReceiverSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.receiverConfig)
}

// ProxySettings implements inbound.Handler.
func (h *AlwaysOnInboundHandler) ProxySettings() *serial.TypedMessage {
	if v, ok := h.proxyConfig.(proto.Message); ok {
		return serial.ToTypedMessage(v)
	}
	return nil
}
