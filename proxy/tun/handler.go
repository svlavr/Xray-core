package tun

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	ctx                  context.Context
	config               *Config
	stack                Stack
	tun                  Tun
	policyManager        policy.Manager
	dispatcher           routing.Dispatcher
	tag                  string
	sniffingRequest      session.SniffingRequest
	uplinkCounter        stats.Counter
	downlinkCounter      stats.Counter
	updater              *InterfaceUpdater
	unregisterController func()
	controllerMu         sync.Mutex
}

// tunUDPStatsWriter preserves the synthetic udpConn buf.Writer boundary while
// counting only packets accepted by its WriteMultiBuffer implementation.
type tunUDPStatsWriter struct {
	writer  buf.Writer
	counter stats.Counter
}

func (w *tunUDPStatsWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	accepted := int64(mb.Len())
	if err := w.writer.WriteMultiBuffer(mb); err != nil {
		return err
	}
	if w.counter != nil {
		w.counter.Add(accepted)
	}
	return nil
}

func (w *tunUDPStatsWriter) Close() error {
	return common.Close(w.writer)
}

func (w *tunUDPStatsWriter) Interrupt() {
	common.Interrupt(w.writer)
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

// Handler implements common.Runnable
var _ common.Runnable = (*Handler)(nil)

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	// Retrieve tag and sniffing config from context (set by AlwaysOnInboundHandler)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		t.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		t.sniffingRequest = content.SniffingRequest
	}

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher

	if len(t.tag) > 0 && pm.ForSystem().Stats.InboundUplink {
		statsManager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + t.tag + ">>>traffic>>>uplink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			t.uplinkCounter = c
		}
	}
	if len(t.tag) > 0 && pm.ForSystem().Stats.InboundDownlink {
		statsManager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + t.tag + ">>>traffic>>>downlink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			t.downlinkCounter = c
		}
	}

	return nil
}

func (t *Handler) Start() error {
	tunName := t.config.Name
	tunInterface, err := NewTun(t.config)
	if err != nil {
		return err
	}

	if t.config.AutoOutboundsInterface != "" {
		tunIndex, err := tunInterface.Index()
		if err != nil {
			_ = tunInterface.Close()
			return err
		}
		if t.config.AutoOutboundsInterface == "auto" {
			t.config.AutoOutboundsInterface = ""
		}
		t.updater = &InterfaceUpdater{tunIndex: tunIndex, fixedName: t.config.AutoOutboundsInterface}
		t.updater.Update()
		if owner, ok := tunInterface.(interface{ setInterfaceUpdater(*InterfaceUpdater) }); ok {
			owner.setInterfaceUpdater(t.updater)
		}
		unregister, err := internet.RegisterDialerControllerContext(t.ctx, func(network, address string, c syscall.RawConn) error {
			iface := t.updater.Get()
			if iface == nil {
				return errors.New("[tun] failed to set interface: interface unavailable")
			}
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				addrPort, _ := netip.ParseAddrPort(address)
				// skip loopback
				if addrPort.Addr().IsLoopback() || strings.HasPrefix(strings.ToLower(address), "localhost:") {
					return
				}
				controlErr = setinterface(network, address, fd, iface)
			}); err != nil {
				return err
			}
			return controlErr
		})
		if err != nil {
			_ = tunInterface.Close()
			return err
		}
		t.controllerMu.Lock()
		t.unregisterController = unregister
		t.controllerMu.Unlock()
	}

	errors.LogInfo(t.ctx, tunName, " created")

	tunStackOptions := StackOptions{
		Tun:         tunInterface,
		IdleTimeout: t.policyManager.ForLevel(t.config.UserLevel).Timeouts.ConnectionIdle,
	}
	tunStack, err := NewStack(t.ctx, tunStackOptions, t)
	if err != nil {
		_ = tunInterface.Close()
		t.unregisterDialerController()
		return err
	}

	err = tunStack.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		t.unregisterDialerController()
		return err
	}

	err = tunInterface.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		t.unregisterDialerController()
		return err
	}

	t.stack = tunStack
	t.tun = tunInterface

	errors.LogInfo(t.ctx, tunName, " up")
	return nil
}

// HandleConnection pass the connection coming from the ip stack to the routing dispatcher
func (t *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	// when handling is done with any outcome, always signal back to the incoming connection
	// to close, send completion packets back to the network, and cleanup
	var ownerScope *flow_observation.ExternalOwnerScope
	var dispatchErr error
	defer func() {
		closeErr := conn.Close()
		if ownerScope != nil {
			ownerScope.AfterOwnerClose(dispatchErr, closeErr)
		}
	}()

	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())

	// if the connection is already closed, conn.RemoteAddr() will be nil
	// due to gvisor weird behavior
	remote := conn.RemoteAddr()
	if remote == nil {
		errors.LogInfo(t.ctx, "dropped quickly closed connection")
		return
	}
	source := net.DestinationFromAddr(remote)
	if destination.Network != net.Network_UDP && (t.uplinkCounter != nil || t.downlinkCounter != nil) {
		conn = &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  t.uplinkCounter,
			WriteCounter: t.downlinkCounter,
		}
	}

	inbound := session.Inbound{
		Name:          "tun",
		Tag:           t.tag,
		CanSpliceCopy: 3,
		Source:        source,
		User: &protocol.MemoryUser{
			Level: t.config.UserLevel,
		},
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: t.sniffingRequest,
	})
	if destination.Network == net.Network_TCP {
		ownerScope = flow_observation.NewExternalOwnerScope(flow_observation.ExternalOwnerTUNTCP)
	} else if destination.Network == net.Network_UDP {
		ownerScope = flow_observation.NewExternalOwnerScope(flow_observation.ExternalOwnerTUNUDP)
	}
	if ownerScope != nil {
		ctx = flow_observation.ContextWithExternalOwnerScope(ctx, ownerScope)
	}
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", destination)

	reader := buf.NewReader(conn)
	writer := buf.NewWriter(conn)
	var readCounter stats.Counter
	if destination.Network == net.Network_UDP {
		writer = &tunUDPStatsWriter{writer: writer, counter: t.downlinkCounter}
		readCounter = t.uplinkCounter
	}
	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: reader, Counter: readCounter},
		Writer: writer,
	}
	dispatchErr = t.dispatcher.DispatchLink(ctx, destination, link)
	if dispatchErr != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(dispatchErr))
	}
}

// Close implements common.Closable.
func (t *Handler) Close() error {
	err := errors.Combine(common.CloseIfExists(t.stack), common.CloseIfExists(t.tun))
	t.unregisterDialerController()
	return err
}

func (t *Handler) unregisterDialerController() {
	t.controllerMu.Lock()
	unregister := t.unregisterController
	t.unregisterController = nil
	t.controllerMu.Unlock()
	if unregister != nil {
		unregister()
	}
}

// Network implements proxy.Inbound
// and exists only to comply to proxy interface, declaring it doesn't listen on any network,
// making the process not open any port for this inbound (input will be network interface)
func (t *Handler) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound
// and exists only to comply to proxy interface, which should never get any inputs due to no listening ports
func (t *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		t := &Handler{config: config.(*Config)}
		err := core.RequireFeatures(ctx, func(pm policy.Manager, dispatcher routing.Dispatcher) error {
			return t.Init(ctx, pm, dispatcher)
		})
		return t, err
	}))
}
