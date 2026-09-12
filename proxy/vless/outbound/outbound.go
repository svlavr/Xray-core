package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	proxymanConfig "github.com/xtls/xray-core/app/proxyman"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse

	testpre   uint32
	initpre   sync.Once
	preConns  chan *ConnExpire
	ctx       context.Context
	cancel    context.CancelFunc
	producers task.Lifecycle
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	ownerCtx := ctx
	if lifecycle := internet.ResourceLifecycleFromContext(ctx); lifecycle != nil {
		ownerCtx = lifecycle.Context()
	}
	handlerCtx, handlerCancel := context.WithCancel(ownerCtx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
		ctx:           handlerCtx,
		cancel:        handlerCancel,
		closeDone:     make(chan struct{}),
	}
	committed := false
	defer func() {
		if !committed {
			handlerCancel()
		}
	}()

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		rvsCtx := session.ContextWithInbound(handlerCtx, &session.Inbound{
			Tag:  a.Reverse.Tag,
			Name: "vless-reverse",
			User: handler.server.User, // TODO: email
		})
		if sc := a.Reverse.Sniffing; sc != nil && sc.Enabled {
			request, err := proxymanConfig.BuildSniffingRequest(sc)
			if err != nil {
				return nil, errors.New("failed to build reverse sniffing request").Base(err).AtError()
			}
			rvsCtx = session.ContextWithContent(rvsCtx, &session.Content{
				SniffingRequest: request,
			})
		}
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx:        rvsCtx,
			handler:    handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		if handler.producers.Acquire() {
			go func() {
				defer handler.producers.Release()
				timer := time.NewTimer(2 * time.Second)
				defer timer.Stop()
				select {
				case <-handler.ctx.Done():
					return
				case <-timer.C:
				}
				_ = handler.reverse.Start()
			}()
		}
	}

	handler.testpre = a.Testpre

	committed = true
	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		h.producers.Seal()
		h.cancel()
		if h.reverse != nil {
			h.closeErr = h.reverse.Close()
		}
		h.producers.Wait()
		close(h.closeDone)
	})
	<-h.closeDone
	return h.closeErr
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection

	if h.testpre > 0 && h.reverse == nil {
		h.initpre.Do(func() {
			h.preConns = make(chan *ConnExpire)
			for range h.testpre { // TODO: randomize
				if !h.producers.Acquire() {
					break
				}
				go func() {
					defer h.producers.Release()
					workerCtx := xctx.ContextWithID(h.ctx, session.NewID())
					for {
						if err := workerCtx.Err(); err != nil {
							return
						}
						conn, err := dialer.Dial(workerCtx, rec.Destination)
						if err != nil {
							if workerCtx.Err() != nil {
								return
							}
							errors.LogWarningInner(workerCtx, err, "pre-connect failed")
							continue
						}
						select {
						case h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)}: // TODO: customize & randomize
						case <-workerCtx.Done():
							_ = conn.Close()
							return
						}
						timer := time.NewTimer(time.Millisecond * 200) // TODO: customize & randomize
						select {
						case <-timer.C:
						case <-workerCtx.Done():
							if !timer.Stop() {
								select {
								case <-timer.C:
								default:
								}
							}
							return
						}
					}
				}()
			}
		})
		for {
			var connTime *ConnExpire
			select {
			case connTime = <-h.preConns:
			case <-h.ctx.Done():
				return errors.New("closed handler").AtWarning()
			}
			if err := h.ctx.Err(); err != nil {
				_ = connTime.Conn.Close()
				return errors.New("closed handler").Base(err).AtWarning()
			}
			if time.Now().Before(connTime.Expire) {
				conn = connTime.Conn
				break
			}
			connTime.Conn.Close()
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return errors.New("failed to find an available destination").Base(err).AtWarning()
		}
	}
	defer conn.Close()

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			var t reflect.Type
			var p uintptr
			if commonConn, ok := conn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.CanSpliceCopy = 3 // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
				}
				t = reflect.TypeOf(commonConn).Elem()
				p = uintptr(unsafe.Pointer(commonConn))
			} else if tlsConn, ok := iConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(tlsConn.Conn))
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(utlsConn.Conn))
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(realityConn.Conn))
			} else {
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
		default:
			panic("unknown VLESS request command")
		}
	default:
		ob.CanSpliceCopy = 3
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = core.ContextWithoutRequestCancellation(ctx)
		defer newCancel()
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == vless.XRV {
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
		}
		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseTask := task.OnSuccess(getResponse, task.Close(clientWriter))
	var err error
	if newCtx == nil {
		err = task.Run(ctx, postRequest, responseTask)
	} else {
		var copies task.Lifecycle
		trackCopy := func(copyTask func() error) func() error {
			copies.Acquire()
			return func() error {
				defer copies.Release()
				return copyTask()
			}
		}
		err = task.Run(ctx, trackCopy(postRequest), trackCopy(responseTask))
		cancel()
		newCancel()
		_ = conn.Close()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		copies.Seal()
		copies.Wait()
		_ = timer.CloseAndWait()
	}
	if err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	mu          sync.Mutex
	startMu     sync.Mutex
	sealed      bool
	tag         string
	dispatcher  routing.Dispatcher
	ctx         context.Context
	handler     *Handler
	workers     []*reverse.BridgeWorker
	monitorTask *task.Periodic
}

func (r *Reverse) monitor() error {
	r.mu.Lock()
	if r.sealed {
		r.mu.Unlock()
		return nil
	}
	workers := append([]*reverse.BridgeWorker(nil), r.workers...)
	r.mu.Unlock()
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		} else {
			_ = w.Close()
		}
	}
	r.mu.Lock()
	if r.sealed {
		r.mu.Unlock()
		return nil
	}
	if len(activeWorkers) != len(workers) {
		r.workers = activeWorkers
	}
	workers = append(workers[:0], r.workers...)
	r.mu.Unlock()

	var numConnections uint32
	var numWorker uint32
	for _, w := range workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		if !r.handler.producers.Acquire() {
			return errors.New("VLESS reverse generation is closed")
		}
		committed := false
		defer func() {
			if !committed {
				r.handler.producers.Release()
			}
		}()
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(session.ContextWithIsReverseMux(r.ctx, true), w, link1)
		if err != nil {
			common.Interrupt(reader1)
			common.Interrupt(reader2)
			common.Interrupt(writer1)
			common.Interrupt(writer2)
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.mu.Lock()
		if r.sealed {
			r.mu.Unlock()
			_ = w.Close()
			common.Interrupt(reader1)
			common.Interrupt(reader2)
			common.Interrupt(writer1)
			common.Interrupt(writer2)
			return nil
		}
		r.workers = append(r.workers, w)
		r.mu.Unlock()
		go func() {
			defer r.handler.producers.Release()
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
		committed = true
	}
	return nil
}

func (r *Reverse) Start() error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	r.mu.Lock()
	if r.sealed {
		r.mu.Unlock()
		return errors.New("VLESS reverse generation is closed")
	}
	r.mu.Unlock()
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	r.startMu.Lock()
	r.mu.Lock()
	r.sealed = true
	workers := append([]*reverse.BridgeWorker(nil), r.workers...)
	r.mu.Unlock()
	_ = r.monitorTask.Close()
	r.startMu.Unlock()
	for _, worker := range workers {
		worker.SignalStop()
	}
	var closeErrors []error
	closeErrors = append(closeErrors, r.monitorTask.CloseAndWait())
	r.mu.Lock()
	workers = append(workers[:0], r.workers...)
	r.workers = nil
	r.mu.Unlock()
	for _, worker := range workers {
		closeErrors = append(closeErrors, worker.Close())
	}
	return errors.Combine(closeErrors...)
}
