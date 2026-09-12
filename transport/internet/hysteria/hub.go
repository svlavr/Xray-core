package hysteria

import (
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type httpHandler struct {
	sync.Mutex

	validator   *account.Validator
	config      *Config
	masqHandler http.Handler
	quicParams  *internet.QuicParams
	conn        *quic.Conn
	listener    *Listener

	auth bool
	user *protocol.MemoryUser
}

func (h *httpHandler) AuthHTTP(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost && r.Host == URLHost && r.URL.Path == URLPath {
		h.Lock()
		defer h.Unlock()

		if h.auth {
			w.Header().Set(ResponseHeaderUDPEnabled, strconv.FormatBool(h.validator != nil))
			w.Header().Set(CommonHeaderCCRX, strconv.FormatUint(h.quicParams.BrutalDown, 10))
			w.Header().Set(CommonHeaderPadding, AuthResponsePadding.String())
			w.WriteHeader(StatusAuthOK)
			return true
		}

		auth := r.Header.Get(RequestHeaderAuth)
		down, _ := strconv.ParseUint(r.Header.Get(CommonHeaderCCRX), 10, 64)

		var user *protocol.MemoryUser
		var ok bool
		if h.validator != nil && h.validator.NotEmpty() {
			user = h.validator.Get(auth)
		} else if h.config.Auth != "" {
			ok = auth == h.config.Auth
		}

		if user != nil || ok {
			h.auth = true
			h.user = user

			conn := h.conn
			quicParams := h.quicParams
			switch quicParams.Congestion {
			case "reno":
			case "bbr":
				congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
			case "", "brutal":
				if quicParams.BrutalUp == 0 || down == 0 {
					congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
				} else {
					congestion.UseBrutal(conn, min(quicParams.BrutalUp, down), quicParams.BrutalDisableLossCompensation)
				}
			case "force-brutal":
				congestion.UseBrutal(conn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
			default:
				panic(quicParams.Congestion)
			}

			if h.validator != nil {
				managerCtx, managerCancel := context.WithCancel(h.listener.ctx)
				udpSM := &udpSessionManager{
					conn: h.conn,
					m:    make(map[uint32]*InterConn),

					addConn:        h.listener.dispatch,
					udpIdleTimeout: time.Duration(h.config.UdpIdleTimeout) * time.Second,
					user:           h.user,
					ctx:            managerCtx,
				}
				if h.listener.acquireBackground(3) {
					go func() {
						defer h.listener.lifecycle.Release()
						select {
						case <-h.conn.Context().Done():
							managerCancel()
						case <-managerCtx.Done():
						}
					}()
					go func() {
						defer h.listener.lifecycle.Release()
						defer managerCancel()
						udpSM.clean()
					}()
					go func() {
						defer h.listener.lifecycle.Release()
						udpSM.run()
					}()
				} else {
					managerCancel()
				}
			}

			w.Header().Set(ResponseHeaderUDPEnabled, strconv.FormatBool(h.validator != nil))
			w.Header().Set(CommonHeaderCCRX, strconv.FormatUint(h.quicParams.BrutalDown, 10))
			w.Header().Set(CommonHeaderPadding, AuthResponsePadding.String())
			w.WriteHeader(StatusAuthOK)
			return true
		}
	}
	return false
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.AuthHTTP(w, r) {
		return
	}
	h.masqHandler.ServeHTTP(w, r)
}

func (h *httpHandler) StreamDispatcher(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil || !h.auth {
		return false, nil
	}

	switch ft {
	case FrameTypeTCPRequest:
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}

		h.listener.dispatch(&interConn{
			stream: stream,
			local:  h.conn.LocalAddr(),
			remote: h.conn.RemoteAddr(),

			user:    h.user,
			handoff: new(internet.InboundHandoff),
		})
		return true, nil
	default:
		return false, nil
	}
}

type Listener struct {
	validator   *account.Validator
	config      *Config
	masqHandler http.Handler
	quicParams  *internet.QuicParams
	addConn     internet.ConnHandler

	pktConn   net.PacketConn
	tr        *quic.Transport
	listener  *quic.Listener
	lifecycle *internet.InboundLifecycle
	ctx       context.Context
	cancel    context.CancelFunc

	mu          sync.Mutex
	closed      bool
	connections map[*quic.Conn]struct{}
	callbacks   map[net.Conn]*internet.InboundHandoff
}

func (l *Listener) handleClient(conn *quic.Conn) {
	defer l.unregisterConnection(conn)
	handler := &httpHandler{
		validator:   l.validator,
		config:      l.config,
		masqHandler: l.masqHandler,
		quicParams:  l.quicParams,
		conn:        conn,
		listener:    l,
	}
	h3s := http3.Server{
		Handler:          handler,
		StreamDispatcher: handler.StreamDispatcher,
	}
	err := h3s.ServeQUICConn(conn)
	_ = conn.CloseWithError(closeErrCodeOK, "")
	errors.LogDebug(context.Background(), conn.RemoteAddr(), " ServeQUICConn exited with ", err)
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(l.ctx)
		if err != nil {
			if err != quic.ErrServerClosed {
				errors.LogErrorInner(context.Background(), err, "failed to serve hysteria")
			}
			break
		}
		if !l.registerConnection(conn) {
			_ = conn.CloseWithError(closeErrCodeOK, "")
			continue
		}
		go l.handleClient(conn)
	}
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	type callbackReceipt struct {
		conn    net.Conn
		handoff *internet.InboundHandoff
	}
	callbacks := make([]callbackReceipt, 0, len(l.callbacks))
	for conn, handoff := range l.callbacks {
		callbacks = append(callbacks, callbackReceipt{conn: conn, handoff: handoff})
	}
	l.mu.Unlock()
	l.cancel()
	for _, callback := range callbacks {
		callback.handoff.Reject()
		_ = callback.conn.Close()
	}
	return errors.Combine(l.listener.Close(), l.tr.Close(), l.pktConn.Close())
}

func (l *Listener) registerConnection(conn *quic.Conn) bool {
	if !l.lifecycle.Acquire() {
		return false
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		l.lifecycle.Release()
		return false
	}
	l.connections[conn] = struct{}{}
	l.mu.Unlock()
	return true
}

func (l *Listener) unregisterConnection(conn *quic.Conn) {
	l.mu.Lock()
	delete(l.connections, conn)
	l.mu.Unlock()
	l.lifecycle.Release()
}

func (l *Listener) dispatch(conn stat.Connection) {
	if l.lifecycle == nil {
		l.addConn(conn)
		return
	}
	if !l.registerCallback(conn) {
		internet.RejectInboundHandoff(conn)
		_ = conn.Close()
		return
	}
	go func() {
		defer l.unregisterCallback(conn)
		l.addConn(conn)
	}()
}

func (l *Listener) registerCallback(conn stat.Connection) bool {
	if !l.lifecycle.Acquire() {
		return false
	}
	handoff := inboundHandoff(conn)
	if handoff == nil {
		l.lifecycle.Release()
		return false
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		l.lifecycle.Release()
		return false
	}
	l.callbacks[conn] = handoff
	l.mu.Unlock()
	return true
}

func (l *Listener) unregisterCallback(conn stat.Connection) {
	l.mu.Lock()
	delete(l.callbacks, conn)
	l.mu.Unlock()
	l.lifecycle.Release()
}

func (l *Listener) acquireBackground(count int) bool {
	acquired := 0
	for acquired < count && l.lifecycle.Acquire() {
		acquired++
	}
	if acquired == count {
		return true
	}
	for range acquired {
		l.lifecycle.Release()
	}
	return false
}

func inboundHandoff(conn stat.Connection) *internet.InboundHandoff {
	switch conn := conn.(type) {
	case *interConn:
		return conn.handoff
	case *InterConn:
		return conn.handoff
	default:
		return nil
	}
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("address is domain")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	validator := ValidatorFromContext(ctx)
	config := streamSettings.ProtocolSettings.(*Config)

	if validator == nil && config.Auth == "" {
		return nil, errors.New("validator is nil")
	}

	var masqHandler http.Handler
	switch strings.ToLower(config.MasqType) {
	case "", "404":
		masqHandler = http.NotFoundHandler()
	case "file":
		masqHandler = http.FileServer(http.Dir(config.MasqFile))
	case "proxy":
		u, err := url.Parse(config.MasqUrl)
		if err != nil {
			return nil, err
		}
		transport := http.DefaultTransport.(*http.Transport)
		switch u.Scheme {
		case "http", "https":
			if config.MasqUrlInsecure {
				transport = transport.Clone()
				if transport.TLSClientConfig == nil {
					transport.TLSClientConfig = &gotls.Config{}
				}
				transport.TLSClientConfig.InsecureSkipVerify = true
			}
		case "", "unix":
			path := u.Path
			u = &url.URL{Scheme: "http", Host: "localhost"}
			dialer := &net.Dialer{Timeout: 30 * time.Second}
			transport = transport.Clone()
			transport.Proxy = nil
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", path)
			}
			transport.MaxIdleConns = masqueradeProxyMaxIdleConnections
			transport.MaxIdleConnsPerHost = masqueradeProxyMaxIdleConnsPerHost
		default:
			return nil, errors.New("unknown scheme")
		}
		masqHandler = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				if !config.MasqUrlRewriteHost {
					r.Out.Host = r.In.Host
				}
				if config.MasqUrlXForwarded {
					r.SetXForwarded()
				}
			},
			Transport:  transport,
			BufferPool: newMasqueradeProxyBufferPool(),
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				errors.LogErrorInner(context.Background(), err, "HTTP reverse proxy error")
				w.WriteHeader(http.StatusBadGateway)
			},
		}
	case "string":
		masqHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range config.MasqStringHeaders {
				w.Header().Set(k, v)
			}
			if config.MasqStringStatusCode != 0 {
				w.WriteHeader(int(config.MasqStringStatusCode))
			} else {
				w.WriteHeader(http.StatusOK)
			}
			_, _ = w.Write([]byte(config.MasqString))
		})
	default:
		return nil, errors.New("unknown masq type")
	}

	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		MaxIncomingStreams:             quicParams.MaxIncomingStreams,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           MaxDatagramFrameSize,
		AssumePeerMaxDatagramFrameSize: MaxDatagramFrameSize,
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = 8388608
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = 8388608
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	if quicParams.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = 1024
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	pktConn, err := internet.ListenSystemPacket(listenerCtx, &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		cancel()
		return nil, err
	}

	if streamSettings.UdpmaskManager != nil {
		newConn, err := streamSettings.UdpmaskManager.WrapPacketConnServerContext(listenerCtx, pktConn)
		if err != nil {
			pktConn.Close()
			cancel()
			return nil, errors.New("mask err").Base(err)
		}
		pktConn = newConn
	}

	var k *quic.StatelessResetKey
	if !quicParams.DisableStatelessReset {
		k = &quic.StatelessResetKey{}
		common.Must2(rand.Read((*k)[:]))
	}

	tr := &quic.Transport{Conn: pktConn, DisableGSO: quicParams.DisableGSO, StatelessResetKey: k}

	listener, err := tr.Listen(tlsConfig.GetTLSConfig(tls.WithNextProto("h3")), quicConfig)
	if err != nil {
		_ = tr.Close()
		_ = pktConn.Close()
		cancel()
		return nil, err
	}

	l := &Listener{
		validator:   validator,
		config:      config,
		masqHandler: masqHandler,
		quicParams:  quicParams,
		addConn:     handler,

		pktConn:     pktConn,
		tr:          tr,
		listener:    listener,
		lifecycle:   internet.InboundLifecycleFromContext(ctx),
		ctx:         listenerCtx,
		cancel:      cancel,
		connections: make(map[*quic.Conn]struct{}),
		callbacks:   make(map[net.Conn]*internet.InboundHandoff),
	}

	if !l.lifecycle.Acquire() {
		_ = l.Close()
		return nil, errors.New("inbound listener is closing")
	}
	go func() {
		defer l.lifecycle.Release()
		l.keepAccepting()
	}()

	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}

const (
	masqueradeProxyBufferSize          = 32 * 1024
	masqueradeProxyMaxIdleConnections  = 100
	masqueradeProxyMaxIdleConnsPerHost = 32
)

type masqueradeProxyBufferPool struct {
	pool sync.Pool
}

func newMasqueradeProxyBufferPool() *masqueradeProxyBufferPool {
	return &masqueradeProxyBufferPool{
		pool: sync.Pool{
			New: func() any {
				return make([]byte, masqueradeProxyBufferSize)
			},
		},
	}
}

func (p *masqueradeProxyBufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *masqueradeProxyBufferPool) Put(buf []byte) {
	if cap(buf) < masqueradeProxyBufferSize {
		return
	}
	p.pool.Put(buf[:masqueradeProxyBufferSize])
}
