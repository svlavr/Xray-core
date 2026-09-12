package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/transport/internet"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
)

type requestHandler struct {
	host           string
	path           string
	ln             *Listener
	socketSettings *internet.SocketConfig
}

var replacer = strings.NewReplacer("+", "-", "/", "_", "=", "")

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !h.ln.acquireCallback() {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer h.ln.lifecycle.Release()
	if len(h.host) > 0 && !internet.IsValidHTTPHost(request.Host, h.host) {
		errors.LogInfo(context.Background(), "failed to validate host, request:", request.Host, ", config:", h.host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if request.URL.Path != h.path {
		errors.LogInfo(context.Background(), "failed to validate path, request:", request.URL.Path, ", config:", h.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	var extraReader io.Reader
	responseHeader := http.Header{}
	if str := request.Header.Get("Sec-WebSocket-Protocol"); str != "" {
		if ed, err := base64.RawURLEncoding.DecodeString(replacer.Replace(str)); err == nil && len(ed) > 0 {
			extraReader = bytes.NewReader(ed)
			responseHeader.Set("Sec-WebSocket-Protocol", str)
		}
	}

	conn, err := upgrader.Upgrade(writer, request, responseHeader)
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to convert to WebSocket connection")
		return
	}

	remoteAddr := conn.RemoteAddr()
	var trustedXFF []string
	if h.socketSettings != nil {
		trustedXFF = h.socketSettings.TrustedXForwardedFor
	}
	remoteAddr = http_proto.ApplyTrustedXForwardedFor(request.Header, trustedXFF, remoteAddr)

	wrapped := newConnection(conn, remoteAddr, extraReader, h.ln.config.HeartbeatPeriod, new(internet.InboundHandoff))
	if h.ln.lifecycle != nil {
		if !h.ln.register(wrapped) {
			wrapped.Close()
			return
		}
		defer func() {
			h.ln.unregister(wrapped)
			wrapped.Close()
		}()
	}
	h.ln.addConn(wrapped)
}

type Listener struct {
	sync.Mutex
	server      http.Server
	listener    net.Listener
	config      *Config
	addConn     internet.ConnHandler
	lifecycle   *internet.InboundLifecycle
	closed      bool
	connections map[*connection]struct{}
}

func ListenWS(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn:     addConn,
		lifecycle:   internet.InboundLifecycleFromContext(ctx),
		connections: make(map[*connection]struct{}),
	}
	wsSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = wsSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen unix domain socket(for WS) on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening unix domain socket(for WS) on ", address)
	} else { // tcp
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP(for WS) on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP(for WS) on ", address, ":", port)
	}

	if streamSettings.TcpmaskManager != nil {
		listener, _ = streamSettings.TcpmaskManager.WrapListener(listener)
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	if config := v2tls.ConfigFromStreamSettings(streamSettings); config != nil {
		if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
	}

	l.listener = listener

	l.server = http.Server{
		Handler: &requestHandler{
			host:           wsSettings.Host,
			path:           wsSettings.GetNormalizedPath(),
			ln:             l,
			socketSettings: streamSettings.SocketSettings,
		},
		ReadHeaderTimeout: time.Second * 4,
		MaxHeaderBytes:    8192,
	}

	if !l.lifecycle.Acquire() {
		listener.Close()
		return nil, errors.New("inbound listener is closing")
	}
	go func() {
		defer l.lifecycle.Release()
		if err := l.server.Serve(l.listener); err != nil {
			errors.LogWarningInner(ctx, err, "failed to serve http for WebSocket")
		}
	}()

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	return ln.listener.Addr()
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	ln.Lock()
	if ln.closed {
		ln.Unlock()
		return nil
	}
	ln.closed = true
	connections := make([]*connection, 0, len(ln.connections))
	for conn := range ln.connections {
		connections = append(connections, conn)
	}
	ln.Unlock()
	var err error
	if ln.lifecycle != nil {
		err = ln.server.Close()
	} else {
		err = ln.listener.Close()
	}
	for _, conn := range connections {
		conn.RejectInboundHandoff()
		conn.Abort()
	}
	return err
}

func (ln *Listener) acquireCallback() bool {
	return ln.lifecycle.Acquire()
}

func (ln *Listener) register(conn *connection) bool {
	ln.Lock()
	defer ln.Unlock()
	if ln.closed {
		return false
	}
	ln.connections[conn] = struct{}{}
	return true
}

func (ln *Listener) unregister(conn *connection) {
	ln.Lock()
	delete(ln.connections, conn)
	ln.Unlock()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenWS))
}
