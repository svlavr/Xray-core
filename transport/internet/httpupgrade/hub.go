package httpupgrade

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
)

type server struct {
	config         *Config
	addConn        internet.ConnHandler
	innnerListener net.Listener
	socketSettings *internet.SocketConfig
	lifecycle      *internet.InboundLifecycle
	mu             sync.Mutex
	closed         bool
	connections    map[net.Conn]*internet.InboundHandoff
}

func (s *server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	type acceptedConnection struct {
		conn    net.Conn
		handoff *internet.InboundHandoff
	}
	connections := make([]acceptedConnection, 0, len(s.connections))
	for conn, handoff := range s.connections {
		connections = append(connections, acceptedConnection{conn: conn, handoff: handoff})
	}
	s.mu.Unlock()
	err := s.innnerListener.Close()
	for _, accepted := range connections {
		accepted.handoff.Reject()
		accepted.conn.Close()
	}
	return err
}

func (s *server) Addr() net.Addr {
	return nil
}

func (s *server) Handle(conn net.Conn) {
	s.handle(conn, false, nil)
}

func (s *server) handle(conn net.Conn, tracked bool, handoff *internet.InboundHandoff) {
	if tracked {
		defer func() {
			s.unregister(conn)
			conn.Close()
			s.lifecycle.Release()
		}()
	}
	upgradedConn, err := s.upgrade(conn, handoff)
	if err != nil {
		common.CloseIfExists(conn)
		errors.LogInfoInner(context.Background(), err, "failed to handle request")
		return
	}
	s.addConn(upgradedConn)
}

// upgrade execute a fake websocket upgrade process and return the available connection
func (s *server) upgrade(conn net.Conn, handoff *internet.InboundHandoff) (stat.Connection, error) {
	// timeout and header limit are the same as websocket
	conn.SetReadDeadline(time.Now().Add(time.Second * 4))
	defer conn.SetReadDeadline(time.Time{})
	connReader := bufio.NewReader(io.LimitReader(conn, 12288))

	req, err := http.ReadRequest(connReader)
	if err != nil {
		return nil, err
	}

	if s.config != nil {
		host := req.Host
		if len(s.config.Host) > 0 && !internet.IsValidHTTPHost(host, s.config.Host) {
			return nil, errors.New("bad host: ", host)
		}
		path := s.config.GetNormalizedPath()
		if req.URL.Path != path {
			return nil, errors.New("bad path: ", req.URL.Path)
		}
	}

	connection := strings.ToLower(req.Header.Get("Connection"))
	upgrade := strings.ToLower(req.Header.Get("Upgrade"))
	if connection != "upgrade" || upgrade != "websocket" {
		return nil, errors.New("unrecognized request")
	}
	resp := &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: 101,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Upgrade", "websocket")
	err = resp.Write(conn)
	if err != nil {
		return nil, err
	}

	remoteAddr := conn.RemoteAddr()
	var trustedXFF []string
	if s.socketSettings != nil {
		trustedXFF = s.socketSettings.TrustedXForwardedFor
	}
	remoteAddr = http_proto.ApplyTrustedXForwardedFor(req.Header, trustedXFF, remoteAddr)

	return stat.Connection(newConnection(conn, remoteAddr, handoff)), nil
}

func (s *server) keepAccepting() {
	for {
		conn, err := s.innnerListener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accept raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		tracked := s.lifecycle != nil
		var handoff *internet.InboundHandoff
		if tracked {
			var registered bool
			handoff, registered = s.register(conn)
			if !registered {
				conn.Close()
				continue
			}
		}
		go s.handle(conn, tracked, handoff)
	}
}

func (s *server) register(conn net.Conn) (*internet.InboundHandoff, bool) {
	if !s.lifecycle.Acquire() {
		return nil, false
	}
	handoff := new(internet.InboundHandoff)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.lifecycle.Release()
		return nil, false
	}
	s.connections[conn] = handoff
	s.mu.Unlock()
	return handoff, true
}

func (s *server) unregister(conn net.Conn) {
	s.mu.Lock()
	delete(s.connections, conn)
	s.mu.Unlock()
}

func ListenHTTPUpgrade(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	if transportConfiguration != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = transportConfiguration.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen unix domain socket(for HttpUpgrade) on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening unix domain socket(for HttpUpgrade) on ", address)
	} else { // tcp
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP(for HttpUpgrade) on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP(for HttpUpgrade) on ", address, ":", port)
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

	serverInstance := &server{
		config:         transportConfiguration,
		addConn:        addConn,
		innnerListener: listener,
		socketSettings: streamSettings.SocketSettings,
		lifecycle:      internet.InboundLifecycleFromContext(ctx),
		connections:    make(map[net.Conn]*internet.InboundHandoff),
	}
	if !serverInstance.lifecycle.Acquire() {
		listener.Close()
		return nil, errors.New("inbound listener is closing")
	}
	go func() {
		defer serverInstance.lifecycle.Release()
		serverInstance.keepAccepting()
	}()
	return serverInstance, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenHTTPUpgrade))
}
