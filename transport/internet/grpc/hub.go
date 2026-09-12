package grpc

import (
	"context"
	"sync"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type Listener struct {
	encoding.UnimplementedGRPCServiceServer
	ctx                  context.Context
	handler              internet.ConnHandler
	local                net.Addr
	config               *Config
	trustedXForwardedFor []string

	s           *grpc.Server
	listener    net.Listener
	lifecycle   *internet.InboundLifecycle
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]struct{}
}

type inboundConnection struct {
	net.Conn
	handoff *internet.InboundHandoff
}

func (c *inboundConnection) AcceptInboundHandoff() bool { return c.handoff.Accept() }
func (c *inboundConnection) RejectInboundHandoff()      { c.handoff.Reject() }

func (l *Listener) Tun(server encoding.GRPCService_TunServer) error {
	if l.lifecycle == nil {
		tunCtx, cancel := context.WithCancel(l.ctx)
		l.handler(encoding.NewHunkConn(server, cancel, l.trustedXForwardedFor))
		<-tunCtx.Done()
		return nil
	}
	if !l.register() {
		return context.Canceled
	}
	tunCtx, cancel := context.WithCancel(l.ctx)
	conn := &inboundConnection{Conn: encoding.NewHunkConn(server, cancel, l.trustedXForwardedFor), handoff: new(internet.InboundHandoff)}
	if !l.addConnection(conn) {
		cancel()
		conn.Close()
		l.lifecycle.Release()
		return context.Canceled
	}
	defer func() {
		l.removeConnection(conn)
		conn.Close()
		l.lifecycle.Release()
	}()
	l.handler(conn)
	<-tunCtx.Done()
	return nil
}

func (l *Listener) TunMulti(server encoding.GRPCService_TunMultiServer) error {
	if l.lifecycle == nil {
		tunCtx, cancel := context.WithCancel(l.ctx)
		l.handler(encoding.NewMultiHunkConn(server, cancel, l.trustedXForwardedFor))
		<-tunCtx.Done()
		return nil
	}
	if !l.register() {
		return context.Canceled
	}
	tunCtx, cancel := context.WithCancel(l.ctx)
	conn := &inboundConnection{Conn: encoding.NewMultiHunkConn(server, cancel, l.trustedXForwardedFor), handoff: new(internet.InboundHandoff)}
	if !l.addConnection(conn) {
		cancel()
		conn.Close()
		l.lifecycle.Release()
		return context.Canceled
	}
	defer func() {
		l.removeConnection(conn)
		conn.Close()
		l.lifecycle.Release()
	}()
	l.handler(conn)
	<-tunCtx.Done()
	return nil
}

func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	connections := make([]net.Conn, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	if l.lifecycle != nil && l.cancel != nil {
		l.cancel()
	}
	var closeErrors []error
	if l.listener != nil {
		closeErrors = append(closeErrors, l.listener.Close())
	}
	if l.lifecycle != nil {
		for _, conn := range connections {
			internet.RejectInboundHandoff(conn)
			closeErrors = append(closeErrors, conn.Close())
		}
	}
	l.s.Stop()
	return errors.Combine(closeErrors...)
}

func (l *Listener) Addr() net.Addr {
	return l.local
}

func Listen(ctx context.Context, address net.Address, port net.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	grpcSettings := settings.ProtocolSettings.(*Config)
	var listener *Listener
	if port == net.Port(0) { // unix
		listener = &Listener{
			handler: handler,
			local: &net.UnixAddr{
				Name: address.Domain(),
				Net:  "unix",
			},
			config: grpcSettings,
		}
	} else { // tcp
		listener = &Listener{
			handler: handler,
			local: &net.TCPAddr{
				IP:   address.IP(),
				Port: int(port),
			},
			config: grpcSettings,
		}
	}

	listener.lifecycle = internet.InboundLifecycleFromContext(ctx)
	listener.ctx = ctx
	if listener.lifecycle != nil {
		listener.ctx, listener.cancel = context.WithCancel(ctx)
	}
	listener.connections = make(map[net.Conn]struct{})
	if settings.SocketSettings != nil {
		listener.trustedXForwardedFor = settings.SocketSettings.TrustedXForwardedFor
	}

	config := tls.ConfigFromStreamSettings(settings)

	var options []grpc.ServerOption
	var s *grpc.Server
	if config != nil {
		// gRPC server may silently ignore TLS errors
		options = append(options, grpc.Creds(credentials.NewTLS(config.GetTLSConfig(tls.WithNextProto("h2")))))
	}
	if grpcSettings.IdleTimeout > 0 || grpcSettings.HealthCheckTimeout > 0 {
		options = append(options, grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    time.Second * time.Duration(grpcSettings.IdleTimeout),
			Timeout: time.Second * time.Duration(grpcSettings.HealthCheckTimeout),
		}))
	}

	s = grpc.NewServer(options...)
	listener.s = s

	if settings.SocketSettings != nil && settings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	var (
		streamListener net.Listener
		err            error
	)
	if port == net.Port(0) { // unix
		streamListener, err = internet.ListenSystem(listener.ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, settings.SocketSettings)
	} else { // tcp
		streamListener, err = internet.ListenSystem(listener.ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, settings.SocketSettings)
	}
	if err != nil {
		if listener.cancel != nil {
			listener.cancel()
		}
		return nil, errors.New("failed to listen gRPC on ", address, ":", port).Base(err)
	}
	if settings.TcpmaskManager != nil {
		boundListener := streamListener
		streamListener, err = settings.TcpmaskManager.WrapListener(boundListener)
		if err != nil {
			boundListener.Close()
			if listener.cancel != nil {
				listener.cancel()
			}
			return nil, errors.New("failed to wrap gRPC listener").Base(err)
		}
	}
	listener.listener = streamListener
	encoding.RegisterGRPCServiceServerX(s, listener, grpcSettings.getServiceName(), grpcSettings.getTunStreamName(), grpcSettings.getTunMultiStreamName())
	if config := reality.ConfigFromStreamSettings(settings); config != nil {
		streamListener = goreality.NewListener(streamListener, config.GetREALITYConfig())
		listener.listener = streamListener
	}
	if !listener.lifecycle.Acquire() {
		listener.Close()
		return nil, errors.New("inbound listener is closing")
	}
	go func() {
		defer listener.lifecycle.Release()

		errors.LogDebug(ctx, "gRPC listen for service name `"+grpcSettings.getServiceName()+"` tun `"+grpcSettings.getTunStreamName()+"` multi tun `"+grpcSettings.getTunMultiStreamName()+"`")
		if serveErr := s.Serve(streamListener); serveErr != nil {
			errors.LogInfoInner(ctx, serveErr, "Listener for gRPC ended")
		}
	}()

	return listener, nil
}

func (l *Listener) register() bool {
	if !l.lifecycle.Acquire() {
		return false
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		l.lifecycle.Release()
		return false
	}
	l.mu.Unlock()
	return true
}

func (l *Listener) addConnection(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.connections[conn] = struct{}{}
	return true
}

func (l *Listener) removeConnection(conn net.Conn) {
	l.mu.Lock()
	delete(l.connections, conn)
	l.mu.Unlock()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
