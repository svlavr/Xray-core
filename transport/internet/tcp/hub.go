package tcp

import (
	"context"
	gotls "crypto/tls"
	"strings"
	"sync"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	listener      net.Listener
	tlsConfig     *gotls.Config
	realityConfig *goreality.Config
	authConfig    internet.ConnectionAuthenticator
	config        *Config
	addConn       internet.ConnHandler
	lifecycle     *internet.InboundLifecycle
	mu            sync.Mutex
	closed        bool
	connections   map[net.Conn]struct{}
}

// ListenTCP creates a new Listener based on configurations.
func ListenTCP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn:     handler,
		lifecycle:   internet.InboundLifecycleFromContext(ctx),
		connections: make(map[net.Conn]struct{}),
	}
	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = tcpSettings
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
			return nil, errors.New("failed to listen Unix Domain Socket on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening Unix Domain Socket on ", address)
	} else {
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP on ", address, ":", port)
	}
	ownedListener := listener
	cleanupListener := true
	defer func() {
		if cleanupListener && ownedListener != nil {
			ownedListener.Close()
		}
	}()

	if streamSettings.TcpmaskManager != nil {
		listener, err = streamSettings.TcpmaskManager.WrapListener(listener)
		if err != nil {
			return nil, errors.New("failed to wrap TCP listener").Base(err)
		}
		ownedListener = listener
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
	}
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		l.realityConfig = config.GetREALITYConfig()
	}

	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("invalid header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("invalid header settings.").Base(err).AtError()
		}
		l.authConfig = auth
	}

	if !l.lifecycle.Acquire() {
		return nil, errors.New("inbound listener is closing")
	}
	cleanupListener = false
	if l.realityConfig != nil {
		go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
	}
	go func() {
		defer l.lifecycle.Release()
		l.keepAccepting()
	}()
	return l, nil
}

func (v *Listener) keepAccepting() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}

		tracked := v.lifecycle != nil
		if tracked {
			if !v.register(conn) {
				conn.Close()
				continue
			}
		}
		go func(rawConn net.Conn) {
			conn := rawConn
			handedOff := false
			defer func() {
				if tracked {
					v.unregister(rawConn)
					rawConn.Close()
					v.lifecycle.Release()
				} else if !handedOff {
					rawConn.Close()
				}
			}()
			if v.tlsConfig != nil {
				conn = tls.Server(conn, v.tlsConfig)
			} else if v.realityConfig != nil {
				if conn, err = reality.Server(conn, v.realityConfig); err != nil {
					errors.LogInfo(context.Background(), err.Error())
					return
				}
			}
			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
			handedOff = true
		}(conn)
	}
}

// Addr implements internet.Listener.Addr.
func (v *Listener) Addr() net.Addr {
	return v.listener.Addr()
}

// Close implements internet.Listener.Close.
func (v *Listener) Close() error {
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return nil
	}
	v.closed = true
	connections := make([]net.Conn, 0, len(v.connections))
	for conn := range v.connections {
		connections = append(connections, conn)
	}
	v.mu.Unlock()
	err := v.listener.Close()
	for _, conn := range connections {
		conn.Close()
	}
	return err
}

func (v *Listener) register(conn net.Conn) bool {
	if !v.lifecycle.Acquire() {
		return false
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		v.lifecycle.Release()
		return false
	}
	v.connections[conn] = struct{}{}
	v.mu.Unlock()
	return true
}

func (v *Listener) unregister(conn net.Conn) { v.mu.Lock(); delete(v.connections, conn); v.mu.Unlock() }

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenTCP))
}
