package grpc

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)

	conn, err := dialgRPC(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("failed to dial gRPC").Base(err)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
	ownerID uint64
}

var (
	globalDialerMap    map[dialerConf]*grpcClientResource
	globalDialerAccess sync.Mutex
)

type grpcClientResource struct {
	key        dialerConf
	conn       *grpc.ClientConn
	unregister func()
	sealed     bool
	mu         sync.Mutex
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
}

func grpcDialContext(gctx, source context.Context, owner *internet.ResourceLifecycle) (context.Context, func()) {
	base := internet.ContextWithResourceLifecycle(owner.Context(), owner)
	var linked context.Context
	var cancel context.CancelFunc
	if deadline, ok := gctx.Deadline(); ok {
		linked, cancel = context.WithDeadline(base, deadline)
	} else {
		linked, cancel = context.WithCancel(base)
	}
	grpcCancelDone := make(chan struct{})
	stopGRPC := context.AfterFunc(gctx, func() {
		cancel()
		close(grpcCancelDone)
	})
	if gctx.Err() != nil {
		cancel()
	}
	linked = c.ContextWithID(linked, c.IDFromContext(source))
	linked = session.ContextWithOutbounds(linked, session.OutboundsFromContext(source))
	linked = session.ContextWithTimeoutOnly(linked, true)
	return linked, func() {
		if !stopGRPC() {
			<-grpcCancelDone
		}
		cancel()
	}
}

func (r *grpcClientResource) SignalStop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.sealed {
		r.mu.Unlock()
		return
	}
	r.sealed = true
	r.mu.Unlock()
	globalDialerAccess.Lock()
	if globalDialerMap[r.key] == r {
		delete(globalDialerMap, r.key)
	}
	globalDialerAccess.Unlock()
	go func() { _ = r.Close() }()
}

func (r *grpcClientResource) Close() error {
	if r == nil {
		return nil
	}
	r.SignalStop()
	r.closeOnce.Do(func() {
		r.closeErr = r.conn.Close()
		close(r.closeDone)
		if r.unregister != nil {
			r.unregister()
		}
	})
	<-r.closeDone
	return r.closeErr
}

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	conn, err := getGrpcClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(conn)
	if grpcSettings.MultiMode {
		errors.LogDebug(ctx, "using gRPC multi mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunMultiStreamName()+"`")
		grpcService, err := client.(encoding.GRPCServiceClientX).TunMultiCustomName(ctx, grpcSettings.getServiceName(), grpcSettings.getTunMultiStreamName())
		if err != nil {
			return nil, errors.New("Cannot dial gRPC").Base(err)
		}
		return encoding.NewMultiHunkConn(grpcService, nil, nil), nil
	}

	errors.LogDebug(ctx, "using gRPC tun mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunStreamName()+"`")
	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(ctx, grpcSettings.getServiceName(), grpcSettings.getTunStreamName())
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, nil, nil), nil
}

func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*grpc.ClientConn, error) {
	owner := streamSettings.ResourceLifecycle
	if owner == nil {
		owner = internet.ResourceLifecycleFromContext(ctx)
	}
	if owner == nil {
		return nil, errors.New("gRPC transport resource lifecycle is unavailable")
	}
	if err := owner.Context().Err(); err != nil {
		return nil, err
	}
	key := dialerConf{Destination: dest, MemoryStreamConfig: streamSettings, ownerID: owner.ID()}
	globalDialerAccess.Lock()
	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*grpcClientResource)
	}
	if resource := globalDialerMap[key]; resource != nil {
		resource.mu.Lock()
		usable := !resource.sealed && owner.Context().Err() == nil && resource.conn.GetState() != connectivity.Shutdown
		resource.mu.Unlock()
		if usable {
			globalDialerAccess.Unlock()
			return resource.conn, nil
		}
	}
	if err := owner.Context().Err(); err != nil {
		globalDialerAccess.Unlock()
		return nil, err
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)
	sockopt := streamSettings.SocketSettings
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	dialOptions := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithContextDialer(func(gctx context.Context, s string) (net.Conn, error) {
			gctx, release := grpcDialContext(gctx, ctx, owner)
			defer release()
			select {
			case <-gctx.Done():
				return nil, gctx.Err()
			default:
			}

			rawHost, rawPort, err := net.SplitHostPort(s)
			if err != nil {
				return nil, err
			}
			if len(rawPort) == 0 {
				rawPort = "443"
			}
			port, err := net.PortFromString(rawPort)
			if err != nil {
				return nil, err
			}
			address := net.ParseAddress(rawHost)

			c, err := internet.DialSystem(gctx, net.TCPDestination(address, port), sockopt)
			if err == nil {
				if streamSettings.TcpmaskManager != nil {
					newConn, err := streamSettings.TcpmaskManager.WrapConnClient(c)
					if err != nil {
						c.Close()
						return nil, errors.New("mask err").Base(err)
					}
					c = newConn
				}

				if tlsConfig != nil {
					config := tlsConfig.GetTLSConfigContext(ctx, tls.WithDestination(dest))
					if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
						return tls.UClient(c, config, fingerprint), nil
					} else { // Fallback to normal gRPC TLS
						return tls.Client(c, config), nil
					}
				}
				if realityConfig != nil {
					return reality.UClient(c, realityConfig, gctx, dest)
				}
			}
			return c, err
		}),
	}

	dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))

	authority := ""
	if grpcSettings.Authority != "" {
		authority = grpcSettings.Authority
	} else if tlsConfig != nil && tlsConfig.ServerName != "" {
		authority = tlsConfig.ServerName
	} else if realityConfig == nil && dest.Address.Family().IsDomain() {
		authority = dest.Address.Domain()
	}
	dialOptions = append(dialOptions, grpc.WithAuthority(authority))

	if grpcSettings.IdleTimeout > 0 || grpcSettings.HealthCheckTimeout > 0 || grpcSettings.PermitWithoutStream {
		dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * time.Duration(grpcSettings.IdleTimeout),
			Timeout:             time.Second * time.Duration(grpcSettings.HealthCheckTimeout),
			PermitWithoutStream: grpcSettings.PermitWithoutStream,
		}))
	}

	if grpcSettings.InitialWindowsSize > 0 {
		dialOptions = append(dialOptions, grpc.WithInitialWindowSize(grpcSettings.InitialWindowsSize))
	}

	var grpcDestHost string
	if dest.Address.Family().IsDomain() {
		grpcDestHost = dest.Address.Domain()
	} else {
		grpcDestHost = dest.Address.IP().String()
	}

	conn, err := grpc.NewClient(
		"passthrough:///"+net.JoinHostPort(grpcDestHost, dest.Port.String()),
		dialOptions...,
	)
	if err != nil {
		globalDialerAccess.Unlock()
		return nil, err
	}
	userAgent := grpcSettings.UserAgent
	// It's NOT recommended to set the UA of gRPC connections to that of real browsers, as they are fundamentally incapable of initiating real gRPC connections.
	switch userAgent {
	case "chrome", "":
		userAgent = utils.ChromeUA
	case "firefox":
		userAgent = utils.FirefoxUA
	case "edge":
		userAgent = utils.MSEdgeUA
	case "golang":
		userAgent = ""
	}
	setUserAgent(conn, userAgent)
	resource := &grpcClientResource{key: key, conn: conn, closeDone: make(chan struct{})}
	if err := owner.RegisterBound(resource, func(unregister func()) { resource.unregister = unregister }); err != nil {
		globalDialerAccess.Unlock()
		_ = conn.Close()
		return nil, err
	}
	resource.mu.Lock()
	if resource.sealed || owner.Context().Err() != nil {
		resource.mu.Unlock()
		globalDialerAccess.Unlock()
		_ = resource.Close()
		return nil, errors.New("gRPC transport resource lifecycle is closed")
	}
	// Connect publishes grpc-go resolver/subconnection work. Keep it inside the
	// exact resource start/stop gate so a winning SignalStop cannot be followed
	// by new transport work or cache publication.
	conn.Connect()
	globalDialerMap[key] = resource
	resource.mu.Unlock()
	globalDialerAccess.Unlock()
	return conn, nil
}

// setUserAgent overrides the user-agent on a ClientConn to remove the
// "grpc-go/version" suffix that grpc.WithUserAgent unconditionally appends.
func setUserAgent(conn *grpc.ClientConn, ua string) {
	if f := reflect.ValueOf(conn).Elem().FieldByName("dopts").FieldByName("copts").FieldByName("UserAgent"); f.IsValid() {
		*(*string)(f.Addr().UnsafePointer()) = ua
	}
}
