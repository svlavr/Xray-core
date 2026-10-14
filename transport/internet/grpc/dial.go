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
	gateway bool
}

var (
	globalDialerMap    map[dialerConf]*grpc.ClientConn
	globalDialerAccess sync.Mutex
)

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	conn, err := getGrpcClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(conn)
	var cancel context.CancelFunc
	if internet.MUSelected(ctx) {
		ctx, cancel = context.WithCancel(ctx)
		if !grpcPooled(ctx, streamSettings) {
			stop := cancel
			cancel = func() { stop(); _ = conn.Close() }
		}
	}
	if grpcSettings.MultiMode {
		errors.LogDebug(ctx, "using gRPC multi mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunMultiStreamName()+"`")
		grpcService, err := client.(encoding.GRPCServiceClientX).TunMultiCustomName(ctx, grpcSettings.getServiceName(), grpcSettings.getTunMultiStreamName())
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return nil, errors.New("Cannot dial gRPC").Base(err)
		}
		return encoding.NewMultiHunkConn(grpcService, cancel, nil), nil
	}

	errors.LogDebug(ctx, "using gRPC tun mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunStreamName()+"`")
	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(ctx, grpcSettings.getServiceName(), grpcSettings.getTunStreamName())
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, cancel, nil), nil
}

func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*grpc.ClientConn, error) {
	selected := internet.MUSelected(ctx)
	pooled := grpcPooled(ctx, streamSettings)
	route := session.OutboundsFromContext(ctx)
	gateway := len(route) != 0 && route[len(route)-1] != nil && route[len(route)-1].Gateway != nil
	key := dialerConf{dest, streamSettings, gateway}
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*grpc.ClientConn)
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	if client, found := globalDialerMap[key]; pooled && found && client.GetState() != connectivity.Shutdown {
		return client, nil
	}

	// A gateway-free native channel can be borrowed by selected RPCs. Freeze
	// its actual route before the creating caller can mutate that metadata.
	if selected || !gateway {
		route = grpcRoute(route)
	}
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

			// Gateway-free pooled channels carry both native and selected RPCs.
			if selected || !gateway {
				if !selected {
					gctx = c.ContextWithID(gctx, c.IDFromContext(ctx))
				}
				gctx = internet.ContextWithMUTransport(gctx)
				gctx = session.ContextWithTrafficOrigin(gctx, session.TrafficOriginInternal)
				gctx = session.ContextWithLogicalObservation(gctx, nil)
				gctx = session.ContextWithOutbounds(gctx, grpcRoute(route))
			} else {
				gctx = c.ContextWithID(gctx, c.IDFromContext(ctx))
				gctx = session.ContextWithOutbounds(gctx, route)
			}
			gctx = session.ContextWithTimeoutOnly(gctx, true)

			var c net.Conn
			if streamSettings.FinalMask != nil {
				c, err = streamSettings.FinalMask.DialTCP(gctx, net.TCPDestination(address, port))
			} else {
				c, err = internet.DialSystem(gctx, net.TCPDestination(address, port), streamSettings.SocketSettings)
			}
			if err == nil {
				if tlsConfig != nil {
					config := tlsConfig.GetTLSConfig(tls.WithDestination(dest))
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
	if err == nil {
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
		conn.Connect()
	}
	if pooled && (!selected || err == nil) {
		globalDialerMap[key] = conn
	}
	return conn, err
}

// setUserAgent overrides the user-agent on a ClientConn to remove the
// "grpc-go/version" suffix that grpc.WithUserAgent unconditionally appends.
func setUserAgent(conn *grpc.ClientConn, ua string) {
	if f := reflect.ValueOf(conn).Elem().FieldByName("dopts").FieldByName("copts").FieldByName("UserAgent"); f.IsValid() {
		*(*string)(f.Addr().UnsafePointer()) = ua
	}
}

func grpcPooled(ctx context.Context, settings *internet.MemoryStreamConfig) bool {
	if !internet.MUSelected(ctx) {
		return true
	}
	if settings.SocketSettings != nil && settings.SocketSettings.DialerProxy != "" {
		return false
	}
	outbounds := session.OutboundsFromContext(ctx)
	return len(outbounds) == 0 || outbounds[len(outbounds)-1] == nil || outbounds[len(outbounds)-1].Gateway == nil
}

func grpcRoute(source []*session.Outbound) []*session.Outbound {
	route := make([]*session.Outbound, len(source))
	for i, outbound := range source {
		if outbound != nil {
			copy := *outbound
			route[i] = &copy
		}
	}
	return route
}
