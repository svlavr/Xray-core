package grpc

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
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
}

var (
	globalDialerMap    map[dialerConf]*grpc.ClientConn
	globalDialerAccess sync.Mutex
)

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)
	pooled := grpcClientPooled(ctx, streamSettings)

	conn, err := getGrpcClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(conn)
	// A standalone stream owns its ClientConn. A handler-owned stream only owns
	// its RPC; closing it must not interrupt sibling streams on the pooled client.
	var closeClient context.CancelFunc
	if !pooled {
		closeConn := func() { _ = conn.Close() }
		stopOwner := func() bool { return false }
		if streamSettings.Owner != nil {
			stopOwner = context.AfterFunc(streamSettings.Owner, closeConn)
		}
		closeClient = func() { stopOwner(); closeConn() }
	}
	if grpcSettings.MultiMode {
		errors.LogDebug(ctx, "using gRPC multi mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunMultiStreamName()+"`")
		streamCtx, cancelStream := context.WithCancel(ctx)
		closeStream := func() {
			cancelStream()
			if closeClient != nil {
				closeClient()
			}
		}
		grpcService, err := client.(encoding.GRPCServiceClientX).TunMultiCustomName(streamCtx, grpcSettings.getServiceName(), grpcSettings.getTunMultiStreamName())
		if err != nil {
			closeStream()
			return nil, errors.New("Cannot dial gRPC").Base(err)
		}
		return encoding.NewMultiHunkConn(grpcService, closeStream, nil), nil
	}

	errors.LogDebug(ctx, "using gRPC tun mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunStreamName()+"`")
	streamCtx, cancelStream := context.WithCancel(ctx)
	closeStream := func() {
		cancelStream()
		if closeClient != nil {
			closeClient()
		}
	}
	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(streamCtx, grpcSettings.getServiceName(), grpcSettings.getTunStreamName())
	if err != nil {
		closeStream()
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, closeStream, nil), nil
}

func grpcClientPooled(ctx context.Context, settings *internet.MemoryStreamConfig) bool {
	if settings.Owner == nil || (settings.SocketSettings != nil && settings.SocketSettings.DialerProxy != "") {
		return false
	}
	// Source addresses can vary per flow (ViaCidr/srcip). Keep these clients
	// stream-owned rather than accumulating one pooled connection per address.
	outbounds := session.OutboundsFromContext(ctx)
	return len(outbounds) == 0 || outbounds[len(outbounds)-1] == nil || outbounds[len(outbounds)-1].Gateway == nil
}

// A reconnect needs a stable route but must not retain the first stream's
// context or mutable session outbounds. A direct TCP dial only uses Gateway;
// a DialerProxy redirect needs the complete tag history.
func frozenOutbounds(ctx context.Context, direct bool) []*session.Outbound {
	outbounds := session.OutboundsFromContext(ctx)
	if direct {
		if len(outbounds) == 0 {
			return nil
		}
		last := outbounds[len(outbounds)-1]
		if last == nil {
			return []*session.Outbound{nil}
		}
		return []*session.Outbound{{Gateway: last.Gateway}}
	}
	frozen := make([]*session.Outbound, len(outbounds))
	for i, ob := range outbounds {
		if ob == nil {
			continue
		}
		copy := *ob
		frozen[i] = &copy
	}
	return frozen
}

func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*grpc.ClientConn, error) {
	pooled := grpcClientPooled(ctx, streamSettings)
	key := dialerConf{Destination: dest, MemoryStreamConfig: streamSettings}
	owner := streamSettings.Owner
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	if owner != nil && owner.Err() != nil {
		return nil, owner.Err()
	}

	if pooled && globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*grpc.ClientConn)
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	if pooled {
		if client, found := globalDialerMap[key]; found && client.GetState() != connectivity.Shutdown {
			return client, nil
		}
	}

	route := frozenOutbounds(ctx, streamSettings.SocketSettings == nil || streamSettings.SocketSettings.DialerProxy == "")
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

			gctx = session.ContextWithOutbounds(gctx, route)
			gctx = session.ContextWithTimeoutOnly(gctx, true)

			var c net.Conn
			if streamSettings.FinalMask != nil {
				c, err = streamSettings.FinalMask.DialTCP(gctx, net.TCPDestination(address, port))
			} else {
				c, err = internet.DialSystem(gctx, net.TCPDestination(address, port), streamSettings.SocketSettings)
			}
			if err == nil {
				if tlsConfig != nil {
					config := tlsConfig.GetTLSConfig(tls.WithClient(), tls.WithDestination(dest))
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
	if err != nil {
		return nil, err
	}
	if owner != nil && owner.Err() != nil {
		_ = conn.Close()
		return nil, owner.Err()
	}
	if pooled {
		globalDialerMap[key] = conn
		context.AfterFunc(owner, func() {
			globalDialerAccess.Lock()
			if globalDialerMap[key] == conn {
				delete(globalDialerMap, key)
			}
			globalDialerAccess.Unlock()
			_ = conn.Close()
		})
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
