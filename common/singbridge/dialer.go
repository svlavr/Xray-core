package singbridge

import (
	"context"
	"os"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

var _ N.Dialer = (*XrayDialer)(nil)

type XrayDialer struct {
	internet.Dialer
}

func NewDialer(dialer internet.Dialer) *XrayDialer {
	return &XrayDialer{dialer}
}

func (d *XrayDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dest, err := ToDestination(destination, ToNetwork(network))
	if err != nil {
		return nil, err
	}
	return d.Dialer.Dial(ctx, dest)
}

func (d *XrayDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type XrayOutboundDialer struct {
	outbound proxy.Outbound
	dialer   internet.Dialer
}

func NewOutboundDialer(outbound proxy.Outbound, dialer internet.Dialer) *XrayOutboundDialer {
	return &XrayOutboundDialer{outbound, dialer}
}

func (d *XrayOutboundDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dest, err := ToDestination(destination, ToNetwork(network))
	if err != nil {
		return nil, err
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.Target = dest

	opts := []pipe.Option{pipe.WithSizeLimit(64 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)
	conn := cnc.NewConnection(cnc.ConnectionInputMulti(downlinkWriter), cnc.ConnectionOutputMulti(uplinkReader))
	link := &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
	if dest.Network == net.Network_TCP {
		scope := flow_observation.BeginAsyncLink(ctx, link)
		processCtx := scope.Context(ctx)
		go func() {
			var processErr error
			defer func() { scope.Release(processErr) }()
			processErr = d.outbound.Process(processCtx, link, d.dialer)
		}()
	} else {
		go d.outbound.Process(ctx, link, d.dialer)
	}
	return conn, nil
}

func (d *XrayOutboundDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
