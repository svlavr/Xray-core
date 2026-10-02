package measurement

import (
	"context"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

type RouteKind uint8

const (
	Direct RouteKind = iota + 1
	ExactOutbound
)

type Route struct {
	Kind RouteKind
	Tag  string // Required only for ExactOutbound.
}

func (r Route) valid() bool {
	return r.Kind == Direct && r.Tag == "" || r.Kind == ExactOutbound && r.Tag != ""
}

func (e *Executor) open(ctx context.Context, route Route, dest xnet.Destination) (net.Conn, error) {
	if route.Kind == Direct {
		return internet.DialSystem(ctx, dest, nil)
	}
	ctx = session.SetForcedOutboundTagToContext(ctx, route.Tag)
	if dest.Network == xnet.Network_UDP {
		ctx = session.ContextWithUDPPacketSource(ctx)
	}
	return core.Dial(ctx, e.instance, dest)
}
