package taggedimpl

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// The stock DialFunc signature is retained; production callers obtain their
// dispatcher from this same core instance.
func DialTaggedOutbound(ctx context.Context, _ routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
	instance := core.FromContext(ctx)
	if instance == nil {
		return nil, errors.New("Instance context variable is not in context, dial denied. ")
	}
	ctx = session.ContextWithContent(ctx, &session.Content{SkipDNSResolve: true})
	ctx = session.SetForcedOutboundTagToContext(ctx, tag)
	return core.Dial(ctx, instance, dest)
}

func init() { tagged.Dialer = DialTaggedOutbound }
