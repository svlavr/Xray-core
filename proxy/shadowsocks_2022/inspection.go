package shadowsocks_2022

import (
	"context"
	"maps"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func packetContext(ctx context.Context, conn net.Conn) context.Context {
	if owner, ok := conn.(interface {
		PacketContext(context.Context) context.Context
	}); ok {
		return owner.PacketContext(ctx)
	}
	return ctx
}

// Native UDP sessions mutate routing metadata independently of their listener.
func packetSessionContext(ctx context.Context) context.Context {
	if original := session.InboundFromContext(ctx); original != nil {
		inbound := *original
		ctx = session.ContextWithInbound(ctx, &inbound)
	}
	if original := session.OutboundsFromContext(ctx); original != nil {
		outbounds := make([]*session.Outbound, len(original))
		for idx, outbound := range original {
			if outbound != nil {
				copy := *outbound
				outbounds[idx] = &copy
			}
		}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	if original := session.ContentFromContext(ctx); original != nil {
		content := *original
		content.Attributes = maps.Clone(original.Attributes)
		ctx = session.ContextWithContent(ctx, &content)
	}
	return ctx
}
