package shadowsocks_2022

import (
	"context"
	"maps"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
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

// observeTCP binds receipts only after the native codec has decoded the request.
// Dispatch marks its returned-link cursor as already observed.
func observeTCP(ctx context.Context, manager stats.Manager, endpoint net.Conn, destination net.Destination, reader buf.Reader, writer buf.Writer, early int) (context.Context, buf.Reader, buf.Writer, func()) {
	ctx, observation, finish := proxy.BeginReturnedObservation(ctx, manager, endpoint, destination, net.Network_TCP)
	if observation == nil {
		return ctx, reader, writer, nil
	}
	if early > 0 {
		observation.Exchange.AddUplink(uint64(early))
	}
	cursor := buf.NewInspectionReader(reader, observation.Exchange, func() {})
	return ctx, cursor, buf.AttachWriterReceipt(writer, observation.Exchange), func() {
		cursor.Interrupt()
		finish()
	}
}
