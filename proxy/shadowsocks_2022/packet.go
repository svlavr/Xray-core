package shadowsocks_2022

import (
	"context"
	"io"
	"maps"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
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

// The first packet's request values are shared by native sessions from that
// source. Each callback must own the metadata it changes during dispatch.
func packetSessionContext(ctx context.Context) context.Context {
	if original := session.InboundFromContext(ctx); original != nil {
		inbound := *original
		ctx = session.ContextWithInbound(ctx, &inbound)
	}
	if original := session.OutboundsFromContext(ctx); original != nil {
		outbounds := make([]*session.Outbound, len(original))
		for i, outbound := range original {
			if outbound != nil {
				copy := *outbound
				outbounds[i] = &copy
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

type natPacketConn struct{ net.Conn }

func (c *natPacketConn) ReadPacket(buffer *B.Buffer) (addr M.Socksaddr, err error) {
	_, err = buffer.ReadFrom(c)
	return
}

func (c *natPacketConn) WritePacket(buffer *B.Buffer, addr M.Socksaddr) error {
	defer buffer.Release()
	offered := buffer.Len()
	var n int
	var err error
	if writer, ok := c.Conn.(interface {
		WriteTo([]byte, net.Addr) (int, error)
	}); ok {
		n, err = writer.WriteTo(buffer.Bytes(), addr.UDPAddr())
	} else {
		n, err = c.Conn.Write(buffer.Bytes())
	}
	if err == nil && n != offered {
		err = io.ErrShortWrite
	}
	return err
}
