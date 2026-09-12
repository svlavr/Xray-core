package realm

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return c.WrapPacketConnClientContext(context.Background(), raw, level, levelCount)
}

func (c *Config) WrapPacketConnClientContext(ctx context.Context, raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	_, ok1 := raw.(*internet.FakePacketConn)
	if level != 0 || ok1 {
		return nil, errors.New("realm requires being at the outermost level")
	}
	return NewConnClientContext(ctx, c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return c.WrapPacketConnServerContext(context.Background(), raw, level, levelCount)
}

func (c *Config) WrapPacketConnServerContext(ctx context.Context, raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("realm requires being at the outermost level")
	}
	return NewConnServerContext(ctx, c, raw)
}
