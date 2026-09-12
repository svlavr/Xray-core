package udphop

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
)

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return c.WrapPacketConnClientContext(context.Background(), raw, level, levelCount)
}

func (c *Config) WrapPacketConnClientContext(ctx context.Context, raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("udphop requires being at the outermost level")
	}
	return NewUDPHopConnContext(ctx, c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return nil, errors.New("udphop: client only")
}
