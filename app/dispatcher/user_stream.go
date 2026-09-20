package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

// DispatchUserStream is the canonical admission for the currently covered
// SOCKS USER TCP path. It builds accounting and lifecycle ownership before the
// link reaches sniffing or an outbound handler.
func (d *DefaultDispatcher) DispatchUserStream(ctx context.Context, dest net.Destination, stream routing.UserStream) error {
	if !dest.IsValid() || dest.Network != net.Network_TCP || stream.Connection == nil {
		buf.ReleaseMulti(stream.Retained)
		_ = common.Close(stream.Connection)
		return errors.New("user stream requires valid TCP destination and connection owner")
	}

	row := d.connections.beginUserStream(ctx, dest, stream.Stop)
	if row != nil {
		defer d.connections.end(row)
	}
	legacyUplink, legacyDownlink := userCounters(ctx, d.policy, d.stats)
	uplink, downlink := d.connections.prepareUserStream(row, legacyUplink)
	if uplink == nil {
		uplink = legacyUplink
	}

	reader := newUserStreamReader(buf.NewReader(stream.Connection), stream.Retained, stream.Connection, uplink)
	defer reader.Close()
	link := &transport.Link{
		Reader: reader,
		Writer: buf.NewBufferToBytesWriter(stream.Connection, legacyDownlink, downlink),
	}
	return d.dispatchPreparedUserStream(ctx, dest, link, row)
}

func (t *connectionTracker) prepareUserStream(row *connectionEntry, legacyUplink stats.Counter) (stats.Counter, stats.Counter) {
	if row == nil {
		return nil, nil
	}
	t.Lock()
	defer t.Unlock()
	if t.closed {
		return nil, nil
	}
	row.uplink = &flowByteCounter{forward: legacyUplink, tracker: t}
	row.downlink = &flowByteCounter{tracker: t}
	return row.uplink, row.downlink
}
