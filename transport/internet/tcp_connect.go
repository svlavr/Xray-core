package internet

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/net"
)

var ErrTCPConnectUnsupported = errors.New("native fresh TCP connect is unsupported")

// DialSystemTCPConnect opens one fresh numeric TCP socket with the effective
// native dialer and its platform controllers, without a source/socket override.
// Arbitrary adapters can return cached or logical connections; they cannot
// establish this boundary and are rejected before invoking them. This helper
// neither replaces the effective dialer nor observes other dial invocations.
func DialSystemTCPConnect(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if dest.Network != net.Network_TCP || dest.Address == nil || dest.Address.Family().IsDomain() || dest.Port == 0 {
		return nil, ErrTCPConnectUnsupported
	}
	d, ok := effectiveSystemDialer.(*DefaultSystemDialer)
	if !ok || d == nil {
		return nil, ErrTCPConnectUnsupported
	}
	return d.Dial(ctx, nil, dest, nil)
}
