package routing

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// UserDispatcher optionally observes explicitly admitted user TCP requests.
// Call only at a trusted user ingress, never for internal/measurement traffic.
// The observed lifetime ends when DispatchUserLink returns, not at transport join.
// Ordinary Dispatcher implementations need not implement this interface.
type UserDispatcher interface {
	DispatchUserLink(context.Context, net.Destination, *transport.Link) error
}
