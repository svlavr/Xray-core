package routing

import (
	"context"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// UserStream transfers the concrete connection and payload already read beyond
// one trusted USER TCP handshake. The dispatcher owns both fields after
// DispatchUserStream is called, including on error.
type UserStream struct {
	Connection stat.Connection
	Retained   buf.MultiBuffer
	// Stop cancels and closes this stream's exact local owner. It is optional;
	// when present, the dispatcher may invoke it once for targeted close.
	Stop func() error
}

// UserStreamDispatcher admits a USER TCP stream before transport.Link is built.
// Ordinary/internal traffic continues to use Dispatcher.DispatchLink.
type UserStreamDispatcher interface {
	DispatchUserStream(context.Context, net.Destination, UserStream) error
}
