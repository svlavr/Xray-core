package tun

import (
	"context"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

type originDispatcher struct {
	testDispatcher
	origin session.TrafficOrigin
}

func (d *originDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	d.origin = session.TrafficOriginFromContext(ctx)
	return d.testDispatcher.DispatchLink(ctx, dest, link)
}

func TestHandlerClassifiesTrafficOrigin(t *testing.T) {
	dispatcher := new(originDispatcher)
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher}
	handler.HandleConnection(newTestConn([]byte("uplink")), xnet.TCPDestination(xnet.LocalHostIP, 443))
	if dispatcher.origin != session.TrafficOriginUser {
		t.Fatalf("TUN traffic origin: got %v want USER", dispatcher.origin)
	}
}
