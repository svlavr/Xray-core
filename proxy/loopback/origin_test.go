package loopback

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type originRecordingDispatcher struct {
	origin session.TrafficOrigin
}

func (*originRecordingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*originRecordingDispatcher) Start() error      { return nil }
func (*originRecordingDispatcher) Close() error      { return nil }
func (*originRecordingDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *originRecordingDispatcher) DispatchLink(ctx context.Context, _ net.Destination, _ *transport.Link) error {
	d.origin = session.TrafficOriginFromContext(ctx)
	return nil
}

func TestLoopbackPreservesTrafficOrigin(t *testing.T) {
	values := []session.TrafficOrigin{
		session.TrafficOriginUnknown,
		session.TrafficOriginUser,
		session.TrafficOriginInternal,
		session.TrafficOriginControlledMeasurement,
	}
	for _, want := range values {
		recorder := new(originRecordingDispatcher)
		loopback := &Loopback{inboundTag: "loopback", dispatcherInstance: recorder}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress("example.invalid"), 443),
		}})
		if want != session.TrafficOriginUnknown {
			ctx = session.ContextWithTrafficOrigin(ctx, want)
		}

		if err := loopback.Process(ctx, new(transport.Link), nil); err != nil {
			t.Fatalf("origin %v: process loopback: %v", want, err)
		}
		if recorder.origin != want {
			t.Fatalf("origin %v: got %v", want, recorder.origin)
		}
	}
}
