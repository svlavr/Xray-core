package reverse

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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

func (d *originRecordingDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.origin = session.TrafficOriginFromContext(ctx)
	return new(transport.Link), nil
}

func (d *originRecordingDispatcher) DispatchLink(ctx context.Context, _ net.Destination, _ *transport.Link) error {
	d.origin = session.TrafficOriginFromContext(ctx)
	return nil
}

func TestBridgeWorkerPreservesExplicitDataOrigin(t *testing.T) {
	recorder := new(originRecordingDispatcher)
	worker := &BridgeWorker{Dispatcher: recorder, Tag: "reverse-bridge"}
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Tag:  "synthetic-user-shaped-inbound",
		User: &protocol.MemoryUser{Email: "not-user@example.invalid"},
	})
	destination := net.TCPDestination(net.DomainAddress("example.invalid"), 443)

	if _, err := worker.Dispatch(ctx, destination); err != nil {
		t.Fatalf("bridge dispatch: %v", err)
	}
	if recorder.origin != session.TrafficOriginUser {
		t.Fatalf("bridge dispatch origin: got %v want USER", recorder.origin)
	}

	if err := worker.DispatchLink(ctx, destination, new(transport.Link)); err != nil {
		t.Fatalf("bridge dispatch link: %v", err)
	}
	if recorder.origin != session.TrafficOriginUser {
		t.Fatalf("bridge dispatch-link origin: got %v want USER", recorder.origin)
	}
}
