package loopback

import (
	"context"
	"testing"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestProcessSuppliesExactLoopbackContinuation(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	handle := registry.AdmitTCP(context.Background(), "", destination.String(), "", flow_observation.ByteScopeLogicalLinkAccepted)
	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	ctx := flow_observation.ContextWithHandle(context.Background(), handle)
	ctx = flow_observation.ContextWithLinkBinding(ctx, handle, link, 0)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: destination}})
	dispatcher := new(continuationDispatcher)
	loopback := &Loopback{dispatcherInstance: dispatcher}

	if err := loopback.Process(ctx, link, nil); err != nil {
		t.Fatal(err)
	}
	if !dispatcher.internal || dispatcher.scope == nil || dispatcher.actual != link {
		t.Fatalf("loopback did not pass exact continuation: %+v", dispatcher)
	}
	dispatcher.scope.Release(nil)
}

type continuationDispatcher struct {
	internal bool
	scope    *flow_observation.RedispatchScope
	actual   *transport.Link
}

func (*continuationDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*continuationDispatcher) Start() error      { return nil }
func (*continuationDispatcher) Close() error      { return nil }
func (*continuationDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *continuationDispatcher) DispatchLink(ctx context.Context, _ net.Destination, link *transport.Link) error {
	d.scope, d.internal = flow_observation.ConsumeLoopbackContinuation(ctx, link)
	d.actual = link
	return nil
}
