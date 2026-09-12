package internet

import (
	"context"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
)

func TestDialerProxyDetourOwnsParticipantAndPreservesDetachedContext(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:example.com:443", "", flow_observation.ByteScopeLogicalLinkAccepted)
	parentLink := new(transport.Link)
	parent, cancel := context.WithCancel(context.Background())
	ctx := flow_observation.ContextWithHandle(parent, handle)
	ctx = flow_observation.ContextWithRootDispatchOwner(ctx, handle)
	ctx = flow_observation.ContextWithLinkBinding(ctx, handle, parentLink, 0)
	cancel()

	started := make(chan struct{})
	release := make(chan struct{})
	nested := &dialerDetourTestHandler{dispatch: func(childCtx context.Context, _ *transport.Link) {
		if childCtx.Done() != nil || childCtx.Err() != nil {
			t.Error("dialerProxy lost stock context.WithoutCancel semantics")
		}
		if flow_observation.HandleFromContext(childCtx) != handle || flow_observation.RootDispatchOwnerFromContext(childCtx) != nil {
			t.Error("dialerProxy child inherited wrong flow authority")
		}
		close(started)
		<-release
	}}
	conn := redirect(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), "detour", nested)
	defer conn.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("nested dialerProxy handler did not start")
	}
	if view := handle.LogicalRoot().View(); view.LiveParticipantCount != 2 {
		t.Fatalf("dialerProxy participant was not acquired before go: %+v", view)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for handle.LogicalRoot().View().LiveParticipantCount != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("dialerProxy participant was not released after handler exit: %+v", handle.LogicalRoot().View())
		}
		time.Sleep(time.Millisecond)
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || len(snapshot.Records[0].Route.KnownHandlerChain) != 1 || snapshot.Records[0].Route.KnownHandlerChain[0].EntryKind != flow_observation.HandlerEntryDialerProxy {
		t.Fatalf("dialerProxy hop missing: %+v", snapshot.Records)
	}
}

type dialerDetourTestHandler struct {
	dispatch func(context.Context, *transport.Link)
}

func (*dialerDetourTestHandler) Type() interface{}                    { return (*dialerDetourTestHandler)(nil) }
func (*dialerDetourTestHandler) Start() error                         { return nil }
func (*dialerDetourTestHandler) Close() error                         { return nil }
func (*dialerDetourTestHandler) Tag() string                          { return "detour" }
func (*dialerDetourTestHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*dialerDetourTestHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *dialerDetourTestHandler) Dispatch(ctx context.Context, link *transport.Link) {
	h.dispatch(ctx, link)
}
