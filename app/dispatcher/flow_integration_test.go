package dispatcher

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestGetLinkBindsExactNativePipeDirections(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 2, MaxSeries: 2, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:example.com:443", "", flow_observation.ByteScopeLogicalLinkAccepted)
	dispatcher := new(DefaultDispatcher)
	inbound, outbound := dispatcher.getLink(context.Background(), handle)
	uplink := buf.New()
	uplink.WriteString("up")
	if err := inbound.Writer.WriteMultiBuffer(buf.MultiBuffer{uplink}); err != nil {
		t.Fatal(err)
	}
	downlink := buf.New()
	downlink.WriteString("down")
	if err := outbound.Writer.WriteMultiBuffer(buf.MultiBuffer{downlink}); err != nil {
		t.Fatal(err)
	}
	view := handle.LogicalRoot().View()
	if dispatcherObservation(t, view.ByteObservations, flow_observation.DirectionUplink, flow_observation.ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 2 || dispatcherObservation(t, view.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted).ObservedBytes.Value != 4 {
		t.Fatalf("native directions were crossed: %+v", view)
	}
}

func TestInitProvidesBoundedFlowObserverWithoutChangingFeatureRequirements(t *testing.T) {
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if dispatcher.FlowObserver() == nil {
		t.Fatal("flow observer unavailable after dispatcher initialization")
	}
	if err := dispatcher.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClosedDispatcherDoesNotReturnTypedNilMuxCarrier(t *testing.T) {
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	dispatcher.flows.Close()
	if carrier := dispatcher.NewMuxCarrierObservation(); carrier != nil {
		t.Fatalf("closed dispatcher returned a typed-nil MUX carrier: %T", carrier)
	}
}

func TestDefaultDispatcherProvidesXUDPEpochObservation(t *testing.T) {
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	destination := net.UDPDestination(net.DomainAddress("xudp-provider.example"), 53)
	observation := dispatcher.NewXUDPObservation(destination, "udp:source.example:1")
	if observation == nil {
		t.Fatal("initialized DefaultDispatcher did not provide XUDP observation")
	}
	if observation.Context(context.Background()) == nil {
		t.Fatal("XUDP observation did not preserve a dispatch context")
	}
}

func TestFlowObservationModesPreserveDispatchDelivery(t *testing.T) {
	for _, test := range []struct {
		name        string
		destination net.Destination
	}{
		{name: "TCP", destination: net.TCPDestination(net.DomainAddress("example.com"), 443)},
		{name: "UDP", destination: net.UDPDestination(net.DomainAddress("example.com"), 53)},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"enabled", "disabled", "faulted"} {
				t.Run(mode, func(t *testing.T) {
					handlerResult := make(chan error, 1)
					selectedTag := make(chan string, 1)
					handler := &continuationTestHandler{tag: "parity-out"}
					handler.dispatch = func(ctx context.Context, link *transport.Link) {
						outbounds := session.OutboundsFromContext(ctx)
						if len(outbounds) == 0 {
							selectedTag <- ""
						} else {
							selectedTag <- outbounds[len(outbounds)-1].Tag
						}
						err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("delivered"))})
						if err == nil {
							err = common.Close(link.Writer)
						}
						common.Interrupt(link.Reader)
						handlerResult <- err
					}
					dispatcher := new(DefaultDispatcher)
					manager := &continuationTestManager{defaultHandler: handler}
					if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
						t.Fatal(err)
					}
					defer dispatcher.Close()
					switch mode {
					case "disabled":
						dispatcher.flows.Close()
						dispatcher.flows = nil
					case "faulted":
						dispatcher.flows.Close()
					}

					inbound, err := dispatcher.Dispatch(context.Background(), test.destination)
					if err != nil {
						t.Fatal(err)
					}
					defer common.Close(inbound.Writer)
					defer common.Interrupt(inbound.Reader)
					delivered, err := inbound.Reader.ReadMultiBuffer()
					if err != nil {
						t.Fatal(err)
					}
					if got := delivered.String(); got != "delivered" {
						buf.ReleaseMulti(delivered)
						t.Fatalf("delivered bytes = %q, want %q", got, "delivered")
					}
					buf.ReleaseMulti(delivered)
					if _, err := inbound.Reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
						t.Fatalf("final read error = %v, want EOF", err)
					}
					if tag := <-selectedTag; tag != "parity-out" {
						t.Fatalf("selected outbound = %q, want parity-out", tag)
					}
					if err := <-handlerResult; err != nil {
						t.Fatalf("handler delivery failed: %v", err)
					}
				})
			}
		})
	}
}

func TestUDPAssociationUsesOneRootAndImmutableFirstRoute(t *testing.T) {
	initialDestination := net.UDPDestination(net.DomainAddress("first.example"), 53)
	packetDestinations := []net.Destination{
		net.UDPDestination(net.DomainAddress("second.example"), 5353),
		net.UDPDestination(net.DomainAddress("third.example"), 443),
	}
	type handlerReceipt struct {
		payload      string
		destinations []string
		err          error
	}
	handleBound := make(chan *flow_observation.Handle, 1)
	result := make(chan handlerReceipt, 1)
	handler := &continuationTestHandler{tag: "udp-out"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		handleBound <- flow_observation.HandleFromContext(ctx)
		receipt := handlerReceipt{}
		for {
			packets, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					receipt.err = err
				}
				break
			}
			for _, packet := range packets {
				receipt.payload += packet.String()
				if packet.UDP != nil {
					receipt.destinations = append(receipt.destinations, packet.UDP.String())
				}
			}
			buf.ReleaseMulti(packets)
		}
		if receipt.err == nil {
			response := buf.FromBytes([]byte("reply"))
			responseDestination := initialDestination
			response.UDP = &responseDestination
			receipt.err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{response})
		}
		if receipt.err == nil {
			receipt.err = common.Close(link.Writer)
		}
		common.Interrupt(link.Reader)
		result <- receipt
	}
	dispatcher := new(DefaultDispatcher)
	manager := &continuationTestManager{defaultHandler: handler}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	ctx, err := flow_observation.WithUserAdmission(context.Background(), flow_observation.Admission{Coordinate: []byte("route-udp")})
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := dispatcher.Dispatch(ctx, initialDestination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(inbound.Reader)
	var handle *flow_observation.Handle
	select {
	case handle = <-handleBound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP handler")
	}
	if handle == nil {
		t.Fatal("UDP handler received no association root")
	}
	for index, destination := range packetDestinations {
		packet := buf.FromBytes([]byte{byte('a' + index), byte('A' + index)})
		packetDestination := destination
		packet.UDP = &packetDestination
		if err := inbound.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
	}
	if err := common.Close(inbound.Writer); err != nil {
		t.Fatal(err)
	}
	downlink, err := inbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := downlink.String(); got != "reply" {
		buf.ReleaseMulti(downlink)
		t.Fatalf("UDP reply = %q, want reply", got)
	}
	buf.ReleaseMulti(downlink)
	receipt := <-result
	if receipt.err != nil || receipt.payload != "aAbB" || len(receipt.destinations) != 2 ||
		receipt.destinations[0] != packetDestinations[0].String() || receipt.destinations[1] != packetDestinations[1].String() {
		t.Fatalf("UDP packet stream changed: %+v", receipt)
	}

	deadline := time.Now().Add(2 * time.Second)
	var snapshot flow_observation.Snapshot
	for {
		snapshot = dispatcher.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP association did not terminate: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	record := snapshot.Records[0]
	if record.FlowKind != flow_observation.KindUDPAssociation || record.TrafficOrigin != flow_observation.OriginUser ||
		record.OriginalDestination != initialDestination.String() || record.EffectiveDestination != initialDestination.String() ||
		record.Route.SelectedTopLevelOutboundTag != "udp-out" || record.FlowID != handle.LogicalRoot().FlowID() {
		t.Fatalf("UDP association identity or first route changed: %+v", record)
	}
	uplink := dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionUplink, flow_observation.ByteScopeLogicalLinkAccepted)
	downlinkObservation := dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
	if uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 4}) ||
		downlinkObservation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(len("reply"))}) || len(record.ByteObservations) != 2 {
		t.Fatalf("UDP logical payload bytes were not counted exactly: %+v", record.ByteObservations)
	}
	if dispatcherSeries(t, snapshot.CounterSeries, flow_observation.DirectionUplink, flow_observation.ByteScopeLogicalLinkAccepted).CumulativeBytes != uplink.ObservedBytes ||
		dispatcherSeries(t, snapshot.CounterSeries, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted).CumulativeBytes != downlinkObservation.ObservedBytes {
		t.Fatalf("UDP durable series diverged from association bytes: %+v", snapshot.CounterSeries)
	}
}

func TestMuxLogicalDispatchUsesOnePresenceOnlyRootAndNativePipeBoundary(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("mux-child.example"), 443)
	handlerResult := make(chan error, 1)
	handler := &continuationTestHandler{tag: "mux-direct"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		handle := flow_observation.HandleFromContext(ctx)
		if handle == nil {
			handlerResult <- errors.New("MUX handler received no flow handle")
			return
		}
		request, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			handlerResult <- err
			return
		}
		if got := request.String(); got != "up" {
			buf.ReleaseMulti(request)
			handlerResult <- errors.New("MUX handler received changed uplink")
			return
		}
		buf.ReleaseMulti(request)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("down"))}); err != nil {
			handlerResult <- err
			return
		}
		closeErr := common.Close(link.Writer)
		common.Interrupt(link.Reader)
		handlerResult <- closeErr
	}
	dispatcher := new(DefaultDispatcher)
	manager := &continuationTestManager{defaultHandler: handler}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	carrier := dispatcher.NewMuxCarrierObservation()
	if carrier == nil {
		t.Fatal("dispatcher did not mint MUX carrier correlation")
	}
	scope := carrier.NewTCPSession([8]byte{}, destination, "")
	ctx := session.ContextWithMultiplexedLogicalSession(context.Background())
	ctx = scope.Context(ctx)
	inbound, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbound.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("up"))}); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(inbound.Writer); err != nil {
		t.Fatal(err)
	}
	response, err := inbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := response.String(); got != "down" {
		buf.ReleaseMulti(response)
		t.Fatalf("MUX response = %q, want down", got)
	}
	buf.ReleaseMulti(response)
	common.Interrupt(inbound.Reader)
	if err := <-handlerResult; err != nil {
		t.Fatal(err)
	}

	beforeClose := dispatcher.FlowObserver().Snapshot()
	if len(beforeClose.Records) != 1 || beforeClose.Records[0].FlowKind != flow_observation.KindMUXLogical ||
		beforeClose.Records[0].CompletionState == flow_observation.CompletionTerminal {
		t.Fatalf("handler return fabricated MUX owner close: %+v", beforeClose)
	}
	scope.AfterClose()
	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := dispatcher.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			if record.Route.SelectedTopLevelOutboundTag != "mux-direct" || record.CarrierReference == "" ||
				record.TrafficOrigin != "" || record.OriginProof != "" || record.CarrierProof != "" ||
				record.TerminalClass != "" || record.TechnicalErrorCategory != "" || len(record.Issues) != 0 {
				t.Fatalf("MUX routed record fabricated absent facts: %+v", record)
			}
			uplink := dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionUplink, flow_observation.ByteScopeLogicalLinkAccepted)
			downlink := dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
			if uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 2}) ||
				downlink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 4}) || len(record.ByteObservations) != 2 {
				t.Fatalf("MUX bytes were double-counted or changed: uplink=%+v downlink=%+v", uplink, downlink)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("MUX scope close did not terminalize exact root: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMuxScopeReplayCannotRewriteBoundRoute(t *testing.T) {
	firstDestination := net.TCPDestination(net.DomainAddress("first.example"), 443)
	secondDestination := net.TCPDestination(net.DomainAddress("second.example"), 8443)
	firstCalled := make(chan struct{})
	secondHandle := make(chan *flow_observation.Handle, 1)
	firstHandler := &continuationTestHandler{tag: "first"}
	firstHandler.dispatch = func(_ context.Context, link *transport.Link) {
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		close(firstCalled)
	}
	secondHandler := &continuationTestHandler{tag: "second"}
	secondHandler.dispatch = func(ctx context.Context, link *transport.Link) {
		secondHandle <- flow_observation.HandleFromContext(ctx)
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
	}
	dispatcher := new(DefaultDispatcher)
	manager := &continuationTestManager{
		defaultHandler: firstHandler,
		tagged: map[string]outbound.Handler{
			"first":  firstHandler,
			"second": secondHandler,
		},
	}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	carrier := dispatcher.NewMuxCarrierObservation()
	scope := carrier.NewTCPSession([8]byte{}, firstDestination, "")
	firstCtx := scope.Context(session.ContextWithMultiplexedLogicalSession(context.Background()))
	firstCtx = session.SetForcedOutboundTagToContext(firstCtx, "first")
	firstLink, err := dispatcher.Dispatch(firstCtx, firstDestination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close(firstLink.Writer)
	defer common.Interrupt(firstLink.Reader)
	select {
	case <-firstCalled:
	case <-time.After(time.Second):
		t.Fatal("first MUX dispatch did not reach its handler")
	}
	firstSnapshot := dispatcher.FlowObserver().Snapshot()
	if len(firstSnapshot.Records) != 1 || firstSnapshot.Records[0].Route.SelectedTopLevelOutboundTag != "first" {
		t.Fatalf("first MUX route was not published: %+v", firstSnapshot)
	}

	secondCtx := scope.Context(session.ContextWithMultiplexedLogicalSession(context.Background()))
	secondCtx = session.SetForcedOutboundTagToContext(secondCtx, "second")
	secondLink, err := dispatcher.Dispatch(secondCtx, secondDestination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close(secondLink.Writer)
	defer common.Interrupt(secondLink.Reader)
	select {
	case handle := <-secondHandle:
		if handle != nil {
			t.Fatalf("replayed MUX dispatch inherited stale handle %s", handle.LogicalRoot().FlowID())
		}
	case <-time.After(time.Second):
		t.Fatal("replayed MUX dispatch did not preserve stock handler invocation")
	}
	afterReplay := dispatcher.FlowObserver().Snapshot()
	if len(afterReplay.Records) != 1 ||
		afterReplay.Records[0].Route.SelectedTopLevelOutboundTag != "first" ||
		afterReplay.Records[0].EffectiveDestination != firstDestination.String() {
		t.Fatalf("replayed MUX scope rewrote the original route: %+v", afterReplay)
	}
	scope.AfterClose()
}

func TestLoopbackRedispatchKeepsOneRootAndOneOwnerSeal(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	dispatcher := new(DefaultDispatcher)
	final := &continuationTestHandler{tag: "final"}
	loop := &continuationTestHandler{tag: "loop", dispatch: func(ctx context.Context, link *transport.Link) {
		ctx = flow_observation.ContextWithLoopbackContinuation(ctx, link)
		_ = dispatcher.DispatchLink(ctx, destination, link)
	}}
	manager := &continuationTestManager{defaultHandler: final, tagged: map[string]outbound.Handler{"loop": loop}}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()

	final.dispatch = func(ctx context.Context, link *transport.Link) {
		final.mu.Lock()
		final.owner = flow_observation.RootDispatchOwnerFromContext(ctx)
		final.scope = flow_observation.RedispatchScopeFromContext(ctx)
		final.handle = flow_observation.HandleFromContext(ctx)
		final.mu.Unlock()
	}
	ctx := session.SetForcedOutboundTagToContext(context.Background(), "loop")
	inbound, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	common.Close(inbound.Writer)
	common.Interrupt(inbound.Reader)

	deadline := time.Now().Add(2 * time.Second)
	var record flow_observation.Record
	for {
		snapshot := dispatcher.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 {
			record = snapshot.Records[0]
			if record.CompletionState == flow_observation.CompletionTerminal {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("loopback flow did not terminate: %+v", record)
		}
		time.Sleep(time.Millisecond)
	}
	if len(record.Route.KnownHandlerChain) != 2 ||
		record.Route.KnownHandlerChain[0].HandlerTag != "loop" ||
		record.Route.KnownHandlerChain[1].HandlerTag != "final" ||
		record.Route.KnownHandlerChain[1].EntryKind != flow_observation.HandlerEntryLoopbackRedispatch {
		t.Fatalf("loopback did not extend one exact route chain: %+v", record.Route)
	}
	final.mu.Lock()
	defer final.mu.Unlock()
	if final.owner != nil || final.scope == nil || final.handle == nil || final.scope.Handle() != final.handle {
		t.Fatalf("nested handler received wrong flow authority: owner=%v scope=%v handle=%v", final.owner, final.scope, final.handle)
	}
}

func TestDispatchLinkWithoutContinuationMasksInheritedRoot(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	final := &continuationTestHandler{tag: "final"}
	manager := &continuationTestManager{defaultHandler: final}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	handle := dispatcher.flows.AdmitTCP(context.Background(), "", destination.String(), "", flow_observation.ByteScopeLogicalLinkAccepted)
	ctx := flow_observation.ContextWithHandle(context.Background(), handle)
	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	called := false
	final.dispatch = func(ctx context.Context, _ *transport.Link) {
		called = true
		if flow_observation.HandleFromContext(ctx) != nil || flow_observation.RootDispatchOwnerFromContext(ctx) != nil || flow_observation.RedispatchScopeFromContext(ctx) != nil {
			t.Error("handler inherited root authority without exact continuation")
		}
	}
	if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
		t.Fatal(err)
	}
	if !called || handle.LogicalRoot().View().LifecycleFault != flow_observation.LifecycleFaultContinuationMissing {
		t.Fatalf("missing continuation did not preserve traffic and fail observation closed: called=%v view=%+v", called, handle.LogicalRoot().View())
	}
}

func TestFailedDispatchAdmissionCannotReuseInheritedRoot(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	final := &continuationTestHandler{tag: "final"}
	manager := &continuationTestManager{defaultHandler: final}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	handle := dispatcher.flows.AdmitTCP(context.Background(), "", destination.String(), "", flow_observation.ByteScopeLogicalLinkAccepted)
	ctx := flow_observation.ContextWithRootDispatchOwner(flow_observation.ContextWithHandle(context.Background(), handle), handle)
	dispatcher.flows.Close()
	called := make(chan struct{})
	final.dispatch = func(ctx context.Context, _ *transport.Link) {
		if flow_observation.HasFlowObservation(ctx) {
			t.Error("failed admission reused inherited flow root")
		}
		close(called)
	}
	inbound, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close(inbound.Writer)
	defer common.Interrupt(inbound.Reader)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("stock dispatch did not continue after observation admission failed")
	}
}

func TestFreshDispatchMasksInheritedExternalOwnerScope(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	final := &continuationTestHandler{tag: "final"}
	manager := &continuationTestManager{defaultHandler: final}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()

	inherited := dispatcher.flows.AdmitTCP(context.Background(), "", destination.String(), "", flow_observation.ByteScopeUnknown)
	scope := flow_observation.NewExternalOwnerScope(flow_observation.ExternalOwnerListenerTCP)
	ctx := flow_observation.ContextWithHandle(context.Background(), inherited)
	ctx = flow_observation.ContextWithExternalOwnerScope(ctx, scope)
	called := make(chan struct{})
	final.dispatch = func(ctx context.Context, _ *transport.Link) {
		if flow_observation.ExternalOwnerScopeFromContext(ctx) != nil || flow_observation.HandleFromContext(ctx) != flow_observation.RootDispatchOwnerFromContext(ctx) {
			t.Error("fresh Dispatch inherited external owner authority")
		}
		close(called)
	}
	inbound, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close(inbound.Writer)
	defer common.Interrupt(inbound.Reader)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("fresh stock dispatch did not reach handler")
	}
	if scope.Handle() != nil {
		t.Fatal("fresh Dispatch bound inherited external owner token")
	}
}

func TestExternalOwnerDispatchLinkWaitsForActualOwnerClose(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	final := &continuationTestHandler{tag: "final"}
	manager := &continuationTestManager{defaultHandler: final}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	scope := flow_observation.NewExternalOwnerScope(flow_observation.ExternalOwnerListenerTCP)
	ctx := flow_observation.ContextWithExternalOwnerScope(context.Background(), scope)
	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
		t.Fatal(err)
	}
	handle := scope.Handle()
	if handle == nil || scope.Link() != link {
		t.Fatal("external DispatchLink did not bind the exact root and link")
	}
	before := dispatcher.FlowObserver().Snapshot()
	if len(before.Records) != 1 || before.Records[0].CompletionState == flow_observation.CompletionTerminal || before.Records[0].Route.SelectedTopLevelOutboundTag != "final" {
		t.Fatalf("DispatchLink return fabricated owner close or lost selection: %+v", before)
	}
	scope.AfterOwnerClose(nil, nil)
	after := dispatcher.FlowObserver().Snapshot()
	if after.Records[0].CompletionState != flow_observation.CompletionTerminal || after.Records[0].CompletionEvidence != flow_observation.CompletionEvidenceRootLogicalLinkQuiesced || dispatcherObservation(t, after.Records[0].ByteObservations, flow_observation.DirectionUplink, flow_observation.ByteScopeDispatcherExternalLinkIO).ObservedBytes != (flow_observation.OptionalUint64{Known: true}) {
		t.Fatalf("actual external owner close did not terminalize with exact external byte scope: %+v", after.Records[0])
	}
}

func TestExternalUDPOwnerDispatchLinkUsesAssociationRoot(t *testing.T) {
	destination := net.UDPDestination(net.DomainAddress("first.example"), 53)
	final := &continuationTestHandler{tag: "external-udp"}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), &continuationTestManager{defaultHandler: final}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()

	scope := flow_observation.NewExternalOwnerScope(flow_observation.ExternalOwnerTUNUDP)
	ctx := flow_observation.ContextWithExternalOwnerScope(context.Background(), scope)
	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	if err := dispatcher.DispatchLink(ctx, destination, link); err != nil {
		t.Fatal(err)
	}
	if handle := scope.Handle(); handle == nil {
		t.Fatalf("external UDP owner did not bind an association root: %+v", handle)
	}
	before := dispatcher.FlowObserver().Snapshot()
	if len(before.Records) != 1 || before.Records[0].FlowKind != flow_observation.KindUDPAssociation || before.Records[0].OriginalDestination != destination.String() || before.Records[0].CompletionState == flow_observation.CompletionTerminal {
		t.Fatalf("external UDP DispatchLink changed first destination or terminalized early: %+v", before)
	}
	scope.AfterOwnerClose(nil, nil)
	after := dispatcher.FlowObserver().Snapshot()
	if len(after.Records) != 1 || after.Records[0].CompletionState != flow_observation.CompletionTerminal {
		t.Fatalf("external UDP owner close did not terminalize root: %+v", after)
	}
}

func TestMultiplexedLogicalDispatchRunsWithoutGenericAdmission(t *testing.T) {
	for _, test := range []struct {
		name        string
		destination net.Destination
	}{
		{name: "decoded MUX TCP", destination: net.TCPDestination(net.DomainAddress("example.com"), 443)},
		{name: "decoded MUX or XUDP UDP marker", destination: net.UDPDestination(net.DomainAddress("example.com"), 53)},
	} {
		t.Run(test.name, func(t *testing.T) {
			handlerResult := make(chan error, 1)
			handler := &continuationTestHandler{tag: "mux-child"}
			handler.dispatch = func(_ context.Context, link *transport.Link) {
				err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("delivered"))})
				if err == nil {
					err = common.Close(link.Writer)
				}
				common.Interrupt(link.Reader)
				handlerResult <- err
			}
			dispatcher := new(DefaultDispatcher)
			manager := &continuationTestManager{defaultHandler: handler}
			if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			defer dispatcher.Close()

			ctx := session.ContextWithMultiplexedLogicalSession(context.Background())
			inbound, err := dispatcher.Dispatch(ctx, test.destination)
			if err != nil {
				t.Fatal(err)
			}
			defer common.Close(inbound.Writer)
			defer common.Interrupt(inbound.Reader)
			delivered, err := inbound.Reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if got := delivered.String(); got != "delivered" {
				buf.ReleaseMulti(delivered)
				t.Fatalf("multiplexed child stock traffic changed: got %q", got)
			}
			buf.ReleaseMulti(delivered)
			if err := <-handlerResult; err != nil {
				t.Fatal(err)
			}

			snapshot := dispatcher.FlowObserver().Snapshot()
			if len(snapshot.Records) != 0 || len(snapshot.CounterSeries) != 0 {
				t.Fatalf("decoded multiplexed child received a generic root: %+v", snapshot)
			}
		})
	}
}

func TestZeroGlobalIDMuxUDPDispatchUsesOneMuxLogicalRoot(t *testing.T) {
	destination := net.UDPDestination(net.DomainAddress("packet.example"), 53)
	handlerResult := make(chan error, 1)
	handler := &continuationTestHandler{tag: "mux-udp"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		if flow_observation.HandleFromContext(ctx) == nil {
			handlerResult <- errors.New("MUX UDP handler has no logical flow handle")
			return
		}
		packets, err := link.Reader.ReadMultiBuffer()
		if err == nil {
			if packets.String() != "request" {
				err = errors.New("MUX UDP request changed")
			}
			buf.ReleaseMulti(packets)
		}
		if err == nil {
			err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("reply"))})
		}
		if err == nil {
			err = common.Close(link.Writer)
		}
		common.Interrupt(link.Reader)
		handlerResult <- err
	}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), &continuationTestManager{defaultHandler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()

	carrier := dispatcher.NewMuxCarrierObservation()
	observation := session.MuxUDPSessionObservationFromCarrier(carrier, [8]byte{}, destination, "")
	scope, ok := observation.(*flow_observation.MuxSessionScope)
	if !ok || scope == nil {
		t.Fatalf("dispatcher did not mint a zero-ID MUX UDP scope: %T", observation)
	}
	ctx := session.ContextWithMultiplexedLogicalSession(context.Background())
	ctx = flow_observation.ContextWithMuxSessionScope(ctx, scope)
	inbound, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbound.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(inbound.Writer); err != nil {
		t.Fatal(err)
	}
	reply, err := inbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if reply.String() != "reply" {
		buf.ReleaseMulti(reply)
		t.Fatalf("MUX UDP reply = %q, want reply", reply.String())
	}
	buf.ReleaseMulti(reply)
	if err := <-handlerResult; err != nil {
		t.Fatal(err)
	}
	scope.AfterClose()

	deadline := time.Now().Add(time.Second)
	for {
		snapshot := dispatcher.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			if record.FlowKind != flow_observation.KindMUXLogical || record.OriginalDestination != destination.String() ||
				record.CarrierReference == "" || record.TerminalClass != "" || len(snapshot.CounterSeries) != 2 {
				t.Fatalf("MUX UDP record is not one presence-only logical root: %+v", snapshot)
			}
			if dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionUplink, flow_observation.ByteScopeLogicalLinkAccepted).ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 7}) ||
				dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted).ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 5}) {
				t.Fatalf("MUX UDP native-pipe payload bytes were not exact: %+v", record.ByteObservations)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("MUX UDP logical root did not terminalize: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUDPDispatchLinkDoesNotCreateGenericAssociation(t *testing.T) {
	destination := net.UDPDestination(net.DomainAddress("example.com"), 53)
	handler := &continuationTestHandler{tag: "external-udp"}
	called := false
	handler.dispatch = func(ctx context.Context, _ *transport.Link) {
		called = true
		if flow_observation.HandleFromContext(ctx) != nil || flow_observation.RootDispatchOwnerFromContext(ctx) != nil {
			t.Error("UDP DispatchLink received generic association authority")
		}
	}
	dispatcher := new(DefaultDispatcher)
	if err := dispatcher.Init(new(Config), &continuationTestManager{defaultHandler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	reader, writer := pipe.New()
	defer common.Interrupt(reader)
	defer common.Close(writer)
	if err := dispatcher.DispatchLink(context.Background(), destination, &transport.Link{Reader: reader, Writer: writer}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("UDP DispatchLink did not preserve stock handler invocation")
	}
	if snapshot := dispatcher.FlowObserver().Snapshot(); len(snapshot.Records) != 0 || len(snapshot.CounterSeries) != 0 {
		t.Fatalf("UDP DispatchLink created a generic association: %+v", snapshot)
	}
}

func TestUnknownCarrierDoesNotInvalidateLogicalByteSeries(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	handler := &continuationTestHandler{
		tag: "custom-outbound",
	}
	handler.dispatch = func(_ context.Context, link *transport.Link) {
		defer common.Close(link.Writer)
		defer common.Interrupt(link.Reader)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("logical"))}); err != nil {
			t.Errorf("logical write failed: %v", err)
		}
	}
	dispatcher := new(DefaultDispatcher)
	manager := &continuationTestManager{defaultHandler: handler}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()

	inbound, err := dispatcher.Dispatch(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(inbound.Reader)
	if err := common.Close(inbound.Writer); err != nil {
		t.Fatal(err)
	}
	delivered, err := inbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := delivered.String(); got != "logical" {
		buf.ReleaseMulti(delivered)
		t.Fatalf("logical traffic changed: got %q", got)
	}
	buf.ReleaseMulti(delivered)

	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := dispatcher.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			if record.CarrierProof != flow_observation.CarrierProofUnknown || !recordHasIssue(record, flow_observation.IssueCarrierProofUnknown) {
				t.Fatalf("custom carrier uncertainty was not retained: %+v", record)
			}
			observation := dispatcherObservation(t, record.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
			series := dispatcherSeries(t, snapshot.CounterSeries, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
			if observation.State != flow_observation.ByteObservationStateProven || observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(len("logical"))}) || series.State != flow_observation.SeriesStateContinuous || series.CumulativeBytes != observation.ObservedBytes {
				t.Fatalf("carrier uncertainty contaminated logical bytes: observation=%+v series=%+v", observation, series)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("MUX-marked root did not reach terminal: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInspectHandlerCarrierMarksOnlyF2CarrierShapes(t *testing.T) {
	for _, test := range []struct {
		name        string
		protocol    string
		wantProof   flow_observation.CarrierProof
		wantF2Issue bool
	}{
		{name: "raw TCP", protocol: "tcp", wantProof: flow_observation.CarrierProofNotApplicable},
		{name: "WebSocket", protocol: "websocket", wantProof: flow_observation.CarrierProofNotApplicable},
		{name: "HTTPUpgrade", protocol: "httpupgrade", wantProof: flow_observation.CarrierProofNotApplicable},
		{name: "UDP transport", protocol: "udp", wantProof: flow_observation.CarrierProofUnknown, wantF2Issue: true},
		{name: "mKCP", protocol: "mkcp", wantProof: flow_observation.CarrierProofUnknown, wantF2Issue: true},
		{name: "Hysteria", protocol: "hysteria", wantProof: flow_observation.CarrierProofUnknown, wantF2Issue: true},
		{name: "SplitHTTP", protocol: "splithttp", wantProof: flow_observation.CarrierProofUnknown, wantF2Issue: true},
		{name: "gRPC", protocol: "grpc", wantProof: flow_observation.CarrierProofUnknown, wantF2Issue: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof, issues := carrierObservationIssues(flow_observation.CarrierObservation{Proof: test.wantProof, CarrierF2Required: test.wantF2Issue})
			gotF2Issue := false
			for _, issue := range issues {
				if issue == flow_observation.IssueCarrierF2Required {
					gotF2Issue = true
				}
			}
			if proof != test.wantProof || gotF2Issue != test.wantF2Issue {
				t.Fatalf("protocol %q carrier classification: proof=%s issues=%v", test.protocol, proof, issues)
			}
		})
	}
	proof, issues := carrierObservationIssues(flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofProven, MuxF2Required: true})
	if proof != flow_observation.CarrierProofUnknown || len(issues) != 1 || issues[0] != flow_observation.IssueMuxCarrierF2Required {
		t.Fatalf("contradictory carrier descriptor did not fail closed: proof=%s issues=%v", proof, issues)
	}
	custom := &continuationTestHandler{panicOnSenderSettings: true}
	proof, issues = inspectHandlerCarrier(custom)
	if proof != flow_observation.CarrierProofUnknown || len(issues) != 1 || issues[0] != flow_observation.IssueCarrierProofUnknown {
		t.Fatalf("custom handler carrier proof did not fail closed: proof=%s issues=%v", proof, issues)
	}
}

func TestDispatchTaskSiblingMayDeliverAfterHandlerReturn(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	wantErr := errors.New("first copy task failed")
	firstTaskReturned := make(chan error, 1)
	lateTaskStarted := make(chan struct{})
	allowLateWrite := make(chan struct{})
	var allowLateWriteOnce sync.Once
	releaseLateWrite := func() { allowLateWriteOnce.Do(func() { close(allowLateWrite) }) }
	lateTaskExited := make(chan struct{})
	handleBound := make(chan *flow_observation.Handle, 1)
	handler := &continuationTestHandler{tag: "paired-copy"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		handleBound <- flow_observation.HandleFromContext(ctx)
		err := task.Run(ctx,
			func() error {
				<-lateTaskStarted
				_, err := link.Reader.ReadMultiBuffer()
				if !errors.Is(err, io.EOF) {
					return err
				}
				return wantErr
			},
			func() error {
				close(lateTaskStarted)
				<-allowLateWrite
				defer close(lateTaskExited)
				payload := buf.FromBytes([]byte("late"))
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
					return err
				}
				return common.Close(link.Writer)
			},
		)
		firstTaskReturned <- err
	}
	dispatcher := new(DefaultDispatcher)
	manager := &continuationTestManager{defaultHandler: handler}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	defer releaseLateWrite()

	inbound, err := dispatcher.Dispatch(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close(inbound.Writer)
	defer common.Interrupt(inbound.Reader)
	var handle *flow_observation.Handle
	select {
	case handle = <-handleBound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for paired-copy handler")
	}
	if handle == nil {
		t.Fatal("paired-copy handler did not receive the logical flow root")
	}
	if err := common.Close(inbound.Writer); err != nil {
		t.Fatal(err)
	}
	var runErr error
	select {
	case runErr = <-firstTaskReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first task result")
	}
	if !errors.Is(runErr, wantErr) {
		t.Fatalf("first task returned %v, want %v", runErr, wantErr)
	}

	deadline := time.Now().Add(2 * time.Second)
	var view flow_observation.LifecycleView
	for {
		view = handle.LogicalRoot().View()
		if view.Phase == flow_observation.LifecyclePhaseOwnerSealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("handler return was not published: %+v", view)
		}
		time.Sleep(time.Millisecond)
	}
	if view.LiveParticipantCount == 0 || view.UplinkState != flow_observation.DirectionStateQuiescent || view.DownlinkState != flow_observation.DirectionStateOpen {
		t.Fatalf("handler return lost the live sibling or one-direction half-close: %+v", view)
	}
	for _, event := range dispatcher.flows.EventsAfter(0, 0).Events {
		if event.Type == flow_observation.EventTerminal {
			t.Fatalf("terminal event preceded late sibling exit: %+v", event)
		}
	}

	releaseLateWrite()
	downlink, err := inbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := downlink.String(); got != "late" {
		buf.ReleaseMulti(downlink)
		t.Fatalf("late sibling delivered %q, want %q", got, "late")
	}
	buf.ReleaseMulti(downlink)
	select {
	case <-lateTaskExited:
	case <-time.After(time.Second):
		t.Fatal("late sibling did not exit after its write")
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		view = handle.LogicalRoot().View()
		if view.Phase == flow_observation.LifecyclePhaseTerminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow did not terminate after sibling exit and pipe drain: %+v", view)
		}
		time.Sleep(time.Millisecond)
	}
	observation := dispatcherObservation(t, view.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
	if observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(len("late"))}) || view.Terminal == nil || view.Terminal.TerminalClass != flow_observation.TerminalClassLocalError {
		t.Fatalf("late accepted bytes or first task outcome were lost: %+v", view)
	}
	snapshot := dispatcher.FlowObserver().Snapshot()
	terminalEvents := 0
	for _, event := range dispatcher.flows.EventsAfter(0, 0).Events {
		if event.Type == flow_observation.EventTerminal {
			terminalEvents++
		}
	}
	series := dispatcherSeries(t, snapshot.CounterSeries, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
	if terminalEvents != 1 || series.CumulativeBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(len("late"))}) || series.ActiveFlowCount != (flow_observation.OptionalUint64{Known: true}) {
		t.Fatalf("terminal publication or durable series is inconsistent: events=%d series=%+v snapshot=%+v", terminalEvents, series, snapshot)
	}
}

func TestDispatchCancellationWaitsForStartedTasksAndLateAcceptedBytes(t *testing.T) {
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	taskStarted := make(chan struct{}, 2)
	releaseFirstTask := make(chan struct{})
	allowLateWrite := make(chan struct{})
	var releaseFirstTaskOnce sync.Once
	var allowLateWriteOnce sync.Once
	releaseFirst := func() { releaseFirstTaskOnce.Do(func() { close(releaseFirstTask) }) }
	releaseLateWrite := func() { allowLateWriteOnce.Do(func() { close(allowLateWrite) }) }
	lateTaskExited := make(chan struct{})
	handleBound := make(chan *flow_observation.Handle, 1)
	runReturned := make(chan error, 1)
	handler := &continuationTestHandler{tag: "cancelled-paired-copy"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		handleBound <- flow_observation.HandleFromContext(ctx)
		runReturned <- task.Run(ctx,
			func() error {
				taskStarted <- struct{}{}
				<-releaseFirstTask
				return nil
			},
			func() error {
				taskStarted <- struct{}{}
				<-allowLateWrite
				defer close(lateTaskExited)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("after-cancel"))}); err != nil {
					return err
				}
				return common.Close(link.Writer)
			},
		)
	}
	dispatcher := new(DefaultDispatcher)
	manager := &continuationTestManager{defaultHandler: handler}
	if err := dispatcher.Init(new(Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	defer releaseFirst()
	defer releaseLateWrite()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inbound, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(inbound.Reader)
	var handle *flow_observation.Handle
	select {
	case handle = <-handleBound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cancelled handler")
	}
	if handle == nil {
		t.Fatal("cancelled handler did not receive the logical flow root")
	}
	for started := 0; started < 2; started++ {
		select {
		case <-taskStarted:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out after %d of 2 copy tasks started", started)
		}
	}
	if err := common.Close(inbound.Writer); err != nil {
		t.Fatal(err)
	}
	cancel()
	var runErr error
	select {
	case runErr = <-runReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cancelled task.Run")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("task.Run returned %v, want cancellation", runErr)
	}

	deadline := time.Now().Add(2 * time.Second)
	var view flow_observation.LifecycleView
	for {
		view = handle.LogicalRoot().View()
		if view.Phase == flow_observation.LifecyclePhaseOwnerSealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancellation did not seal the owner: %+v", view)
		}
		time.Sleep(time.Millisecond)
	}
	if view.LiveParticipantCount < 2 || view.UplinkState != flow_observation.DirectionStateQuiescent || view.DownlinkState != flow_observation.DirectionStateOpen {
		t.Fatalf("cancellation overtook started tasks or half-close state: %+v", view)
	}

	releaseFirst()
	releaseLateWrite()
	downlink, err := inbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := downlink.String(); got != "after-cancel" {
		buf.ReleaseMulti(downlink)
		t.Fatalf("late task delivered %q, want %q", got, "after-cancel")
	}
	buf.ReleaseMulti(downlink)
	select {
	case <-lateTaskExited:
	case <-time.After(time.Second):
		t.Fatal("late task did not exit after cancellation")
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		view = handle.LogicalRoot().View()
		if view.Phase == flow_observation.LifecyclePhaseTerminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancelled flow did not terminate after tasks exited: %+v", view)
		}
		time.Sleep(time.Millisecond)
	}
	observation := dispatcherObservation(t, view.ByteObservations, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
	if observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(len("after-cancel"))}) || view.Terminal == nil || view.Terminal.TerminalClass != flow_observation.TerminalClassCancelled {
		t.Fatalf("cancellation terminal or late accepted bytes were lost: %+v", view)
	}
	snapshot := dispatcher.FlowObserver().Snapshot()
	terminalEvents := 0
	for _, event := range dispatcher.flows.EventsAfter(0, 0).Events {
		if event.Type == flow_observation.EventTerminal {
			terminalEvents++
		}
	}
	series := dispatcherSeries(t, snapshot.CounterSeries, flow_observation.DirectionDownlink, flow_observation.ByteScopeLogicalLinkAccepted)
	if terminalEvents != 1 || series.CumulativeBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(len("after-cancel"))}) || series.ActiveFlowCount != (flow_observation.OptionalUint64{Known: true}) {
		t.Fatalf("cancelled terminal publication or durable series is inconsistent: events=%d series=%+v snapshot=%+v", terminalEvents, series, snapshot)
	}
}

func dispatcherObservation(t testing.TB, observations []flow_observation.ByteObservation, direction flow_observation.Direction, scope flow_observation.ByteScope) flow_observation.ByteObservation {
	t.Helper()
	for _, observation := range observations {
		if observation.Direction == direction && observation.ByteScope == scope {
			return observation
		}
	}
	t.Fatalf("missing byte observation direction=%s scope=%s in %+v", direction, scope, observations)
	return flow_observation.ByteObservation{}
}

func dispatcherSeries(t testing.TB, series []flow_observation.CounterSeries, direction flow_observation.Direction, scope flow_observation.ByteScope) flow_observation.CounterSeries {
	t.Helper()
	for _, candidate := range series {
		if candidate.Key.Direction == direction && candidate.Key.ByteScope == scope {
			return candidate
		}
	}
	t.Fatalf("missing counter series direction=%s scope=%s in %+v", direction, scope, series)
	return flow_observation.CounterSeries{}
}

type continuationTestHandler struct {
	tag                   string
	panicOnSenderSettings bool
	dispatch              func(context.Context, *transport.Link)
	mu                    sync.Mutex
	owner                 *flow_observation.Handle
	scope                 *flow_observation.RedispatchScope
	handle                *flow_observation.Handle
}

func (h *continuationTestHandler) Type() interface{} { return (*continuationTestHandler)(nil) }
func (h *continuationTestHandler) Start() error      { return nil }
func (h *continuationTestHandler) Close() error      { return nil }
func (h *continuationTestHandler) Tag() string       { return h.tag }
func (h *continuationTestHandler) SenderSettings() *serial.TypedMessage {
	if h.panicOnSenderSettings {
		panic("carrier inspection must not serialize sender settings")
	}
	return nil
}
func (h *continuationTestHandler) ProxySettings() *serial.TypedMessage { return nil }
func (h *continuationTestHandler) Dispatch(ctx context.Context, link *transport.Link) {
	if h.dispatch != nil {
		h.dispatch(ctx, link)
	}
}

func recordHasIssue(record flow_observation.Record, issue flow_observation.Issue) bool {
	for _, candidate := range record.Issues {
		if candidate == issue {
			return true
		}
	}
	return false
}

func BenchmarkUDPAssociationDispatchAdmission(b *testing.B) {
	const batchSize = 256
	for _, observed := range []bool{false, true} {
		name := "observer-disabled"
		if observed {
			name = "observer-enabled"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			completed := 0
			for completed < b.N {
				b.StopTimer()
				done := make(chan struct{})
				handler := &continuationTestHandler{tag: "udp-out"}
				handler.dispatch = func(_ context.Context, link *transport.Link) {
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					done <- struct{}{}
				}
				dispatcher := new(DefaultDispatcher)
				if err := dispatcher.Init(new(Config), &continuationTestManager{defaultHandler: handler}, nil, nil, nil); err != nil {
					b.Fatal(err)
				}
				if !observed {
					dispatcher.flows.Close()
					dispatcher.flows = nil
				}
				remaining := min(batchSize, b.N-completed)
				b.StartTimer()
				for range remaining {
					link, err := dispatcher.Dispatch(context.Background(), net.UDPDestination(net.DomainAddress("example.com"), 53))
					if err != nil {
						b.Fatal(err)
					}
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					<-done
				}
				b.StopTimer()
				if err := dispatcher.Close(); err != nil {
					b.Fatal(err)
				}
				completed += remaining
			}
		})
	}
}

func BenchmarkUDPAssociationNativePipeWrite(b *testing.B) {
	const payloadSize = 128
	for _, observed := range []bool{false, true} {
		name := "observer-disabled"
		if observed {
			name = "observer-enabled"
		}
		b.Run(name, func(b *testing.B) {
			b.StopTimer()
			var registry *flow_observation.Registry
			var handle *flow_observation.Handle
			if observed {
				var err error
				registry, err = flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 2, MaxEvents: 4})
				if err != nil {
					b.Fatal(err)
				}
				handle = registry.AdmitUDPAssociation(context.Background(), "", "udp:example.com:53", "")
			}
			inbound, outbound := new(DefaultDispatcher).getLink(context.Background(), handle)
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				for {
					packets, err := outbound.Reader.ReadMultiBuffer()
					buf.ReleaseMulti(packets)
					if err != nil {
						return
					}
				}
			}()
			destination := net.UDPDestination(net.DomainAddress("packet.example"), 5353)
			payload := make([]byte, payloadSize)
			b.SetBytes(payloadSize)
			b.ReportAllocs()
			b.StartTimer()
			for range b.N {
				packet := buf.FromBytes(payload)
				packet.UDP = &destination
				if err := inbound.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			common.Close(inbound.Writer)
			<-drained
			common.Interrupt(inbound.Reader)
			common.Interrupt(outbound.Writer)
			if registry != nil {
				registry.Close()
			}
		})
	}
}

type continuationTestManager struct {
	defaultHandler outbound.Handler
	tagged         map[string]outbound.Handler
}

func (*continuationTestManager) Type() interface{} { return outbound.ManagerType() }
func (*continuationTestManager) Start() error      { return nil }
func (*continuationTestManager) Close() error      { return nil }
func (m *continuationTestManager) GetHandler(tag string) outbound.Handler {
	return m.tagged[tag]
}
func (m *continuationTestManager) GetDefaultHandler() outbound.Handler { return m.defaultHandler }
func (*continuationTestManager) AddHandler(context.Context, outbound.Handler) error {
	return nil
}
func (*continuationTestManager) RemoveHandler(context.Context, string) error { return nil }
func (m *continuationTestManager) ListHandlers(context.Context) []outbound.Handler {
	return []outbound.Handler{m.defaultHandler}
}
