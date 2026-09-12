package mux_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	feature_outbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

func TestServerMuxCarrierRecordsEncodedLinkIOWithoutChangingLogicalBytes(t *testing.T) {
	handlerResult := make(chan error, 1)
	handler := &muxFlowHandler{tag: "mux-carrier-out"}
	handler.dispatch = func(_ context.Context, link *transport.Link) {
		request, err := link.Reader.ReadMultiBuffer()
		if err == nil && request.String() != "hello" {
			err = errors.New("decoded request changed")
		}
		buf.ReleaseMulti(request)
		if err == nil {
			err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("world"))})
		}
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		handlerResult <- err
	}
	dispatcherInstance := new(dispatcher.DefaultDispatcher)
	if err := dispatcherInstance.Init(new(dispatcher.Config), &muxFlowManager{handler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcherInstance.Close()
	baseServerLink, peerLink := newLinkPair()
	readCounter := &carrierCountingReader{Reader: baseServerLink.Reader}
	writeCounter := &carrierCountingWriter{Writer: baseServerLink.Writer}
	worker, err := mux.NewServerWorker(context.Background(), dispatcherInstance, &transport.Link{Reader: readCounter, Writer: writeCounter})
	if err != nil {
		t.Fatal(err)
	}
	request := mux.NewWriter(41, net.TCPDestination(net.DomainAddress("logical.carrier.example"), 443), peerLink.Writer, protocol.TransferTypeStream, [8]byte{}, nil)
	if err := request.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	responseReader := &buf.BufferedReader{Reader: peerLink.Reader}
	responseMeta := readMuxFrameMetadata(t, responseReader)
	if responseMeta.SessionID != 41 || responseMeta.SessionStatus != mux.SessionStatusKeep || !responseMeta.Option.Has(mux.OptionData) {
		t.Fatalf("unexpected response metadata: %+v", responseMeta)
	}
	response, err := mux.NewStreamReader(responseReader).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := response.String(); got != "world" {
		buf.ReleaseMulti(response)
		t.Fatalf("decoded response = %q, want world", got)
	}
	buf.ReleaseMulti(response)
	if err := <-handlerResult; err != nil {
		t.Fatal(err)
	}
	request.Close()
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := waitMuxCarrierTerminal(t, dispatcherInstance.FlowObserver())
	if len(snapshot.Records) != 1 {
		t.Fatalf("logical records = %d, want 1", len(snapshot.Records))
	}
	uplink := muxFlowObservation(t, snapshot.Records[0], flow_observation.DirectionUplink)
	downlink := muxFlowObservation(t, snapshot.Records[0], flow_observation.DirectionDownlink)
	if uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 5}) ||
		downlink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 5}) {
		t.Fatalf("carrier accounting changed logical payload totals: %+v", snapshot.Records[0].ByteObservations)
	}
	carrier := snapshot.CarrierRecords[0]
	carrierUp := muxCarrierObservation(t, carrier, flow_observation.DirectionUplink)
	carrierDown := muxCarrierObservation(t, carrier, flow_observation.DirectionDownlink)
	if carrierUp.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: readCounter.bytes.Load()}) ||
		carrierDown.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: writeCounter.bytes.Load()}) {
		t.Fatalf("encoded carrier bytes do not match exact link I/O: record=%+v read=%d write=%d", carrier.ByteObservations, readCounter.bytes.Load(), writeCounter.bytes.Load())
	}
	if carrierUp.ObservedBytes.Value <= uplink.ObservedBytes.Value || carrierDown.ObservedBytes.Value <= downlink.ObservedBytes.Value {
		t.Fatalf("carrier framing/control bytes were not kept separate: carrier=%+v logical=%+v", carrier.ByteObservations, snapshot.Records[0].ByteObservations)
	}
}

func TestServerMuxCarrierBlockedReaderShutdownCompletesFence(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 4, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	d := &muxPacketFlowDispatcher{registry: registry}
	serverLink, peerLink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), d, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	var closes sync.WaitGroup
	for i := 0; i < 8; i++ {
		closes.Add(1)
		go func() {
			defer closes.Done()
			_ = worker.Close()
		}()
	}
	closes.Wait()
	snapshot := waitMuxCarrierTerminal(t, registry)
	if len(snapshot.Records) != 0 || snapshot.CarrierRecords[0].ActivityState != flow_observation.ActivityAdmitted {
		t.Fatalf("blocked-reader shutdown fabricated traffic: %+v", snapshot)
	}
	common.Interrupt(peerLink.Reader)
	common.Interrupt(peerLink.Writer)
}

func TestServerMuxCarrierBlockedResponseWriteFencesHandlerAndMarksDownlinkOnly(t *testing.T) {
	errBlocked := errors.New("blocked response write")
	blocked := newCarrierBlockedWriter(errBlocked)
	handlerResult := make(chan error, 1)
	handler := &muxFlowHandler{tag: "mux-blocked-out"}
	handler.dispatch = func(_ context.Context, link *transport.Link) {
		request, err := link.Reader.ReadMultiBuffer()
		buf.ReleaseMulti(request)
		if err == nil {
			err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))})
		}
		handlerResult <- err
	}
	dispatcherInstance := new(dispatcher.DefaultDispatcher)
	if err := dispatcherInstance.Init(new(dispatcher.Config), &muxFlowManager{handler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcherInstance.Close()
	serverLink, peerLink := newLinkPair()
	serverLink.Writer = blocked
	worker, err := mux.NewServerWorker(context.Background(), dispatcherInstance, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	request := mux.NewWriter(42, net.TCPDestination(net.DomainAddress("blocked.carrier.example"), 443), peerLink.Writer, protocol.TransferTypeStream, [8]byte{}, nil)
	if err := request.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("response handler did not reach blocked carrier writer")
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.interrupted:
	case <-time.After(time.Second):
		t.Fatal("server monitor did not preserve writer interruption")
	}
	if snapshot := dispatcherInstance.FlowObserver().Snapshot(); len(snapshot.CarrierRecords) != 1 || snapshot.CarrierRecords[0].CompletionState == flow_observation.CompletionTerminal {
		t.Fatalf("carrier terminalized while response handler was blocked: %+v", snapshot.CarrierRecords)
	}
	close(blocked.release)
	select {
	case err := <-handlerResult:
		if err != nil {
			t.Fatalf("outbound handler result changed by carrier failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked response handler did not exit")
	}
	snapshot := waitMuxCarrierTerminal(t, dispatcherInstance.FlowObserver())
	carrierUp := muxCarrierObservation(t, snapshot.CarrierRecords[0], flow_observation.DirectionUplink)
	carrierDown := muxCarrierObservation(t, snapshot.CarrierRecords[0], flow_observation.DirectionDownlink)
	if carrierUp.State != flow_observation.ByteObservationStateProven || !carrierUp.ObservedBytes.Known ||
		carrierDown.State != flow_observation.ByteObservationStateIndeterminate || carrierDown.ObservedBytes.Known {
		t.Fatalf("write error did not stay downlink-only: %+v", snapshot.CarrierRecords[0].ByteObservations)
	}
}

func TestServerMuxCarrierMalformedEOFClosesTwoSiblingsBeforeTerminal(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	owners := make(chan *transport.Link, 2)
	d := &muxPacketFlowDispatcher{registry: registry}
	d.OnDispatch = func(context.Context, net.Destination) (*transport.Link, error) {
		owner, child := newLinkPair()
		owners <- owner
		return child, nil
	}
	serverLink, peerLink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), d, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	for id := uint16(1); id <= 2; id++ {
		writer := mux.NewWriter(id, net.TCPDestination(net.DomainAddress("sibling.example"), 443), peerLink.Writer, protocol.TransferTypeStream, [8]byte{}, nil)
		if err := writer.WriteMultiBuffer(nil); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for worker.ActiveConnections() != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("active siblings = %d, want 2", worker.ActiveConnections())
		}
		time.Sleep(time.Millisecond)
	}
	common.Interrupt(peerLink.Writer)
	snapshot := waitMuxCarrierTerminal(t, registry)
	if worker.ActiveConnections() != 0 || snapshot.CarrierRecords[0].CompletionState != flow_observation.CompletionTerminal {
		t.Fatalf("carrier terminal preceded sibling teardown: active=%d carrier=%+v", worker.ActiveConnections(), snapshot.CarrierRecords[0])
	}
	close(owners)
	for owner := range owners {
		common.Interrupt(owner.Reader)
		common.Interrupt(owner.Writer)
	}
}

func TestServerMuxCarrierFencesSixtyFourRealSiblingWriters(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 128, MaxSeries: 8, MaxEvents: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	const siblings = 64
	owners := make(chan *transport.Link, siblings)
	d := &muxPacketFlowDispatcher{registry: registry}
	d.OnDispatch = func(context.Context, net.Destination) (*transport.Link, error) {
		owner, child := newLinkPair()
		owners <- owner
		return child, nil
	}
	serverLink, peerLink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), d, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			mb, err := peerLink.Reader.ReadMultiBuffer()
			buf.ReleaseMulti(mb)
			if err != nil {
				return
			}
		}
	}()
	for id := uint16(1); id <= siblings; id++ {
		writer := mux.NewWriter(id, net.TCPDestination(net.DomainAddress("many-siblings.example"), 443), peerLink.Writer, protocol.TransferTypeStream, [8]byte{}, nil)
		if err := writer.WriteMultiBuffer(nil); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for worker.ActiveConnections() != siblings {
		if time.Now().After(deadline) {
			t.Fatalf("active siblings = %d, want %d", worker.ActiveConnections(), siblings)
		}
		time.Sleep(time.Millisecond)
	}
	links := make([]*transport.Link, 0, siblings)
	for i := 0; i < siblings; i++ {
		links = append(links, <-owners)
	}
	var writers sync.WaitGroup
	for _, owner := range links {
		owner := owner
		writers.Add(1)
		go func() {
			defer writers.Done()
			_ = owner.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("x"))})
			common.Close(owner.Writer)
			common.Interrupt(owner.Reader)
		}()
	}
	writers.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for worker.ActiveConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("sibling writers did not quiesce: active=%d", worker.ActiveConnections())
		}
		time.Sleep(time.Millisecond)
	}
	common.Interrupt(peerLink.Writer)
	snapshot := waitMuxCarrierTerminal(t, registry)
	downlink := muxCarrierObservation(t, snapshot.CarrierRecords[0], flow_observation.DirectionDownlink)
	if downlink.State != flow_observation.ByteObservationStateProven || !downlink.ObservedBytes.Known || downlink.ObservedBytes.Value == 0 {
		t.Fatalf("real sibling frame writes were not observed: %+v", downlink)
	}
	common.Interrupt(peerLink.Reader)
	select {
	case <-drainDone:
	case <-time.After(time.Second):
		t.Fatal("response drain did not stop")
	}
}

func TestServerDecodedMuxTCPPublishesPresenceOnlyFlow(t *testing.T) {
	handlerResult := make(chan error, 1)
	handler := &muxFlowHandler{tag: "mux-flow-out"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		handle := flow_observation.HandleFromContext(ctx)
		if handle == nil {
			handlerResult <- errors.New("decoded MUX handler has no flow handle")
			return
		}
		if inbound := session.InboundFromContext(ctx); inbound == nil || inbound.CanSpliceCopy != 3 {
			handlerResult <- errors.New("decoded MUX handler lost the stock direct/splice exclusion")
			return
		}
		request, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			handlerResult <- err
			return
		}
		if got := request.String(); got != "hello" {
			buf.ReleaseMulti(request)
			handlerResult <- errors.New("decoded MUX request changed")
			return
		}
		buf.ReleaseMulti(request)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("world"))}); err != nil {
			handlerResult <- err
			return
		}
		closeErr := common.Close(link.Writer)
		common.Interrupt(link.Reader)
		handlerResult <- closeErr
	}

	dispatcherInstance := new(dispatcher.DefaultDispatcher)
	manager := &muxFlowManager{handler: handler}
	if err := dispatcherInstance.Init(new(dispatcher.Config), manager, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcherInstance.Close()

	serverCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.DomainAddress("physical-carrier.example"), 1234),
		User:   new(protocol.MemoryUser),
	})
	serverCtx, err := flow_observation.WithUserAdmission(serverCtx, flow_observation.Admission{Coordinate: []byte("carrier-only")})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx = session.ContextWithOutbounds(serverCtx, []*session.Outbound{{}})
	muxServerLink, muxClientLink := newLinkPair()
	serverWorker, err := mux.NewServerWorker(serverCtx, dispatcherInstance, muxServerLink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = serverWorker.Close()
		<-serverWorker.WaitClosed()
	}()
	clientWorker, err := mux.NewClientWorker(*muxClientLink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = clientWorker.Close()
		<-clientWorker.WaitClosed()
	}()

	clientInbound, clientOutbound := newLinkPair()
	defer common.Interrupt(clientInbound.Reader)
	defer common.Interrupt(clientInbound.Writer)
	defer common.Interrupt(clientOutbound.Reader)
	defer common.Interrupt(clientOutbound.Writer)
	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("logical.example"), 443),
	}})
	if !clientWorker.Dispatch(clientCtx, clientInbound) {
		t.Fatal("client MUX worker rejected logical TCP session")
	}
	if err := clientOutbound.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	response, err := clientOutbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := response.String(); got != "world" {
		buf.ReleaseMulti(response)
		t.Fatalf("decoded MUX response = %q, want world", got)
	}
	buf.ReleaseMulti(response)
	if err := <-handlerResult; err != nil {
		t.Fatal(err)
	}
	if err := common.Close(clientOutbound.Writer); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		snapshot := dispatcherInstance.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			if record.FlowKind != flow_observation.KindMUXLogical || record.CarrierReference == "" ||
				record.Source != "" || record.TrafficOrigin != "" || record.OriginProof != "" ||
				record.AdmissionCoordinate.Known ||
				record.CarrierProof != "" || record.Route.SelectedTopLevelOutboundTag != "mux-flow-out" ||
				record.TerminalClass != "" || record.TechnicalErrorCategory != "" ||
				record.CompletionEvidence != flow_observation.CompletionEvidenceProvenLogicalSessionClosed {
				t.Fatalf("decoded MUX record violates presence-only contract: %+v", record)
			}
			uplink := muxFlowObservation(t, record, flow_observation.DirectionUplink)
			downlink := muxFlowObservation(t, record, flow_observation.DirectionDownlink)
			if uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 5}) ||
				downlink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 5}) || len(record.ByteObservations) != 2 {
				t.Fatalf("decoded MUX bytes were not counted exactly once: uplink=%+v downlink=%+v", uplink, downlink)
			}
			if len(snapshot.CounterSeries) != 2 {
				t.Fatalf("decoded MUX created a duplicate accounting series: %+v", snapshot.CounterSeries)
			}
			for _, series := range snapshot.CounterSeries {
				if series.Key.ByteScope != flow_observation.ByteScopeLogicalLinkAccepted ||
					series.CumulativeBytes != (flow_observation.OptionalUint64{Known: true, Value: 5}) ||
					series.ActiveFlowCount != (flow_observation.OptionalUint64{Known: true, Value: 0}) {
					t.Fatalf("decoded MUX series is not canonical: %+v", series)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("decoded MUX flow did not terminalize: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServerDecodedZeroGlobalIDUDPCreatesMuxLogicalScope(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	dispatched := make(chan struct{})
	websiteInbound, websiteOutbound := newLinkPair()
	defer common.Interrupt(websiteInbound.Reader)
	defer common.Interrupt(websiteInbound.Writer)
	defer common.Interrupt(websiteOutbound.Reader)
	defer common.Interrupt(websiteOutbound.Writer)
	dispatcher := &muxPacketFlowDispatcher{
		TestDispatcher: TestDispatcher{OnDispatch: func(ctx context.Context, destination net.Destination) (*transport.Link, error) {
			scope := flow_observation.MuxSessionScopeFromContext(ctx)
			if destination.Network != net.Network_UDP || scope == nil || !session.IsMultiplexedLogicalSession(ctx) {
				return nil, errors.New("zero-ID UDP MUX path did not receive its logical observation scope")
			}
			if registry.AdmitMuxUDP(scope, destination) == nil {
				return nil, errors.New("zero-ID UDP MUX scope was not admitted")
			}
			close(dispatched)
			return websiteOutbound, nil
		}},
		registry: registry,
	}
	serverCtx := session.ContextWithInbound(context.Background(), &session.Inbound{User: new(protocol.MemoryUser)})
	serverCtx = session.ContextWithOutbounds(serverCtx, []*session.Outbound{{}})
	muxServerLink, muxClientLink := newLinkPair()
	serverWorker, err := mux.NewServerWorker(serverCtx, dispatcher, muxServerLink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = serverWorker.Close()
		<-serverWorker.WaitClosed()
	}()
	clientWorker, err := mux.NewClientWorker(*muxClientLink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = clientWorker.Close()
		<-clientWorker.WaitClosed()
	}()
	clientInbound, clientOutbound := newLinkPair()
	defer common.Interrupt(clientInbound.Reader)
	defer common.Interrupt(clientInbound.Writer)
	defer common.Interrupt(clientOutbound.Reader)
	defer common.Interrupt(clientOutbound.Writer)
	destination := net.UDPDestination(net.DomainAddress("packet.example"), 53)
	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: destination}})
	if !clientWorker.Dispatch(clientCtx, clientInbound) {
		t.Fatal("client MUX worker rejected ordinary UDP session")
	}
	packet := buf.FromBytes([]byte("packet"))
	packet.UDP = &destination
	if err := clientOutbound.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("ordinary UDP MUX frame did not preserve stock dispatch")
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].FlowKind != flow_observation.KindMUXLogical ||
		snapshot.Records[0].OriginalDestination != destination.String() || snapshot.Records[0].CarrierReference == "" {
		t.Fatalf("ordinary zero-ID UDP MUX frame did not create one logical record: %+v", snapshot)
	}
}

func TestServerDecodedZeroGlobalIDUDPDefaultDispatcherPreservesFirstRouteAndPackets(t *testing.T) {
	first := net.UDPDestination(net.DomainAddress("first.packet.example"), 53)
	second := net.UDPDestination(net.DomainAddress("second.packet.example"), 5353)
	handlerResult := make(chan error, 1)
	handler := &muxFlowHandler{tag: "mux-udp-flow-out"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		if flow_observation.HandleFromContext(ctx) == nil {
			handlerResult <- errors.New("decoded MUX UDP handler has no flow handle")
			return
		}
		wants := []net.Destination{first, second}
		for index := 0; index < len(wants); {
			packets, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				handlerResult <- err
				return
			}
			for _, packet := range packets {
				if index == len(wants) || packet.String() != string([]byte{'a' + byte(index)}) || packet.UDP == nil || packet.UDP.String() != wants[index].String() {
					buf.ReleaseMulti(packets)
					handlerResult <- errors.New("decoded MUX UDP packet target or payload changed")
					return
				}
				index++
			}
			buf.ReleaseMulti(packets)
		}
		common.Interrupt(link.Reader)
		response := buf.FromBytes([]byte("z"))
		response.UDP = &first
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{response}); err != nil {
			handlerResult <- err
			return
		}
		handlerResult <- common.Close(link.Writer)
	}
	dispatcherInstance := new(dispatcher.DefaultDispatcher)
	if err := dispatcherInstance.Init(new(dispatcher.Config), &muxFlowManager{handler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcherInstance.Close()

	serverCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.DomainAddress("physical-carrier.example"), 1234),
		User:   new(protocol.MemoryUser),
	})
	serverCtx = session.ContextWithOutbounds(serverCtx, []*session.Outbound{{}})
	muxServerLink, muxClientLink := newLinkPair()
	serverWorker, err := mux.NewServerWorker(serverCtx, dispatcherInstance, muxServerLink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverWorker.Close(); <-serverWorker.WaitClosed() }()
	clientWorker, err := mux.NewClientWorker(*muxClientLink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientWorker.Close(); <-clientWorker.WaitClosed() }()
	clientInbound, clientOutbound := newLinkPair()
	defer common.Interrupt(clientInbound.Reader)
	defer common.Interrupt(clientInbound.Writer)
	defer common.Interrupt(clientOutbound.Reader)
	defer common.Interrupt(clientOutbound.Writer)
	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: first}})
	if !clientWorker.Dispatch(clientCtx, clientInbound) {
		t.Fatal("client MUX worker rejected UDP session")
	}
	for index, destination := range []net.Destination{first, second} {
		packet := buf.FromBytes([]byte{'a' + byte(index)})
		packet.UDP = &destination
		if err := clientOutbound.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
	}
	reply, err := clientOutbound.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 1 || reply.String() != "z" {
		buf.ReleaseMulti(reply)
		t.Fatal("decoded MUX UDP reply payload changed")
	}
	buf.ReleaseMulti(reply)
	if err := <-handlerResult; err != nil {
		t.Fatal(err)
	}
	if err := common.Close(clientOutbound.Writer); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		snapshot := dispatcherInstance.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			if record.FlowKind != flow_observation.KindMUXLogical || record.OriginalDestination != first.String() ||
				record.Route.SelectedTopLevelOutboundTag != "mux-udp-flow-out" || record.CarrierReference == "" ||
				record.Source != "" || record.TrafficOrigin != "" || record.OriginProof != "" || record.AdmissionCoordinate.Known ||
				record.TerminalClass != "" || record.TechnicalErrorCategory != "" {
				t.Fatalf("decoded MUX UDP record changed identity or presence-only facts: %+v", record)
			}
			uplink := muxFlowObservation(t, record, flow_observation.DirectionUplink)
			downlink := muxFlowObservation(t, record, flow_observation.DirectionDownlink)
			if uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 2}) ||
				downlink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 1}) || len(snapshot.CounterSeries) != 2 {
				t.Fatalf("decoded MUX UDP payload bytes were not exact: %+v", snapshot)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("decoded MUX UDP record did not terminalize: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServerMissingMuxUDPKeepDiscardsPayloadWithoutAdmission(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	dispatcher := &muxPacketFlowDispatcher{
		TestDispatcher: TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
			return nil, errors.New("missing Keep unexpectedly dispatched")
		}},
		registry: registry,
	}
	serverLink, peerLink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close(); <-worker.WaitClosed() }()

	destination := net.UDPDestination(net.DomainAddress("missing.packet.example"), 53)
	keep := mux.NewResponseWriter(77, peerLink.Writer, protocol.TransferTypePacket)
	packet := buf.FromBytes([]byte("discarded"))
	packet.UDP = &destination
	if err := keep.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	responseReader := &buf.BufferedReader{Reader: peerLink.Reader}
	response := readMuxFrameMetadata(t, responseReader)
	if response.SessionID != 77 || response.SessionStatus != mux.SessionStatusEnd || response.Option != 0 {
		t.Fatalf("missing Keep response changed: %+v", response)
	}
	probe := mux.NewResponseWriter(78, peerLink.Writer, protocol.TransferTypePacket)
	probePacket := buf.FromBytes([]byte("probe"))
	probePacket.UDP = &destination
	if err := probe.WriteMultiBuffer(buf.MultiBuffer{probePacket}); err != nil {
		t.Fatal(err)
	}
	probeResponse := readMuxFrameMetadata(t, responseReader)
	if probeResponse.SessionID != 78 || probeResponse.SessionStatus != mux.SessionStatusEnd || probeResponse.Option != 0 {
		t.Fatalf("post-discard missing Keep response changed: %+v", probeResponse)
	}
	if worker.Closed() {
		t.Fatal("missing Keep closed the MUX carrier")
	}
	if snapshot := registry.Snapshot(); len(snapshot.Records) != 0 || snapshot.AccountingCoverage.State != flow_observation.AccountingCoverageComplete {
		t.Fatalf("missing Keep created observation state: %+v", snapshot)
	}
}

func TestServerMuxUDPEndOptionDataIsDiscardedOutsideLogicalBytes(t *testing.T) {
	destination := net.UDPDestination(net.DomainAddress("end.packet.example"), 53)
	handlerResult := make(chan error, 1)
	handler := &muxFlowHandler{tag: "mux-udp-end-out"}
	handler.dispatch = func(_ context.Context, link *transport.Link) {
		packets, err := link.Reader.ReadMultiBuffer()
		if err == nil {
			if packets.String() != "x" {
				err = errors.New("decoded MUX UDP request changed")
			}
			buf.ReleaseMulti(packets)
		}
		if err == nil {
			_, closeErr := link.Reader.ReadMultiBuffer()
			if closeErr == nil {
				err = errors.New("End did not close decoded MUX UDP input")
			} else {
				err = nil
			}
		}
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		handlerResult <- err
	}
	dispatcherInstance := new(dispatcher.DefaultDispatcher)
	if err := dispatcherInstance.Init(new(dispatcher.Config), &muxFlowManager{handler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcherInstance.Close()
	serverLink, peerLink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), dispatcherInstance, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close(); <-worker.WaitClosed() }()

	request := mux.NewWriter(91, destination, peerLink.Writer, protocol.TransferTypePacket, [8]byte{}, nil)
	packet := buf.FromBytes([]byte("x"))
	packet.UDP = &destination
	if err := request.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	end := buf.New()
	endMeta := mux.FrameMetadata{SessionID: 91, SessionStatus: mux.SessionStatusEnd, Option: mux.OptionData}
	if err := endMeta.WriteTo(end); err != nil {
		end.Release()
		t.Fatal(err)
	}
	ignored := []byte("not-logical-payload")
	if _, err := serial.WriteUint16(end, uint16(len(ignored))); err != nil {
		end.Release()
		t.Fatal(err)
	}
	if err := peerLink.Writer.WriteMultiBuffer(buf.MultiBuffer{end, buf.FromBytes(ignored)}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-handlerResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("MUX UDP End handler did not complete")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		snapshot := dispatcherInstance.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			uplink := muxFlowObservation(t, record, flow_observation.DirectionUplink)
			downlink := muxFlowObservation(t, record, flow_observation.DirectionDownlink)
			if uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: 1}) ||
				downlink.ObservedBytes != (flow_observation.OptionalUint64{Known: true}) {
				t.Fatalf("End option-data entered logical byte cells: %+v", record.ByteObservations)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("MUX UDP End option-data flow did not terminalize: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServerDuplicateMuxUDPSessionIDClosesCarrierWithoutLeakingSessions(t *testing.T) {
	links := make([]*transport.Link, 0, 2)
	dispatched := make(chan struct{}, 2)
	dispatcher := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		owner, child := newLinkPair()
		links = append(links, owner)
		dispatched <- struct{}{}
		return child, nil
	}}
	serverLink, peerLink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = worker.Close()
		<-worker.WaitClosed()
		for _, link := range links {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
	}()
	destination := net.UDPDestination(net.DomainAddress("duplicate.packet.example"), 53)
	first := mux.NewWriter(12, destination, peerLink.Writer, protocol.TransferTypePacket, [8]byte{}, nil)
	firstPacket := buf.FromBytes([]byte("a"))
	firstPacket.UDP = &destination
	if err := first.WriteMultiBuffer(buf.MultiBuffer{firstPacket}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("first duplicate-ID session was not dispatched")
	}
	deadline := time.Now().Add(time.Second)
	for worker.ActiveConnections() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("first decoded session was not retained: active=%d", worker.ActiveConnections())
		}
		time.Sleep(time.Millisecond)
	}
	duplicate := mux.NewWriter(12, destination, peerLink.Writer, protocol.TransferTypePacket, [8]byte{}, nil)
	duplicatePacket := buf.FromBytes([]byte("b"))
	duplicatePacket.UDP = &destination
	if err := duplicate.WriteMultiBuffer(buf.MultiBuffer{duplicatePacket}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("second duplicate-ID session was not dispatched")
	}
	select {
	case <-worker.WaitClosed():
	case <-time.After(time.Second):
		t.Fatal("duplicate MUX session ID did not close the malformed carrier")
	}
	deadline = time.Now().Add(time.Second)
	for worker.ActiveConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("carrier teardown leaked %d decoded sessions", worker.ActiveConnections())
		}
		time.Sleep(time.Millisecond)
	}
}

func readMuxFrameMetadata(t testing.TB, reader *buf.BufferedReader) mux.FrameMetadata {
	t.Helper()
	type result struct {
		meta mux.FrameMetadata
		err  error
	}
	results := make(chan result, 1)
	go func() {
		var meta mux.FrameMetadata
		err := meta.Unmarshal(reader, false)
		results <- result{meta: meta, err: err}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.meta
	case <-time.After(time.Second):
		t.Fatal("timed out reading MUX frame metadata")
		return mux.FrameMetadata{}
	}
}

func muxFlowObservation(t testing.TB, record flow_observation.Record, direction flow_observation.Direction) flow_observation.ByteObservation {
	t.Helper()
	for _, observation := range record.ByteObservations {
		if observation.Direction == direction && observation.ByteScope == flow_observation.ByteScopeLogicalLinkAccepted {
			return observation
		}
	}
	t.Fatalf("missing MUX logical observation %s in %+v", direction, record.ByteObservations)
	return flow_observation.ByteObservation{}
}

func muxCarrierObservation(t testing.TB, record flow_observation.CarrierRecord, direction flow_observation.Direction) flow_observation.ByteObservation {
	t.Helper()
	for _, observation := range record.ByteObservations {
		if observation.Direction == direction && observation.ByteScope == flow_observation.ByteScopeCarrierConnectionIO {
			return observation
		}
	}
	t.Fatalf("missing %s carrier observation in %+v", direction, record.ByteObservations)
	return flow_observation.ByteObservation{}
}

func waitMuxCarrierTerminal(t testing.TB, observer flow_observation.Observer) flow_observation.Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		snapshot := observer.Snapshot()
		if len(snapshot.CarrierRecords) == 1 && snapshot.CarrierRecords[0].CompletionState == flow_observation.CompletionTerminal {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatalf("server MUX carrier did not terminalize: %+v", snapshot.CarrierRecords)
		}
		time.Sleep(time.Millisecond)
	}
}

type carrierCountingReader struct {
	buf.Reader
	bytes atomic.Uint64
}

func (r *carrierCountingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	r.bytes.Add(uint64(mb.Len()))
	return mb, err
}

func (r *carrierCountingReader) Interrupt() { common.Interrupt(r.Reader) }
func (r *carrierCountingReader) Close() error {
	return common.Close(r.Reader)
}

type carrierCountingWriter struct {
	buf.Writer
	bytes atomic.Uint64
}

func (w *carrierCountingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := uint64(mb.Len())
	err := w.Writer.WriteMultiBuffer(mb)
	if err == nil {
		w.bytes.Add(n)
	}
	return err
}

func (w *carrierCountingWriter) Interrupt() { common.Interrupt(w.Writer) }
func (w *carrierCountingWriter) Close() error {
	return common.Close(w.Writer)
}

type carrierBlockedWriter struct {
	err         error
	entered     chan struct{}
	interrupted chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	stopOnce    sync.Once
}

func newCarrierBlockedWriter(err error) *carrierBlockedWriter {
	return &carrierBlockedWriter{err: err, entered: make(chan struct{}), interrupted: make(chan struct{}), release: make(chan struct{})}
}

func (w *carrierBlockedWriter) WriteMultiBuffer(buf.MultiBuffer) error {
	w.enterOnce.Do(func() { close(w.entered) })
	<-w.release
	return w.err
}

func (w *carrierBlockedWriter) Interrupt() { w.stopOnce.Do(func() { close(w.interrupted) }) }
func (w *carrierBlockedWriter) Close() error {
	w.Interrupt()
	return nil
}

type muxFlowHandler struct {
	tag      string
	dispatch func(context.Context, *transport.Link)
}

func (*muxFlowHandler) Type() interface{}                                    { return (*muxFlowHandler)(nil) }
func (*muxFlowHandler) Start() error                                         { return nil }
func (*muxFlowHandler) Close() error                                         { return nil }
func (h *muxFlowHandler) Tag() string                                        { return h.tag }
func (*muxFlowHandler) SenderSettings() *serial.TypedMessage                 { return nil }
func (*muxFlowHandler) ProxySettings() *serial.TypedMessage                  { return nil }
func (h *muxFlowHandler) Dispatch(ctx context.Context, link *transport.Link) { h.dispatch(ctx, link) }

type muxFlowManager struct{ handler feature_outbound.Handler }

func (*muxFlowManager) Type() interface{}                                          { return feature_outbound.ManagerType() }
func (*muxFlowManager) Start() error                                               { return nil }
func (*muxFlowManager) Close() error                                               { return nil }
func (m *muxFlowManager) GetHandler(string) feature_outbound.Handler               { return nil }
func (m *muxFlowManager) GetDefaultHandler() feature_outbound.Handler              { return m.handler }
func (*muxFlowManager) AddHandler(context.Context, feature_outbound.Handler) error { return nil }
func (*muxFlowManager) RemoveHandler(context.Context, string) error                { return nil }
func (m *muxFlowManager) ListHandlers(context.Context) []feature_outbound.Handler {
	return []feature_outbound.Handler{m.handler}
}

type muxPacketFlowDispatcher struct {
	TestDispatcher
	registry *flow_observation.Registry
}

func (d *muxPacketFlowDispatcher) NewMuxCarrierObservation() session.MuxCarrierObservation {
	if d == nil || d.registry == nil {
		return nil
	}
	carrier := d.registry.NewMuxCarrierObservation()
	if carrier == nil {
		return nil
	}
	return carrier
}
