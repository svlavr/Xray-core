package outbound

import (
	"context"
	stderrors "errors"
	"testing"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	internet "github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestClassifyFlowCarrierObservation(t *testing.T) {
	for _, test := range []struct {
		protocol string
		want     flow_observation.CarrierObservation
	}{
		{protocol: "tcp", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofNotApplicable}},
		{protocol: "websocket", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofNotApplicable}},
		{protocol: "httpupgrade", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofNotApplicable}},
		{protocol: "udp", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofUnknown, CarrierF2Required: true}},
		{protocol: "mkcp", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofUnknown, CarrierF2Required: true}},
		{protocol: "hysteria", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofUnknown, CarrierF2Required: true}},
		{protocol: "splithttp", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofUnknown, CarrierF2Required: true}},
		{protocol: "grpc", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofUnknown, CarrierF2Required: true}},
		{protocol: "third-party", want: flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofUnknown}},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			got := classifyFlowCarrierObservation(&internet.MemoryStreamConfig{ProtocolName: test.protocol}, false)
			if got != test.want {
				t.Fatalf("carrier observation for %q: got %+v, want %+v", test.protocol, got, test.want)
			}
		})
	}

	muxObservation := classifyFlowCarrierObservation(&internet.MemoryStreamConfig{ProtocolName: "tcp"}, true)
	if muxObservation.Proof != flow_observation.CarrierProofUnknown || !muxObservation.MuxF2Required {
		t.Fatalf("enabled MUX was not classified as F2-required: %+v", muxObservation)
	}
	detourObservation := classifyFlowCarrierObservation(
		&internet.MemoryStreamConfig{ProtocolName: "tcp", SocketSettings: &internet.SocketConfig{DialerProxy: "dialer"}},
		false,
	)
	if detourObservation.Proof != flow_observation.CarrierProofUnknown || !detourObservation.DialerProxyCarrierUnknown {
		t.Fatalf("dialerProxy carrier was not classified as unknown: %+v", detourObservation)
	}
}

func TestManagerBindsStockCarrierObservationWithoutHandlerCallback(t *testing.T) {
	manager, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	observation := flow_observation.CarrierObservation{Proof: flow_observation.CarrierProofProven}
	handler := &Handler{tag: "carrier-bound", flowCarrier: observation}

	if _, ok := flow_observation.HandlerCarrierObservation(handler); ok {
		t.Fatal("carrier observation was visible before manager admission")
	}
	if err := manager.AddHandler(context.Background(), handler); err != nil {
		t.Fatal(err)
	}
	if got, ok := flow_observation.HandlerCarrierObservation(handler); !ok || got != observation {
		t.Fatalf("manager-bound carrier observation = (%+v, %v), want (%+v, true)", got, ok, observation)
	}
	if err := manager.RemoveHandler(context.Background(), handler.tag); err != nil {
		t.Fatal(err)
	}
	if _, ok := flow_observation.HandlerCarrierObservation(handler); ok {
		t.Fatal("carrier observation remained after handler removal")
	}

	second := &Handler{tag: "carrier-close", flowCarrier: observation}
	if err := manager.AddHandler(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := flow_observation.HandlerCarrierObservation(second); ok {
		t.Fatal("carrier observation remained after manager close")
	}
}

func TestSelectedOutboundMuxBindsWorkerCorrelationAfterSessionAdmission(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 5, MaxSeries: 10, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)

	fromCarrierReader, fromCarrierWriter := pipe.New(pipe.WithoutSizeLimit())
	toCarrierReader, toCarrierWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: fromCarrierReader, Writer: toCarrierWriter}, mux.ClientStrategy{MaxConcurrency: 4, MaxConnection: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		common.Must(worker.Close())
		common.Interrupt(fromCarrierReader)
		common.Close(fromCarrierWriter)
		common.Interrupt(toCarrierReader)
		common.Close(toCarrierWriter)
	})

	handler := &Handler{
		tag: "mux-out",
		mux: &mux.ClientManager{Enabled: true, Picker: staticMuxWorkerPicker{worker: worker}},
	}
	refs := make([]string, 0, 3)
	for index, destination := range []net.Destination{
		net.TCPDestination(net.DomainAddress("first.example"), 443),
		net.TCPDestination(net.DomainAddress("second.example"), 443),
		net.UDPDestination(net.DomainAddress("third.example"), 53),
	} {
		var handle *flow_observation.Handle
		if destination.Network == net.Network_UDP {
			handle = registry.AdmitUDPAssociation(context.Background(), "", destination.String(), "")
		} else {
			handle = registry.AdmitTCP(context.Background(), "", destination.String(), "", flow_observation.ByteScopeLogicalLinkAccepted)
		}
		if handle == nil {
			t.Fatalf("flow %d was not admitted", index)
		}
		handle.SelectRoot("", handler.tag, "handler", destination.String(), "", true, flow_observation.CarrierProofUnknown, flow_observation.IssueMuxCarrierF2Required)
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: destination, Tag: handler.tag}})
		ctx = flow_observation.ContextWithHandle(ctx, handle)
		logicalReader, logicalWriter := pipe.New(pipe.WithoutSizeLimit())
		responseReader, responseWriter := pipe.New(pipe.WithoutSizeLimit())
		handler.Dispatch(ctx, &transport.Link{Reader: logicalReader, Writer: responseWriter})
		common.Close(logicalWriter)
		common.Interrupt(responseReader)

		records := registry.Snapshot().Records
		var record *flow_observation.Record
		for recordIndex := range records {
			if records[recordIndex].FlowID == handle.LogicalRoot().View().FlowID {
				record = &records[recordIndex]
				break
			}
		}
		if record == nil || record.SelectedOutboundCarrierReference == "" || record.CarrierReference != "" {
			t.Fatalf("flow %d missing exact selected-outbound carrier correlation: %+v", index, records)
		}
		refs = append(refs, record.SelectedOutboundCarrierReference)
	}
	if refs[0] != refs[1] || refs[0] != refs[2] {
		t.Fatalf("one ClientWorker produced different TCP/UDP carrier references: %q", refs)
	}

	fullDestination := net.TCPDestination(net.DomainAddress("full.example"), 443)
	fullHandle := registry.AdmitTCP(context.Background(), "", fullDestination.String(), "", flow_observation.ByteScopeLogicalLinkAccepted)
	fullHandle.SelectRoot("", handler.tag, "handler", fullDestination.String(), "", true, flow_observation.CarrierProofUnknown, flow_observation.IssueMuxCarrierF2Required)
	fullCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: fullDestination, Tag: handler.tag}})
	fullCtx = flow_observation.ContextWithHandle(fullCtx, fullHandle)
	fullReader, fullWriter := pipe.New(pipe.WithoutSizeLimit())
	fullResponseReader, fullResponseWriter := pipe.New(pipe.WithoutSizeLimit())
	handler.Dispatch(fullCtx, &transport.Link{Reader: fullReader, Writer: fullResponseWriter})
	common.Close(fullWriter)
	common.Interrupt(fullResponseReader)
	for _, record := range registry.Snapshot().Records {
		if record.FlowID == fullHandle.LogicalRoot().View().FlowID && record.SelectedOutboundCarrierReference != "" {
			t.Fatalf("full worker was attached after failed session allocation: %+v", record)
		}
	}
}

type staticMuxWorkerPicker struct {
	worker *mux.ClientWorker
}

func (p staticMuxWorkerPicker) PickAvailable() (*mux.ClientWorker, error) {
	return p.worker, nil
}

func TestSubmitOutboundErrorPreservesForeignTrackerAndFlowOutcome(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:example.com:443", "", flow_observation.ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "out", "freedom", "tcp:example.com:443", "", true, flow_observation.CarrierProofNotApplicable)
	feedback := new(outboundErrorTestFeedback)
	ctx := session.TrackedConnectionError(context.Background(), feedback)
	ctx = flow_observation.ContextWithHandle(ctx, handle)
	wantErr := stderrors.New("outbound failed")

	submitOutboundError(ctx, wantErr)
	if feedback.calls != 1 || feedback.err != wantErr {
		t.Fatalf("foreign error feedback = (%d, %v), want (1, %v)", feedback.calls, feedback.err, wantErr)
	}
	handle.HandlerReturned(context.Background(), "tcp:example.com:443")
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	record := registry.Snapshot().Records[0]
	if record.CompletionState != flow_observation.CompletionTerminal || record.TerminalClass != flow_observation.TerminalClassLocalError || record.TechnicalErrorCategory != "OUTBOUND_ERROR" {
		t.Fatalf("flow outcome did not retain outbound error: %+v", record)
	}
}

type outboundErrorTestFeedback struct {
	calls int
	err   error
}

func (f *outboundErrorTestFeedback) SubmitError(err error) {
	f.calls++
	f.err = err
}
