package trojan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	feature_outbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

func TestTrojanUDPUsesOneObservedStockAssociation(t *testing.T) {
	destination := net.UDPDestination(net.DomainAddress("trojan.example"), 53)
	handlerResult := make(chan error, 1)
	handler := &trojanFlowHandler{tag: "udp-out"}
	handler.dispatch = func(ctx context.Context, link *transport.Link) {
		handle := flow_observation.HandleFromContext(ctx)
		if handle == nil {
			handlerResult <- errors.New("Trojan UDP handler received no association root")
			return
		}
		request, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			handlerResult <- err
			return
		}
		if request.String() != "request" || len(request) != 1 || request[0].UDP == nil || *request[0].UDP != destination {
			buf.ReleaseMulti(request)
			handlerResult <- errors.New("Trojan UDP request changed")
			return
		}
		buf.ReleaseMulti(request)
		response := buf.FromBytes([]byte("reply"))
		responseDestination := destination
		response.UDP = &responseDestination
		err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{response})
		if err == nil {
			err = common.Close(link.Writer)
		}
		common.Interrupt(link.Reader)
		handlerResult <- err
	}
	dispatcherInstance := new(dispatcher.DefaultDispatcher)
	if err := dispatcherInstance.Init(new(dispatcher.Config), &trojanFlowManager{handler: handler}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer dispatcherInstance.Close()

	server := &Server{cone: true}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.UDPDestination(net.LocalHostIP, 1234),
		User:   new(protocol.MemoryUser),
	})
	ctx, err := flow_observation.WithUserAdmission(ctx, flow_observation.Admission{Coordinate: []byte("trojan-udp")})
	if err != nil {
		t.Fatal(err)
	}
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()
	defer inputWriter.Close()
	output := newTrojanFlowWriter()
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.handleUDPPayload(
			ctx,
			policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Second}},
			&PacketReader{Reader: inputReader},
			&PacketWriter{Writer: output},
			dispatcherInstance,
		)
	}()
	request := buf.FromBytes([]byte("request"))
	requestDestination := destination
	request.UDP = &requestDestination
	if err := (&PacketWriter{Writer: inputWriter}).WriteMultiBuffer(buf.MultiBuffer{request}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-output.wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Trojan UDP response")
	}
	if err := <-handlerResult; err != nil {
		t.Fatal(err)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
	response, err := (&PacketReader{Reader: bytes.NewReader(output.Bytes())}).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if response.String() != "reply" || len(response) != 1 || response[0].UDP == nil || *response[0].UDP != destination {
		buf.ReleaseMulti(response)
		t.Fatalf("Trojan UDP response changed: %+v", response)
	}
	buf.ReleaseMulti(response)

	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := dispatcherInstance.FlowObserver().Snapshot()
		if len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal {
			record := snapshot.Records[0]
			if record.FlowKind != flow_observation.KindUDPAssociation || record.TrafficOrigin != flow_observation.OriginUser ||
				record.OriginalDestination != destination.String() || record.EffectiveDestination != destination.String() ||
				record.Route.SelectedTopLevelOutboundTag != "udp-out" {
				t.Fatalf("Trojan UDP association facts changed: %+v", record)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Trojan UDP association did not terminalize: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

type trojanFlowHandler struct {
	tag      string
	dispatch func(context.Context, *transport.Link)
}

func (*trojanFlowHandler) Type() interface{}                    { return (*trojanFlowHandler)(nil) }
func (*trojanFlowHandler) Start() error                         { return nil }
func (*trojanFlowHandler) Close() error                         { return nil }
func (h *trojanFlowHandler) Tag() string                        { return h.tag }
func (*trojanFlowHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*trojanFlowHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *trojanFlowHandler) Dispatch(ctx context.Context, link *transport.Link) {
	h.dispatch(ctx, link)
}

type trojanFlowManager struct{ handler feature_outbound.Handler }

func (*trojanFlowManager) Type() interface{}                                          { return feature_outbound.ManagerType() }
func (*trojanFlowManager) Start() error                                               { return nil }
func (*trojanFlowManager) Close() error                                               { return nil }
func (*trojanFlowManager) GetHandler(string) feature_outbound.Handler                 { return nil }
func (m *trojanFlowManager) GetDefaultHandler() feature_outbound.Handler              { return m.handler }
func (*trojanFlowManager) AddHandler(context.Context, feature_outbound.Handler) error { return nil }
func (*trojanFlowManager) RemoveHandler(context.Context, string) error                { return nil }
func (m *trojanFlowManager) ListHandlers(context.Context) []feature_outbound.Handler {
	return []feature_outbound.Handler{m.handler}
}

type trojanFlowWriter struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	wrote     chan struct{}
	wroteOnce sync.Once
}

func newTrojanFlowWriter() *trojanFlowWriter {
	return &trojanFlowWriter{wrote: make(chan struct{})}
}

func (w *trojanFlowWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	written, err := w.buffer.Write(payload)
	w.mu.Unlock()
	w.wroteOnce.Do(func() { close(w.wrote) })
	return written, err
}

func (w *trojanFlowWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buffer.Bytes()...)
}
