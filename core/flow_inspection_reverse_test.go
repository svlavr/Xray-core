package core_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/mux"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

type inspectionReverseCarrier struct {
	mu     sync.Mutex
	worker *mux.ClientWorker
	ready  chan fs.TrafficOrigin
}

func (*inspectionReverseCarrier) Tag() string  { return "carrier" }
func (*inspectionReverseCarrier) Start() error { return nil }
func (h *inspectionReverseCarrier) Close() error {
	h.mu.Lock()
	w := h.worker
	h.mu.Unlock()
	if w != nil {
		return w.Close()
	}
	return nil
}
func (*inspectionReverseCarrier) SenderSettings() *serial.TypedMessage { return nil }
func (*inspectionReverseCarrier) ProxySettings() *serial.TypedMessage  { return nil }
func (h *inspectionReverseCarrier) Dispatch(ctx context.Context, link *transport.Link) {
	w, err := mux.NewClientWorker(*link, mux.ClientStrategy{})
	if err != nil {
		return
	}
	h.mu.Lock()
	h.worker = w
	h.mu.Unlock()
	h.ready <- session.TrafficOriginFromContext(ctx)
	<-w.WaitClosed()
}

func TestFlowInspectionAppReverseChildren(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	carrier := &inspectionReverseCarrier{ready: make(chan fs.TrafficOrigin, 1)}
	if err := instance.GetFeature(fout.ManagerType()).(fout.Manager).AddHandler(context.Background(), carrier); err != nil {
		t.Fatal(err)
	}
	if err := instance.GetFeature(frouting.RouterType()).(frouting.Router).AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "bridge.invalid"}}}}, TargetTag: &router.RoutingRule_Tag{Tag: "carrier"}}}}), true); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	object, err := common.CreateObject(ctx, &reverse.Config{BridgeConfig: []*reverse.BridgeConfig{{Tag: "bridge", Domain: "bridge.invalid"}}})
	if err != nil {
		t.Fatal(err)
	}
	bridge := object.(*reverse.Reverse)
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Close(); carrier.Close() })
	select {
	case origin := <-carrier.ready:
		if origin != fs.TrafficOriginInternal {
			t.Fatalf("carrier origin: %v", origin)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native bridge did not establish carrier")
	}
	carrier.mu.Lock()
	client := carrier.worker
	carrier.mu.Unlock()
	open := func(target cnet.Destination) (*pipe.Writer, *pipe.Reader) {
		uplink, input := pipe.New()
		output, downlink := pipe.New()
		t.Cleanup(func() { uplink.Interrupt(); output.Interrupt() })
		child := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
		child = session.ContextWithTrafficOrigin(child, fs.TrafficOriginUser)
		if !client.Dispatch(child, &transport.Link{Reader: uplink, Writer: downlink}) {
			t.Fatal("reverse client dispatch failed")
		}
		return input, output
	}
	control, _ := open(cnet.UDPDestination(cnet.DomainAddress("reverse"), 0))
	message := new(reverse.Control)
	message.FillInRandom()
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	control.WriteMultiBuffer(buf.MergeBytes(nil, encoded))
	control.Close()
	inspectionWait(t, func() bool { return client.ActiveConnections() == 0 })
	destination := startOutboundStatsTCPServer(t)
	send, receive := open(destination)
	payload := []byte("reverse decoded data")
	send.WriteMultiBuffer(buf.MergeBytes(nil, payload))
	mb, err := receive.ReadMultiBufferTimeout(3 * time.Second)
	if err != nil || !bytes.Equal([]byte(mb.String()), transformOutboundStatsTCPPayload(payload)) {
		t.Fatalf("reverse response: %q %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	var row fs.FlowRecord
	inspectionWait(t, func() bool {
		live, _ := view.ReadLive(context.Background())
		if len(live.Rows) != 1 {
			return false
		}
		row = live.Rows[0]
		return row.Uplink.Known == uint64(len(payload)) && row.Downlink.Known == uint64(len(payload))
	})
	if row.Origin != fs.TrafficOriginUnknown || row.InitialDestination != destination || row.AccountingRoute.Outbound.Tag != "direct" {
		t.Fatalf("reverse child: %+v", row)
	}
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 0 {
		t.Fatal("reverse control generated logical records")
	}
	out, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
	if err != nil || out[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("reverse exact stop: %+v %v", out, err)
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == row.Ref
	})
	totals, _ := view.ReadTotals(context.Background())
	for _, bucket := range totals.Rows {
		if bucket.Uplink.Known != 0 && (bucket.Origin != fs.TrafficOriginUnknown || bucket.Uplink.Known != uint64(len(payload))) {
			t.Fatalf("reverse control/USER contamination: %+v", bucket)
		}
	}
}
