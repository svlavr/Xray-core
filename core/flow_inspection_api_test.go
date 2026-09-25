package core_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
)

func inspectionAPITerminal(t *testing.T, view fs.FlowInspection) fs.TerminalRecord {
	t.Helper()
	var terminal fs.TerminalRecord
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) != 1 {
			return false
		}
		terminal = page.Rows[0]
		return true
	})
	return terminal
}

func inspectionAPIContext(instance *core.Instance, origin fs.TrafficOrigin) context.Context {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	if origin != fs.TrafficOriginUnknown {
		ctx = session.ContextWithTrafficOrigin(ctx, origin)
	}
	return ctx
}

func TestFlowInspectionAPIDialTCPOrigins(t *testing.T) {
	for _, origin := range []fs.TrafficOrigin{
		fs.TrafficOriginUnknown,
		fs.TrafficOriginInternal,
		fs.TrafficOriginControlledMeasurement,
	} {
		t.Run(map[fs.TrafficOrigin]string{
			fs.TrafficOriginUnknown:               "unknown",
			fs.TrafficOriginInternal:              "internal",
			fs.TrafficOriginControlledMeasurement: "controlled-measurement",
		}[origin], func(t *testing.T) {
			instance, view, _ := inspectionCore(t, true, false)
			destination := startOutboundStatsTCPServer(t)
			payload := []byte("caller-facing TCP payload")
			conn, err := core.Dial(inspectionAPIContext(instance, origin), instance, destination)
			if err != nil {
				t.Fatal(err)
			}
			if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("write %d/%d: %v", n, len(payload), err)
			}
			response := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, response); err != nil {
				t.Fatal(err)
			}
			if want := transformOutboundStatsTCPPayload(payload); !bytes.Equal(response, want) {
				t.Fatalf("response %x want %x", response, want)
			}
			if err = conn.Close(); err != nil {
				t.Fatal(err)
			}
			flow := inspectionAPITerminal(t, view).Flow
			if flow.Kind != fs.FlowKindTCP || flow.Origin != origin || flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(len(payload)) || flow.AccountingRoute.Outbound.Tag != "direct" || flow.AccountingRoute.Outbound.Serial == 0 {
				t.Fatalf("API TCP facts: %+v", flow)
			}
		})
	}
}

func TestFlowInspectionAPIDialUDPStream(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	destination := startOutboundStatsUDPServer(t, 0x35)
	payload := []byte("caller UDP stream")
	conn, err := core.Dial(inspectionAPIContext(instance, fs.TrafficOriginInternal), instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	flow := inspectionAPITerminal(t, view).Flow
	if flow.Kind != fs.FlowKindUDPAssociation || flow.Origin != fs.TrafficOriginInternal || flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(len(payload)) || len(flow.Destinations) != 1 || flow.Destinations[0] != destination {
		t.Fatalf("API UDP stream facts: %+v", flow)
	}
}

func TestFlowInspectionAPIDialUDPPacketConn(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	destination := startOutboundStatsUDPServer(t, 0x57)
	payload := []byte("caller packet payload")
	conn, err := core.DialUDP(inspectionAPIContext(instance, fs.TrafficOriginInternal), instance)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.WriteTo(payload, destination.RawNetAddr()); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, 7)
	n, _, err := conn.ReadFrom(response)
	if err != nil || n != len(response) {
		t.Fatalf("read %d/%d: %v", n, len(response), err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	flow := inspectionAPITerminal(t, view).Flow
	if flow.Kind != fs.FlowKindUDPAssociation || flow.Origin != fs.TrafficOriginInternal || flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(n) || len(flow.Destinations) != 1 || flow.Destinations[0] != destination || flow.AccountingRoute.Outbound.Tag != "direct" || flow.AccountingRoute.Outbound.Serial == 0 {
		t.Fatalf("API PacketConn facts: %+v", flow)
	}
}

func TestFlowInspectionAPITaggedForcedHandler(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	destination := startOutboundStatsTCPServer(t)
	payload := []byte("tagged caller payload")
	dispatcher := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	conn, err := taggedimpl.DialTaggedOutbound(inspectionAPIContext(instance, fs.TrafficOriginControlledMeasurement), dispatcher, destination, "direct")
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	flow := inspectionAPITerminal(t, view).Flow
	if flow.Origin != fs.TrafficOriginControlledMeasurement || flow.AccountingRoute.Selection != fs.SelectionForced || flow.AccountingRoute.Outbound.Tag != "direct" || flow.AccountingRoute.Outbound.Serial == 0 || flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(len(payload)) {
		t.Fatalf("tagged API facts: %+v", flow)
	}
}

func TestFlowInspectionAPILoopbackContinuation(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	inspectionForwardRoute(t, instance)
	destination := startOutboundStatsTCPServer(t)
	payload := []byte("loopback continuation")
	conn, err := core.Dial(context.Background(), instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	page := inspectionAPITerminal(t, view)
	if page.Flow.Origin != fs.TrafficOriginUnknown || len(page.Flow.Routes) != 2 || page.Flow.Routes[0].Outbound.Tag != "forward" || page.Flow.AccountingRoute.Outbound.Tag != "direct" || page.Flow.Uplink.Known != uint64(len(payload)) || page.Flow.Downlink.Known != uint64(len(payload)) {
		t.Fatalf("loopback API continuation: %+v", page)
	}
}

func TestFlowInspectionAPILocalStop(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	destination := startOutboundStatsTCPServer(t)
	conn, err := core.Dial(context.Background(), instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ref fs.FlowRef
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) != 1 || live.Rows[0].AccountingRoute.Outbound.Serial == 0 {
			return false
		}
		ref = live.Rows[0].Ref
		return true
	})
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("close API root: %+v %v", outcomes, err)
	}
	terminal := inspectionAPITerminal(t, view)
	if terminal.Flow.Ref != ref || terminal.Reason != fs.EndReasonLocalStop {
		t.Fatalf("local-stop terminal: %+v", terminal)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFlowInspectionAPIExistingRootContinuation(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	destination := startOutboundStatsTCPServer(t)
	provider := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider)
	root := provider.Observation().PrepareTCP(fs.TrafficOriginUser, net.Destination{}, destination, nil)
	ctx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: root})
	payload := []byte("physical continuation")
	conn, err := core.Dial(ctx, instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	root.Finish()
	flow := inspectionAPITerminal(t, view).Flow
	if flow.Ref != root.Ref() || flow.Origin != fs.TrafficOriginUser || len(flow.Routes) != 1 || flow.AccountingRoute.Outbound.Tag != "direct" || flow.Uplink.Known != 0 || flow.Downlink.Known != 0 {
		t.Fatalf("existing-root continuation: %+v", flow)
	}
}

func TestFlowInspectionAPIDialerProxyPhysicalContinuation(t *testing.T) {
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "direct",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
					SocketSettings: &internet.SocketConfig{DialerProxy: "proxy"},
				}}),
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
			{Tag: "proxy", ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	view, err := core.EnableFlowInspection(instance, fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	destination := startOutboundStatsTCPServer(t)
	payload := []byte("dialer proxy payload")
	ctx := session.ContextWithTrafficOrigin(context.Background(), fs.TrafficOriginUser)
	conn, err := core.Dial(ctx, instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	flow := inspectionAPITerminal(t, view).Flow
	if flow.Origin != fs.TrafficOriginUser || len(flow.Routes) != 1 || flow.Routes[0].Outbound.Tag != "direct" || flow.AccountingRoute.Outbound.Tag != "direct" || flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(len(payload)) {
		t.Fatalf("dialerProxy physical continuation: %+v", flow)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, total := range totals.Rows {
		if total.Outbound.Tag == "proxy" {
			t.Fatalf("dialerProxy created a logical bucket: %+v", total)
		}
	}
}
