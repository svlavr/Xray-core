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
	"github.com/xtls/xray-core/common/buf"
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

// Direct core calls retain forwarding but no longer admit inspection roots.
func inspectionAPIRetired(t *testing.T, view fs.FlowInspection) {
	t.Helper()
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("core API admitted live roots: %+v %v", live, err)
	}
	totals, err := view.ReadTotals()
	if err != nil || totals.User != (fs.ClientTotals{}) || len(totals.Rows) != 0 {
		t.Fatalf("core API admitted totals: %+v %v", totals, err)
	}
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
		fs.TrafficOriginUser,
		fs.TrafficOriginUnknown,
		fs.TrafficOriginInternal,
		fs.TrafficOriginControlledMeasurement,
	} {
		t.Run(map[fs.TrafficOrigin]string{
			fs.TrafficOriginUser:                  "user",
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
			inspectionAPIRetired(t, view)
			if err = conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFlowInspectionAPIDialUDPOrigins(t *testing.T) {
	for _, origin := range []fs.TrafficOrigin{fs.TrafficOriginUser, fs.TrafficOriginUnknown, fs.TrafficOriginInternal, fs.TrafficOriginControlledMeasurement} {
		t.Run(map[fs.TrafficOrigin]string{fs.TrafficOriginUser: "user", fs.TrafficOriginUnknown: "unknown", fs.TrafficOriginInternal: "internal", fs.TrafficOriginControlledMeasurement: "measurement"}[origin], func(t *testing.T) {
			instance, view, _ := inspectionCore(t, true, false)
			destination := startOutboundStatsUDPServer(t, 0x57)
			payload := []byte("explicit packet admission")
			conn, err := core.DialUDP(inspectionAPIContext(instance, origin), instance)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if n, err := conn.WriteTo(payload, destination.RawNetAddr()); err != nil || n != len(payload) {
				t.Fatalf("write: %d %v", n, err)
			}
			response := make([]byte, 7)
			n, sender, err := conn.ReadFrom(response)
			if err != nil || n != len(response) {
				t.Fatalf("read: %d %v", n, err)
			}
			if net.DestinationFromAddr(sender) != destination || !bytes.Equal(response, transformOutboundStatsPayload(payload[:n], 0x57)) {
				t.Fatalf("packet source/payload changed: %v %x", sender, response)
			}
			inspectionAPIRetired(t, view)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
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
	mb, err := conn.(buf.Reader).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || mb[0].UDP == nil || *mb[0].UDP != destination || !bytes.Equal(mb[0].Bytes(), transformOutboundStatsPayload(payload, 0x35)) {
		t.Fatalf("native UDP stream metadata/payload: %+v", mb)
	}
	inspectionAPIRetired(t, view)
	if err = conn.Close(); err != nil {
		t.Fatal(err)
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
	n, sender, err := conn.ReadFrom(response)
	if err != nil || n != len(response) {
		t.Fatalf("read %d/%d: %v", n, len(response), err)
	}
	if net.DestinationFromAddr(sender) != destination || !bytes.Equal(response, transformOutboundStatsPayload(payload[:n], 0x57)) {
		t.Fatalf("packet source/payload changed: %v %x", sender, response)
	}
	inspectionAPIRetired(t, view)
	if err = conn.Close(); err != nil {
		t.Fatal(err)
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
	inspectionAPIRetired(t, view)
	if err = conn.Close(); err != nil {
		t.Fatal(err)
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
	inspectionAPIRetired(t, view)
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFlowInspectionAPICallerClose(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	destination := startOutboundStatsTCPServer(t)
	first, err := core.Dial(context.Background(), instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := core.Dial(context.Background(), instance, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := first.Write([]byte("closed")); n != 0 || err == nil {
		t.Fatalf("closed caller write: %d %v", n, err)
	}
	controlExchange(t, sibling, net.Network_TCP)
	inspectionAPIRetired(t, view)
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
	if session.LogicalObservationFromContext(ctx).Exchange != root {
		t.Fatal("core API rewrote caller observation")
	}
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) > 1 {
		t.Fatalf("continuation duplicated root: %+v %v", live, err)
	}
	for _, flow := range live.Rows {
		if flow.Ref != root.Ref() {
			t.Fatalf("continuation created root: %+v", flow)
		}
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	root.Finish()
}

func TestFlowInspectionNativeDialerProxyPhysicalContinuation(t *testing.T) {
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
	conn := controlNativeDial(t, instance, destination)
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
	var flow fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLiveInto(nil)
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		flow = live.Rows[0]
		return flow.Uplink == uint64(len(payload)) && flow.Downlink == uint64(len(payload))
	})
	if flow.Origin != fs.TrafficOriginUser || flow.Outbound.Tag != "direct" || flow.Uplink != uint64(len(payload)) || flow.Downlink != uint64(len(payload)) {
		t.Fatalf("dialerProxy physical continuation: %+v", flow)
	}
	totals, err := view.ReadTotals()
	if err != nil {
		t.Fatal(err)
	}
	for _, total := range totals.Rows {
		if total.Outbound.Tag == "proxy" {
			t.Fatalf("dialerProxy created a logical bucket: %+v", total)
		}
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
}
