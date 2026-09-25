package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type muxTimedReader struct{ *pipe.Reader }

func (r muxTimedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.Reader.ReadMultiBufferTimeout(3 * time.Second)
}

func inspectionMuxWire(t *testing.T, instance *core.Instance, origin fs.TrafficOrigin) (*pipe.Writer, *buf.BufferedReader) {
	t.Helper()
	input, send := pipe.New()
	output, reply := pipe.New()
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithTrafficOrigin(ctx, origin)
	// Anonymous native admission must not require User metadata.
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: cnet.TCPDestination(cnet.LocalHostIP, 1234)})
	worker, err := mux.NewServerWorker(ctx, instance.GetFeature(frouting.DispatcherType()).(frouting.Dispatcher), &transport.Link{Reader: input, Writer: reply})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(); input.Interrupt(); output.Interrupt() })
	return send, &buf.BufferedReader{Reader: muxTimedReader{output}}
}

func inspectionMuxWirePacket(t *testing.T, send buf.Writer, receive *buf.BufferedReader, id uint16, global [8]byte, destination cnet.Destination, payload string) {
	t.Helper()
	writer := mux.NewWriter(id, destination, send, protocol.TransferTypePacket, global, nil)
	b := buf.FromBytes([]byte(payload))
	b.UDP = &destination
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	var meta mux.FrameMetadata
	if err := meta.Unmarshal(receive, false); err != nil {
		t.Fatal(err)
	}
	mb, err := mux.NewPacketReader(receive, &meta.Target).ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != payload || meta.SessionID != id {
		t.Fatalf("wire response: %+v %q %v", meta, mb.String(), err)
	}
}

func TestFlowInspectionMuxRetainedProvenance(t *testing.T) {
	for i, mode := range []string{"origin", "unknown", "foreign-runtime", "disabled-runtime"} {
		t.Run(mode, func(t *testing.T) {
			owner, view, _ := inspectionCore(t, true, false)
			destination := startOutboundStatsUDPServer(t, 0)
			global := [8]byte{0xfa, 0x51, byte(i + 1)}
			a, ar := inspectionMuxWire(t, owner, fs.TrafficOriginUser)
			inspectionMuxWirePacket(t, a, ar, 1, global, destination, "known")
			var first fs.FlowRecord
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				if len(live.Rows) != 1 {
					return false
				}
				first = live.Rows[0]
				return first.Uplink.Known == 5 && first.Downlink.Known == 5
			})
			other := owner
			origin := fs.TrafficOriginInternal
			var otherView fs.FlowInspection
			if mode == "unknown" {
				origin = fs.TrafficOriginUnknown
			}
			if mode == "foreign-runtime" || mode == "disabled-runtime" {
				other, otherView, _ = inspectionCore(t, mode == "foreign-runtime", false)
				origin = fs.TrafficOriginUser
			}
			b, br := inspectionMuxWire(t, other, origin)
			inspectionMuxWirePacket(t, b, br, 2, global, destination, "ambiguous")
			c, cr := inspectionMuxWire(t, owner, fs.TrafficOriginUser)
			inspectionMuxWirePacket(t, c, cr, 3, global, destination, "still fenced")
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 {
				t.Fatalf("retained rows: %+v %v", live, err)
			}
			row := live.Rows[0]
			if row.Ref != first.Ref || row.Origin != fs.TrafficOriginUser || row.Uplink.Known != 5 || row.Downlink.Known != 5 || !row.Uplink.Incomplete || !row.Downlink.Incomplete {
				t.Fatalf("fenced result: %+v", row)
			}
			if otherView != nil {
				foreign, _ := otherView.ReadLive(context.Background())
				if len(foreign.Rows) != 0 {
					t.Fatal("foreign runtime acquired old association ref")
				}
			}
			totals, _ := view.ReadTotals(context.Background())
			var known uint64
			var incomplete bool
			for _, bucket := range totals.Rows {
				known += bucket.Uplink.Known
				incomplete = incomplete || bucket.Uplink.Incomplete || bucket.Downlink.Incomplete
			}
			if known != 5 || !incomplete {
				t.Fatalf("fenced totals: %+v", totals)
			}
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{first.Ref})
			if err != nil || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("retained close: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == first.Ref
			})
		})
	}
}
