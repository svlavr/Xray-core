package core_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/socks"
)

func inspectionSOCKSOutbound(t *testing.T, remote string, enabled bool) (*core.Instance, fs.FlowInspection, string) {
	t.Helper()
	instance, view, address := inspectionCore(t, enabled, true)
	host, portString, err := net.SplitHostPort(remote)
	if err != nil {
		t.Fatal(err)
	}
	port, err := cnet.PortFromString(portString)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.AddOutboundHandler(instance, &core.OutboundHandlerConfig{
		Tag: "socks-proxy", ProxySettings: serial.ToTypedMessage(&socks.ClientConfig{
			Server: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.ParseAddress(host)), Port: uint32(port)},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
		Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "socks-proxy"},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	return instance, view, address
}

func TestFlowInspectionSOCKSOutbound(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			_, remoteView, remote := inspectionCore(t, true, true)
			instance, view, address := inspectionSOCKSOutbound(t, remote, enabled)
			destination := startOutboundStatsTCPServer(t)
			payload := append([]byte("GET / HTTP/1.1\r\nHost: socks-outbound.invalid\r\n\r\n"), bytes.Repeat([]byte("p"), 8192)...)
			first := inspectionSOCKS(t, address, destination, payload)
			second := inspectionSOCKS(t, address, destination, payload)
			if !enabled {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled outbound acquired inspection")
				}
				return
			}
			var selected fs.FlowRef
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				if len(live.Rows) != 2 {
					return false
				}
				for _, row := range live.Rows {
					if row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) || row.Uplink.Incomplete || row.Downlink.Incomplete {
						return false
					}
					if row.AccountingRoute.Outbound.Tag != "socks-proxy" || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != destination || row.Origin != fs.TrafficOriginUser || row.Uplink.Incomplete || row.Downlink.Incomplete {
						t.Fatalf("live proxy receipt: %+v", row)
					}
					if row.Source.Port == cnet.Port(first.LocalAddr().(*net.TCPAddr).Port) {
						selected = row.Ref
					}
				}
				return selected.ID != 0
			})
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected})
			if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("close: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				if len(page.Rows) != 1 {
					return false
				}
				if page.Rows[0].Flow.Ref != selected || page.Rows[0].Reason != fs.EndReasonLocalStop {
					t.Fatalf("wrong stopped exchange: %+v", page.Rows)
				}
				return true
			})
			if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("stopped endpoint returned %d, %v", n, err)
			}
			extra := []byte("sibling through SOCKS after exact close")
			if _, err := second.Write(extra); err != nil {
				t.Fatal(err)
			}
			inspectionResponse(t, second, extra)
			second.Close()
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 2
			})
			want := uint64(2*len(payload) + len(extra))
			totals, _ := view.ReadTotals(context.Background())
			var up, down uint64
			for _, row := range totals.Rows {
				if row.Uplink.Known == 0 && row.Downlink.Known == 0 {
					continue
				}
				if row.Outbound.Tag != "socks-proxy" || row.Uplink.Incomplete || row.Downlink.Incomplete {
					t.Fatalf("proxy totals: %+v", row)
				}
				up += row.Uplink.Known
				down += row.Downlink.Known
			}
			if up != want || down != want {
				t.Fatalf("handshake included or payload lost: %d/%d, want %d", up, down, want)
			}
			// Each instance owns its own exchange; neither client transport
			// dialing nor its SOCKS handshake creates an extra local admission.
			inspectionTCPTotals(t, remoteView, want)
		})
	}
}

func TestFlowInspectionSOCKSOutboundHandshakeEnding(t *testing.T) {
	for _, stop := range []bool{false, true} {
		name := "rejected"
		if stop {
			name = "stop-pending-handshake"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			_, view, address := inspectionSOCKSOutbound(t, listener.Addr().String(), true)
			client := inspectionSOCKS(t, address, cnet.TCPDestination(cnet.LocalHostIP, 80), nil)
			payload := []byte("GET / HTTP/1.1\r\nHost: handshake.invalid\r\n\r\n")
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			var peer net.Conn
			select {
			case peer = <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("outbound did not connect")
			}
			t.Cleanup(func() { peer.Close() })
			peer.SetDeadline(time.Now().Add(5 * time.Second))
			greeting := make([]byte, 3)
			if _, err := io.ReadFull(peer, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 1, 0}) {
				t.Fatalf("native greeting: %v %v", greeting, err)
			}
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 || live.Rows[0].AccountingRoute.Outbound.Tag != "socks-proxy" {
				t.Fatalf("handshake owner: %+v %v", live, err)
			}
			ref := live.Rows[0].Ref
			if stop {
				out, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
				if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
					t.Fatalf("handshake stop: %+v %v", out, err)
				}
				page, _ := view.ReadTerminals(context.Background())
				if len(page.Rows) != 1 || page.Rows[0].Reason != fs.EndReasonLocalStop {
					t.Fatalf("owner-close snapshot: %+v", page)
				}
				live, err := view.ReadLive(context.Background())
				if err != nil || len(live.Rows) != 0 {
					t.Fatalf("owner-close remained live: %+v %v", live, err)
				}
			}
			// Let the real handshake finish with the native unsupported-method
			// failure. No inspection deadline or handshake cancellation is added.
			if _, err := peer.Write([]byte{5, 255}); err != nil {
				t.Fatal(err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				if len(page.Rows) != 1 {
					return false
				}
				row := page.Rows[0]
				if row.Flow.Ref != ref || row.Flow.Uplink.Known != uint64(len(payload)) || row.Flow.Downlink.Known != 0 || row.Flow.Uplink.Incomplete || row.Flow.Downlink.Incomplete || row.Flow.AccountingRoute.Outbound.Tag != "socks-proxy" {
					t.Fatalf("failed handshake receipt: %+v", row)
				}
				if stop && row.Reason != fs.EndReasonLocalStop {
					t.Fatalf("lost local stop: %+v", row)
				}
				return true
			})
		})
	}
}
