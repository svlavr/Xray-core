package core_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/dokodemo"
	httpproxy "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func inspectionTCPInbound(t *testing.T, kind string, destination cnet.Destination, enabled, sniff bool) (*core.Instance, fs.FlowInspection, string) {
	t.Helper()
	var settings *serial.TypedMessage
	switch kind {
	case "http-connect":
		settings = serial.ToTypedMessage(&httpproxy.ServerConfig{})
	case "socks-http-connect":
		settings = serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH})
	case "dokodemo":
		settings = serial.ToTypedMessage(&dokodemo.Config{
			RewriteAddress: cnet.NewIPOrDomain(destination.Address), RewritePort: uint32(destination.Port),
			AllowedNetworks: []cnet.Network{cnet.Network_TCP},
		})
	default:
		t.Fatalf("unknown inbound %q", kind)
	}
	port := tcp.PickPort()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:           cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList:         &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
				SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http"}},
			}),
			ProxySettings: settings,
		}},
		Outbound: []*core.OutboundHandlerConfig{inspectionFreedom("direct")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	var view fs.FlowInspection
	if enabled {
		view, err = core.EnableFlowInspection(instance, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, view, net.JoinHostPort("127.0.0.1", port.String())
}

// Send tunnel payload in the same write as CONNECT to exercise retained bytes.
// Reading exactly the native response leaves any already-arrived echo untouched.
func inspectionTCPClient(t *testing.T, kind, address string, destination cnet.Destination, payload []byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := payload
	if kind != "dokodemo" {
		target := net.JoinHostPort(destination.Address.String(), destination.Port.String())
		request = append([]byte("CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"), payload...)
	}
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if kind != "dokodemo" {
		want := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
		response := make([]byte, len(want))
		if _, err = io.ReadFull(conn, response); err != nil || !bytes.Equal(response, want) {
			t.Fatalf("CONNECT response %q: %v", response, err)
		}
	}
	return conn
}

func TestFlowInspectionTCPAdmissions(t *testing.T) {
	t.Setenv(platform.UseFreedomSplice, "enable")
	t.Setenv(platform.UseReadV, "enable")
	for _, kind := range []string{"http-connect", "socks-http-connect", "dokodemo"} {
		t.Run(kind, func(t *testing.T) {
			destination := startOutboundStatsTCPServer(t)
			_, view, address := inspectionTCPInbound(t, kind, destination, true, true)
			payload := append([]byte("GET / HTTP/1.1\r\nHost: p2.invalid\r\n\r\n"), bytes.Repeat([]byte("x"), 8192)...)
			first := inspectionTCPClient(t, kind, address, destination, payload)
			inspectionResponse(t, first, payload)
			second := inspectionTCPClient(t, kind, address, destination, payload)
			inspectionResponse(t, second, payload)
			var selected fs.FlowRecord
			inspectionWait(t, func() bool {
				live, err := view.ReadLive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(live.Rows) != 2 {
					return false
				}
				for _, row := range live.Rows {
					if row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) {
						return false
					}
					if row.Kind != fs.FlowKindTCP || row.Origin != fs.TrafficOriginUser || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Outbound.Tag != "direct" || row.InitialDestination != destination || row.AccountingRoute.RouteTarget.Address.Domain() != "p2.invalid" {
						t.Fatalf("admission/route: %+v", row)
					}
					if row.Uplink.Incomplete || row.Downlink.Incomplete {
						return false
					}
					if row.Uplink.Incomplete || row.Downlink.Incomplete {
						t.Fatalf("live byte facts: %+v", row)
					}
					if row.Source.Port == cnet.Port(first.LocalAddr().(*net.TCPAddr).Port) {
						selected = row
					}
				}
				return selected.Ref.ID != 0
			})
			inspectionTCPTotals(t, view, uint64(2*len(payload)))
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("exact close: %+v %v", outcomes, err)
			}
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Rows) != 1 {
					return false
				}
				ended := page.Rows[0]
				if ended.Flow.Ref != selected.Ref || ended.Reason != fs.EndReasonLocalStop || ended.Flow.Uplink.Known != uint64(len(payload)) || ended.Flow.Downlink.Known != uint64(len(payload)) {
					t.Fatalf("terminal: %+v", ended)
				}
				return true
			})
			if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("stopped endpoint remains open: %d %v", n, err)
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("endpoint did not close: %v", err)
			}
			extra := []byte("sibling after exact close")
			if _, err = second.Write(extra); err != nil {
				t.Fatal(err)
			}
			inspectionResponse(t, second, extra)
			second.Close()
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 2
			})
			inspectionTCPTotals(t, view, uint64(2*len(payload)+len(extra)))
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 0 {
				t.Fatalf("retained live endpoints: %+v %v", live, err)
			}
		})
	}
}

func inspectionTCPTotals(t *testing.T, view fs.FlowInspection, want uint64) {
	t.Helper()
	inspectionWait(t, func() bool {
		totals, err := view.ReadTotals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var up, down uint64
		for _, row := range totals.Rows {
			if row.Uplink.Known == 0 && row.Downlink.Known == 0 {
				continue
			}
			if row.Uplink.Incomplete || row.Downlink.Incomplete {
				return false
			}
			if row.Origin != fs.TrafficOriginUser || row.Outbound.Serial == 0 || row.Outbound.Tag != "direct" || row.Uplink.Incomplete || row.Downlink.Incomplete {
				t.Fatalf("total attribution/accuracy: %+v", row)
			}
			up += row.Uplink.Known
			down += row.Downlink.Known
		}
		return up == want && down == want
	})
}

func TestFlowInspectionTCPAdmissionsDisabled(t *testing.T) {
	t.Setenv(platform.UseFreedomSplice, "enable")
	t.Setenv(platform.UseReadV, "enable")
	for _, kind := range []string{"http-connect", "socks-http-connect", "dokodemo"} {
		t.Run(kind, func(t *testing.T) {
			destination := startOutboundStatsTCPServer(t)
			instance, _, address := inspectionTCPInbound(t, kind, destination, false, false)
			provider := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider)
			payload := bytes.Repeat([]byte("collection off"), 1024)
			conn := inspectionTCPClient(t, kind, address, destination, payload)
			response := make([]byte, len(payload))
			if n, err := io.ReadFull(conn, response); err != nil {
				t.Fatalf("disabled response: got %d of %d bytes: %v", n, len(payload), err)
			}
			if !bytes.Equal(response, transformOutboundStatsTCPPayload(payload)) {
				t.Fatal("disabled payload changed")
			}
			conn.Close()
			if provider.Observation() != nil {
				t.Fatal("disabled traffic allocated inspection")
			}
		})
	}
}

// The first-byte buffering repair also serves ordinary HTTP. Two pipelined
// requests exercise the next request already retained in that same reader and
// must become distinct request-local observations on one accepted connection.
func TestFlowInspectionHTTPDelegationKeepAliveControl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.URL.Path)
	}))
	defer server.Close()
	_, view, address := inspectionTCPInbound(t, "socks-http-connect", cnet.Destination{}, true, false)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := "GET " + server.URL + "/first HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\nProxy-Connection: keep-alive\r\n\r\n"
	request += "GET " + server.URL + "/second HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\nProxy-Connection: close\r\n\r\n"
	if _, err = io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	for _, want := range []string{"/first", "/second"} {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("keep-alive response: %d %q %v", response.StatusCode, body, err)
		}
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil || len(page.Rows) != 2 {
			return false
		}
		if page.Rows[0].Flow.Ref == page.Rows[1].Flow.Ref {
			t.Fatal("pipelined HTTP requests reused one FlowRef")
		}
		for _, row := range page.Rows {
			if row.Flow.Kind != fs.FlowKindTCP || row.Flow.AccountingRoute.Outbound.Tag != "direct" || row.Flow.AccountingRoute.Outbound.Serial == 0 || row.Flow.Uplink.Known == 0 || row.Flow.Downlink.Known == 0 || row.Flow.Uplink.Incomplete || row.Flow.Downlink.Incomplete {
				t.Fatalf("plain HTTP request receipt: %+v", row)
			}
		}
		return true
	})
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 0 {
		t.Fatalf("completed plain HTTP request remained live: %+v %v", live, err)
	}
}

func TestFlowInspectionTCPAdmissionsRejected(t *testing.T) {
	for _, kind := range []string{"http-connect", "dokodemo"} {
		t.Run(kind, func(t *testing.T) {
			destination := cnet.TCPDestination(cnet.LocalHostIP, 1)
			instance, view, address := inspectionTCPInbound(t, kind, destination, true, true)
			routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
			if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
				RuleTag: "missing", Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "absent"},
			}}}), true); err != nil {
				t.Fatal(err)
			}
			payload := []byte("GET / HTTP/1.1\r\nHost: rejected.invalid\r\n\r\n")
			inspectionTCPClient(t, kind, address, destination, payload)
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Rows) != 1 {
					return false
				}
				final := page.Rows[0]
				if final.Reason != fs.EndReasonRejected || final.Flow.Uplink.Known != uint64(len(payload)) || final.Flow.Downlink.Known != 0 || final.Flow.AccountingRoute.Outbound.Serial != 0 {
					t.Fatalf("rejected receipt: %+v", final)
				}
				return true
			})
		})
	}
}
