package core_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/blackhole"
)

func TestFlowInspectionBlackholeTCP(t *testing.T) {
	for _, kind := range []string{"none", "http", "custom"} {
		for _, enabled := range []bool{false, true} {
			name := kind + "/disabled"
			if enabled {
				name = kind + "/enabled"
			}
			t.Run(name, func(t *testing.T) {
				instance, view, address := inspectionCore(t, enabled, true)
				custom := bytes.Repeat([]byte("local answer"), 300)
				if err := core.AddOutboundHandler(instance, &core.OutboundHandlerConfig{
					Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{
						Response: &blackhole.Response{Type: kind, CustomResponseData: custom},
					}),
				}); err != nil {
					t.Fatal(err)
				}
				// Keep a real Freedom sibling open, then route only future exchanges
				// to Blackhole through the native router.
				payload := []byte("GET / HTTP/1.1\r\nHost: block.invalid\r\n\r\n")
				destination := startOutboundStatsTCPServer(t)
				sibling := inspectionSOCKS(t, address, destination, payload)
				routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
				if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
					Networks: []cnet.Network{cnet.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "block"},
				}}}), true); err != nil {
					t.Fatal(err)
				}
				conn := inspectionSOCKS(t, address, destination, nil)
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				var response []byte
				switch kind {
				case "http":
					// Read the raw header exactly; the native response keeps its
					// socket open for a second after this write.
					r := bufio.NewReader(conn)
					for {
						line, err := r.ReadBytes('\n')
						if err != nil {
							t.Fatal(err)
						}
						response = append(response, line...)
						if bytes.Equal(line, []byte("\r\n")) {
							break
						}
					}
					resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(response)), nil)
					if err != nil || resp.StatusCode != 403 {
						t.Fatalf("local HTTP response: %v %v", resp, err)
					}
					resp.Body.Close()
				case "custom":
					response = make([]byte, len(custom))
					if _, err := io.ReadFull(conn, response); err != nil || !bytes.Equal(response, custom) {
						t.Fatalf("local custom response: %v", err)
					}
				}
				if !enabled {
					if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
						t.Fatal("disabled collection acquired an inspection store")
					}
				} else {
					var ref fs.FlowRef
					if kind == "custom" {
						inspectionWait(t, func() bool {
							live, _ := view.ReadLive(context.Background())
							for _, row := range live.Rows {
								if row.AccountingRoute.Outbound.Tag == "block" && row.Downlink.Known == uint64(len(response)) {
									ref = row.Ref
									return true
								}
							}
							return false
						})
						out, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
						if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
							t.Fatalf("local stop: %+v %v", out, err)
						}
					}
					var terminal fs.TerminalRecord
					inspectionWait(t, func() bool {
						page, _ := view.ReadTerminals(context.Background())
						for _, row := range page.Rows {
							if row.Flow.AccountingRoute.Outbound.Tag == "block" {
								terminal = row
								return true
							}
						}
						return false
					})
					flow := terminal.Flow
					wantReason := fs.EndReasonRejected
					if kind == "custom" {
						wantReason = fs.EndReasonLocalStop
						if flow.Ref != ref {
							t.Fatal("stopped reference changed")
						}
					}
					if terminal.Reason != wantReason || flow.Origin != fs.TrafficOriginUser || len(flow.Routes) == 0 || flow.AccountingRoute.Outbound.Serial == 0 || flow.AccountingRoute.Effective != destination || flow.Routes[0].Outbound != flow.AccountingRoute.Outbound {
						t.Fatalf("ending/route/origin: %+v", terminal)
					}
					if flow.Uplink.Known != uint64(len(payload)) || flow.Downlink.Known != uint64(len(response)) || flow.Uplink.Incomplete || flow.Downlink.Incomplete {
						t.Fatalf("terminal custody: %+v", flow)
					}
					totals, _ := view.ReadTotals(context.Background())
					var found bool
					for _, row := range totals.Rows {
						if row.Outbound == flow.AccountingRoute.Outbound {
							found = true
							if row.Uplink.Known != flow.Uplink.Known || row.Downlink.Known != flow.Downlink.Known || row.Uplink.Incomplete || row.Downlink.Incomplete {
								t.Fatalf("total/terminal mismatch: %+v", row)
							}
						}
					}
					if !found {
						t.Fatal("missing Blackhole total")
					}
				}
				if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
					t.Fatalf("blocked socket remains usable: %d %v", n, err)
				}
				if _, err := sibling.Write(payload); err != nil {
					t.Fatal(err)
				}
				inspectionResponse(t, sibling, payload)
			})
		}
	}
}

func TestFlowInspectionBlackholeUDP(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			destination := cnet.UDPDestination(cnet.LocalHostIP, 9)
			response := []byte("blocked")
			instance, view, inbound := inspectionUDPInboundThrough(t, destination, enabled, false, &core.OutboundHandlerConfig{
				Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{
					Response: &blackhole.Response{Type: "custom", CustomResponseData: response},
				}),
			})
			first, sibling := inspectionUDPClient(t), inspectionUDPClient(t)
			payload := []byte("UDP consumed by Blackhole")
			send := func(conn *net.UDPConn) {
				t.Helper()
				if n, err := conn.WriteToUDP(payload, inbound); err != nil || n != len(payload) {
					t.Fatalf("send blocked UDP: %d %v", n, err)
				}
			}
			for _, conn := range []*net.UDPConn{first, sibling} {
				send(conn)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				data := make([]byte, 32)
				n, _, err := conn.ReadFromUDP(data)
				if err != nil || !bytes.Equal(data[:n], response) {
					t.Fatalf("native UDP local response: %q %v", data[:n], err)
				}
			}
			if !enabled {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled Blackhole UDP allocated observation state")
				}
				return
			}
			readRow := func(conn *net.UDPConn, count uint64) fs.FlowRecord {
				t.Helper()
				var found fs.FlowRecord
				inspectionWait(t, func() bool {
					live, _ := view.ReadLive(context.Background())
					for _, row := range live.Rows {
						if row.Source.Port == cnet.Port(conn.LocalAddr().(*net.UDPAddr).Port) && row.Uplink.Known == count && row.Downlink.Known == uint64(len(response)) && !row.Uplink.Incomplete && !row.Downlink.Incomplete {
							found = row
							return true
						}
					}
					return false
				})
				if found.Kind != fs.FlowKindUDPAssociation || found.Origin != fs.TrafficOriginUser || found.AccountingRoute.Outbound.Tag != "block" || found.AccountingRoute.Outbound.Serial == 0 || found.AccountingRoute.Effective != destination || found.Uplink.Incomplete || found.Downlink.Incomplete {
					t.Fatalf("Blackhole UDP facts: %+v", found)
				}
				return found
			}
			selected := readRow(first, uint64(len(payload)))
			other := readRow(sibling, uint64(len(payload)))
			out, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
			if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("exact Blackhole UDP stop: %+v %v", out, err)
			}
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				if len(page.Rows) != 1 {
					return false
				}
				terminal := page.Rows[0]
				if terminal.Flow.Ref != selected.Ref || terminal.Reason != fs.EndReasonLocalStop || terminal.Flow.Uplink.Known != uint64(len(payload)) || terminal.Flow.Downlink.Known != uint64(len(response)) {
					t.Fatalf("Blackhole UDP terminal: %+v", terminal)
				}
				return true
			})
			send(sibling)
			if row := readRow(sibling, uint64(2*len(payload))); row.Ref != other.Ref {
				t.Fatal("closing one Blackhole association replaced its sibling")
			}
			totals, err := view.ReadTotals(context.Background())
			if err != nil {
				t.Fatalf("Blackhole UDP totals: %+v %v", totals, err)
			}
			var matched bool
			for _, total := range totals.Rows {
				if total.Outbound != selected.AccountingRoute.Outbound {
					if total.Uplink.Known != 0 || total.Downlink.Known != 0 {
						t.Fatalf("unexpected UDP attribution: %+v", total)
					}
					continue
				}
				matched = true
				if total.Origin != fs.TrafficOriginUser || total.Uplink.Known != uint64(3*len(payload)) || total.Downlink.Known != uint64(2*len(response)) || total.Uplink.Incomplete || total.Downlink.Incomplete {
					t.Fatalf("Blackhole UDP total attribution: %+v", total)
				}
			}
			if !matched {
				t.Fatal("missing Blackhole UDP totals")
			}
		})
	}
}
