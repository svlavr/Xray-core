package dispatcher_test

import (
	"bytes"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessout "github.com/xtls/xray-core/proxy/vmess/outbound"
	testtcp "github.com/xtls/xray-core/testing/servers/tcp"
	xproxy "golang.org/x/net/proxy"
)

func waitUserConnections(t *testing.T, d *dispatcher.DefaultDispatcher, count int) []dispatcher.UserConnection {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows := d.ConnectionSnapshot().Connections
		if len(rows) == count {
			return rows
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("wanted %d live requests, got %+v", count, d.ConnectionSnapshot())
	return nil
}

func TestUserConnectionsSOCKSRouteSwitch(t *testing.T) {
	for _, name := range []string{"disabled", "enabled", "native-mux", "native-mux-sniff"} {
		enabled := name != "disabled"
		t.Run(name, func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var echoWG sync.WaitGroup
			echoWG.Go(func() {
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					echoWG.Go(func() {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
						_, _ = io.Copy(conn, conn)
					})
				}
			})
			t.Cleanup(func() { echo.Close(); echoWG.Wait() })
			port := testtcp.PickPort()
			rules := func(tag string) *router.Config {
				return &router.Config{Rule: []*router.RoutingRule{{
					TargetTag: &router.RoutingRule_Tag{Tag: tag}, RuleTag: "choose-" + tag,
					Networks: []net.Network{net.Network_TCP},
				}}}
			}
			firstOutbound := &core.OutboundHandlerConfig{Tag: "A", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}
			if strings.HasPrefix(name, "native-mux") {
				gatewayPort := testtcp.PickPort()
				account := serial.ToTypedMessage(&vmess.Account{Id: "f7304539-6863-4d7d-a59e-71d6a57c5011", SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}})
				gateway, err := core.New(&core.Config{
					App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
					Inbound: []*core.InboundHandlerConfig{{
						ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: net.NewIPOrDomain(net.LocalHostIP), PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(gatewayPort)}}}),
						ProxySettings:    serial.ToTypedMessage(&vmessin.Config{User: []*protocol.User{{Account: account}}}),
					}},
					Outbound: []*core.OutboundHandlerConfig{{ProxySettings: firstOutbound.ProxySettings}},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { gateway.Close() })
				if err := gateway.Start(); err != nil {
					t.Fatal(err)
				}
				firstOutbound.SenderSettings = serial.ToTypedMessage(&proxyman.SenderConfig{MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4}})
				firstOutbound.ProxySettings = serial.ToTypedMessage(&vmessout.Config{Receiver: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(gatewayPort), User: &protocol.User{Account: account}}})
			}
			v, err := core.New(&core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&dispatcher.Config{}),
					serial.ToTypedMessage(&proxyman.InboundConfig{}),
					serial.ToTypedMessage(&proxyman.OutboundConfig{}),
					serial.ToTypedMessage(rules("A")),
				},
				Inbound: []*core.InboundHandlerConfig{{
					Tag: "user-socks",
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						Listen:           net.NewIPOrDomain(net.LocalHostIP),
						PortList:         &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
						SniffingSettings: &proxyman.SniffingConfig{Enabled: strings.HasSuffix(name, "-sniff")},
					}),
					ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{Address: net.NewIPOrDomain(net.LocalHostIP)}),
				}},
				Outbound: []*core.OutboundHandlerConfig{
					firstOutbound,
					{Tag: "B", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			d := v.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
			if enabled {
				if err := d.EnableConnectionTracking(8); err != nil {
					t.Fatal(err)
				}
			}
			if err := v.Start(); err != nil {
				t.Fatal(err)
			}
			dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, port).NetAddr(), nil, &net.Dialer{Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			dial := func() net.Conn {
				t.Helper()
				conn, err := dialer.Dial("tcp", echo.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				return conn
			}
			exchange := func(conn net.Conn) {
				t.Helper()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := []byte("live user TCP payload")
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("payload changed")
				}
			}
			a := dial()
			exchange(a)
			if err := v.GetFeature(routing.RouterType()).(*router.Router).ReloadRules(rules("B"), false); err != nil {
				t.Fatal(err)
			}
			b := dial()
			exchange(b)
			exchange(a)
			if enabled {
				rows := waitUserConnections(t, d, 2)
				deadline := time.Now().Add(5 * time.Second)
				for {
					complete := true
					for i, row := range rows {
						want := int64(len("live user TCP payload"))
						if i == 0 {
							want *= 2
						}
						rawDeferred := (runtime.GOOS == "linux" || runtime.GOOS == "android") && !(strings.HasPrefix(name, "native-mux") && i == 0)
						complete = complete && row.UplinkReadBytes == want && (rawDeferred || row.DownlinkWrittenBytes == want)
					}
					if complete {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("completed I/O counters not published: %+v", rows)
					}
					time.Sleep(time.Millisecond)
					rows = waitUserConnections(t, d, 2)
				}
				for i, tag := range []string{"A", "B"} {
					if !rows[i].OutboundSelected || rows[i].OutboundTag != tag || rows[i].RuleTag != "choose-"+tag || rows[i].InboundTag != "user-socks" || rows[i].Source == "" {
						t.Fatalf("wrong selected facts: %+v", rows)
					}
					want := int64(len("live user TCP payload"))
					if i == 0 {
						want *= 2
					}
					if rows[i].UplinkCoverage != dispatcher.BytesExact || rows[i].UplinkReadBytes != want {
						t.Fatalf("uplink payload accounting: %+v, want %d", rows[i], want)
					}
					if (runtime.GOOS == "linux" || runtime.GOOS == "android") && !(strings.HasPrefix(name, "native-mux") && i == 0) {
						if rows[i].DownlinkCoverage != dispatcher.BytesDeferredRawCopy {
							t.Fatalf("active native raw copy must report deferred bytes: %+v", rows[i])
						}
					} else if rows[i].DownlinkCoverage != dispatcher.BytesExact || rows[i].DownlinkWrittenBytes != want {
						t.Fatalf("downlink accepted accounting: %+v, want %d", rows[i], want)
					}
				}
				a.Close()
				left := waitUserConnections(t, d, 1)
				if left[0].ID != rows[1].ID {
					t.Fatal("wrong request retired")
				}
				if totals := d.ConnectionSnapshot().OutboundTotals; len(totals) != 2 || totals[0].OutboundTag != "A" || totals[0].UplinkReadBytes != int64(2*len("live user TCP payload")) {
					t.Fatalf("retirement erased A totals: %+v", totals)
				}
				exchange(b)
			} else if len(d.ConnectionSnapshot().Connections) != 0 {
				t.Fatal("disabled tracker registered traffic")
			}
			b.Close()
			a.Close()
			waitUserConnections(t, d, 0)
			if enabled {
				// Dispatch return may precede raw-copy return. Totals must receive
				// that late result while remaining independent of the live index.
				deadline := time.Now().Add(5 * time.Second)
				for {
					totals := d.ConnectionSnapshot().OutboundTotals
					complete := len(totals) == 2
					for i, total := range totals {
						want := int64(2 * len("live user TCP payload"))
						complete = complete && total.OutboundTag == []string{"A", "B"}[i] && total.UplinkReadBytes == want && total.DownlinkWrittenBytes == want && total.UplinkCoverage == dispatcher.BytesExact && total.DownlinkCoverage == dispatcher.BytesExact
					}
					if complete {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("final per-outbound totals: %+v", totals)
					}
					time.Sleep(time.Millisecond)
				}
			} else if len(d.ConnectionSnapshot().OutboundTotals) != 0 {
				t.Fatal("disabled observation counted USER totals")
			}
		})
	}
}
