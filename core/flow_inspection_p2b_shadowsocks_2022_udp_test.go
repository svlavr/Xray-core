package core_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	N "github.com/sagernet/sing/common/network"
	cnet "github.com/xtls/xray-core/common/net"
	fin "github.com/xtls/xray-core/features/inbound"
	fs "github.com/xtls/xray-core/features/stats"
	ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func TestFlowInspectionP2BShadowsocks2022UDP(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{{"single", inspectionShadowsocks2022Receiver}, {"multi", inspectionShadowsocks2022MultiReceiver}} {
		t.Run(test.name, func(t *testing.T) {
			inspectionSuppliedUDPReceiverAcceptance(t, test.receiver, []byte("SS2022 decoded packet"))
		})
	}
}

type inspectionRebindConn struct{ net.Conn }

func TestFlowInspectionP2BShadowsocks2022Rebind(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "multi"}[multi], func(t *testing.T) {
			instance, view, outbound := inspectionShadowsocks2022ReceiverMode(t, true, false, multi)
			settings, err := outbound.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			config := settings.(*ss.ClientConfig)
			server := cnet.TCPDestination(config.Address.AsAddress(), cnet.Port(config.Port)).NetAddr()
			dial := func() net.Conn {
				conn, err := net.Dial("udp", server)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				return conn
			}
			transport := &inspectionRebindConn{Conn: dial()}
			method, err := shadowaead_2022.NewWithPassword(config.Method, config.Key, nil)
			if err != nil {
				t.Fatal(err)
			}
			client, sibling := method.DialPacketConn(transport), method.DialPacketConn(transport)
			first, second := startOutboundStatsUDPServer(t, 0x19), startOutboundStatsUDPServer(t, 0x37)
			exchange := func(client N.NetPacketConn, destination cnet.Destination, payload []byte, mask byte) {
				t.Helper()
				transport.SetDeadline(time.Now().Add(3 * time.Second))
				addr := &net.UDPAddr{IP: destination.Address.IP(), Port: int(destination.Port)}
				if _, err := client.WriteTo(payload, addr); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, 65535)
				n, from, err := client.ReadFrom(response)
				want := append([]byte(nil), payload...)
				for i := range want {
					want[i] ^= mask
				}
				if err != nil || !bytes.Equal(response[:n], want) || from.String() != addr.String() {
					t.Fatalf("packet response %d %v %v", n, from, err)
				}
			}
			payload := []byte("first native session")
			extra := []byte("second destination after rebind")
			siblingPayload := []byte("sibling")
			exchange(client, first, payload, 0x19)
			exchange(sibling, first, siblingPayload, 0x19)
			var original fs.FlowRef
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				for _, row := range live.Rows {
					if row.Uplink.Known == uint64(len(payload)) && row.Downlink.Known == row.Uplink.Known {
						original = row.Ref
					}
				}
				return len(live.Rows) == 2 && original.ID != 0
			})
			transport.Conn.Close()
			transport.Conn = dial()
			exchange(client, second, extra, 0x37)
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive(context.Background())
				for _, row := range live.Rows {
					if row.Ref == original {
						return row.Uplink.Known == uint64(len(payload)+len(extra)) && row.Downlink.Known == row.Uplink.Known && len(row.Destinations) == 2
					}
				}
				return false
			})
			inspectionClosePacketCallback(t, view, original)
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == original
			})
			// The same wire session creates a fresh logical admission after stop.
			exchange(client, first, payload, 0x19)
			exchange(sibling, second, siblingPayload, 0x37)
			inspectionWait(t, func() bool { live, _ := view.ReadLive(context.Background()); return len(live.Rows) == 2 })
			if err := instance.GetFeature(fin.ManagerType()).(fin.Manager).RemoveHandler(context.Background(), "ss2022-receiver"); err != nil {
				t.Fatal(err)
			}
			inspectionWait(t, func() bool { live, _ := view.ReadLive(context.Background()); return len(live.Rows) == 0 })
		})
	}
}
