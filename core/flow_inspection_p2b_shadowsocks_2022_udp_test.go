package core_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

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
			method, err := ss.GetCipherMethod(config.Method)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := ss.ParsePSKList(config.Key, method.KeySaltLength)
			if err != nil {
				t.Fatal(err)
			}
			newCodec := func() *ss.UDPPacketCodec {
				var codec *ss.UDPPacketCodec
				if len(keys) == 2 {
					codec, err = ss.NewUDPPacketCodec(method, keys[1], keys[0])
				} else {
					codec, err = ss.NewUDPPacketCodec(method, keys[0])
				}
				if err != nil {
					t.Fatal(err)
				}
				return codec
			}
			client, sibling := newCodec(), newCodec()
			first, second := startOutboundStatsUDPServer(t, 0x19), startOutboundStatsUDPServer(t, 0x37)
			exchange := func(codec *ss.UDPPacketCodec, destination cnet.Destination, payload []byte, mask byte) {
				t.Helper()
				transport.SetDeadline(time.Now().Add(3 * time.Second))
				packet, err := codec.EncodeClientPacket(destination, payload)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := transport.Write(packet.Bytes()); err != nil {
					packet.Release()
					t.Fatal(err)
				}
				packet.Release()
				response := make([]byte, 65535)
				n, err := transport.Read(response)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := codec.DecodePacket(response[:n])
				want := append([]byte(nil), payload...)
				for i := range want {
					want[i] ^= mask
				}
				if err != nil || !bytes.Equal(decoded.Payload, want) || decoded.Destination != destination {
					t.Fatalf("packet response %+v %v", decoded, err)
				}
			}
			payload := []byte("first native session")
			extra := []byte("second destination after rebind")
			siblingPayload := []byte("sibling")
			exchange(client, first, payload, 0x19)
			exchange(sibling, first, siblingPayload, 0x19)
			var original fs.FlowRef
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive()
				for _, row := range live.Rows {
					if row.Uplink == uint64(len(payload)) && row.Downlink == row.Uplink {
						original = row.Ref
					}
				}
				return len(live.Rows) == 2 && original.ID != 0
			})
			transport.Conn.Close()
			transport.Conn = dial()
			exchange(client, second, extra, 0x37)
			inspectionWait(t, func() bool {
				live, _ := view.ReadLive()
				for _, row := range live.Rows {
					if row.Ref == original {
						return row.Uplink == uint64(len(payload)+len(extra)) && row.Downlink == row.Uplink
					}
				}
				return false
			})
			inspectionClosePacketCallback(t, view, original)
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals()
				return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == original
			})
			// The same wire session creates a fresh logical admission after stop.
			exchange(client, first, payload, 0x19)
			exchange(sibling, second, siblingPayload, 0x37)
			inspectionWait(t, func() bool { live, _ := view.ReadLive(); return len(live.Rows) == 2 })
			if err := instance.GetFeature(fin.ManagerType()).(fin.Manager).RemoveHandler(context.Background(), "ss2022-receiver"); err != nil {
				t.Fatal(err)
			}
			inspectionWait(t, func() bool { live, _ := view.ReadLive(); return len(live.Rows) == 0 })
		})
	}
}
