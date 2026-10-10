package core_test

import (
	"net"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestFlowInspectionSOCKSUDPNativeCounters(t *testing.T) {
	port := tcp.PickPort()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{}),
			serial.ToTypedMessage(&policy.Config{System: &policy.SystemPolicy{Stats: &policy.SystemPolicy_Stats{
				InboundUplink: true, InboundDownlink: true,
			}}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "native-udp",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UdpEnabled: true}),
		}},
		Outbound: []*core.OutboundHandlerConfig{inspectionFreedom("direct")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	view, err := core.EnableFlowInspection(instance, fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	control, client, relay := inspectionSOCKSAssociation(t, net.JoinHostPort("127.0.0.1", port.String()))
	defer control.Close()
	manager := instance.GetFeature(fs.ManagerType()).(fs.Manager)
	up := manager.GetCounter("inbound>>>native-udp>>>traffic>>>uplink")
	down := manager.GetCounter("inbound>>>native-udp>>>traffic>>>downlink")
	if up == nil || down == nil {
		t.Fatal("native counters unavailable")
	}
	// Wait for the server's counter updates after the IPv4 no-auth handshake:
	// greeting/request are 3+10 bytes, method selection/reply are 2+10 bytes.
	inspectionWait(t, func() bool { return up.Value() == 13 && down.Value() == 12 })
	// Compare UDP deltas independently of the control handshake framing.
	beforeUp, beforeDown := up.Value(), down.Value()
	dest := startOutboundStatsUDPServer(t, 0x19)
	payload := []byte("decoded payload differs from SOCKS framing")
	wire, err := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: dest.Address, Port: dest.Port}, payload)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := int64(wire.Len())
	wire.Release()
	inspectionSOCKSPacket(t, client, relay, dest, payload, 0x19)
	inspectionWait(t, func() bool {
		live, err := view.ReadLiveInto(nil)
		return err == nil && len(live.Rows) == 1 && live.Rows[0].Uplink == uint64(len(payload)) && live.Rows[0].Downlink == uint64(len(payload))
	})
	if gotUp, gotDown := up.Value()-beforeUp, down.Value()-beforeDown; gotUp != wantWire || gotDown != wantWire {
		t.Fatalf("native UDP encoded bytes: %d/%d, want %d/%d", gotUp, gotDown, wantWire, wantWire)
	}
}
