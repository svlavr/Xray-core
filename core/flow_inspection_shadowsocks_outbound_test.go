package core_test

import (
	"errors"
	"math/rand/v2"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/socks"
)

func inspectionPickTCPUDPPort(t *testing.T) cnet.Port {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 128; attempt++ {
		// TCP and UDP have different excluded ranges on Windows. Sampling the
		// dynamic range avoids an OS allocator walking a long opposite-protocol
		// exclusion range; both sockets are still actually bound before return.
		port := cnet.Port(49152 + rand.IntN(16384))
		packet, err := stdnet.ListenPacket("udp4", "127.0.0.1:"+port.String())
		if err != nil {
			lastErr = err
			continue
		}
		listener, err := stdnet.Listen("tcp4", packet.LocalAddr().String())
		if err != nil {
			lastErr = err
			if closeErr := packet.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			continue
		}
		if err := errors.Join(listener.Close(), packet.Close()); err != nil {
			t.Fatal(err)
		}
		return port
	}
	t.Fatalf("no joint TCP/UDP loopback port: %v", lastErr)
	return 0
}

func inspectionShadowsocksConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	_, _, outbound := inspectionShadowsocksReceiver(t, false, false)
	return outbound
}

func inspectionShadowsocksReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	port := inspectionPickTCPUDPPort(t)
	user := &protocol.User{Account: serial.ToTypedMessage(&shadowsocks.Account{
		Password: "inspection-test-only", CipherType: shadowsocks.CipherType_AES_128_GCM,
	})}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:           cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList:         &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"quic"}},
		}),
		ProxySettings: serial.ToTypedMessage(&shadowsocks.ServerConfig{
			Users: []*protocol.User{user}, Network: []cnet.Network{cnet.Network_TCP, cnet.Network_UDP},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	outbound := &core.OutboundHandlerConfig{Tag: "shadowsocks-proxy", ProxySettings: serial.ToTypedMessage(&shadowsocks.ClientConfig{
		Server: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(port), User: user},
	})}
	return remote, view, outbound
}

func TestFlowInspectionShadowsocksOutboundTCP(t *testing.T) {
	inspectionOutboundTCP(t, inspectionShadowsocksConfig)
}

func TestFlowInspectionShadowsocksOutboundUDP(t *testing.T) {
	inspectionOutboundUDP(t, inspectionShadowsocksConfig)
}

func TestFlowInspectionShadowsocksOutboundUDPBatch(t *testing.T) {
	instance, view, _ := inspectionUDPInboundThrough(t, cnet.UDPDestination(cnet.LocalHostIP, 9), true, false, inspectionShadowsocksConfig(t))
	inspectionUDPBatchThrough(t, instance, view, "shadowsocks-proxy")
}

func TestFlowInspectionShadowsocksOutboundPreparationFailure(t *testing.T) {
	outbound := inspectionShadowsocksConfig(t)
	message, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	config := message.(*shadowsocks.ClientConfig)
	config.Server.User.Account = serial.ToTypedMessage(&socks.Account{})
	outbound.ProxySettings = serial.ToTypedMessage(config)
	inspectionOutboundPreparationFailure(t, outbound)
}
