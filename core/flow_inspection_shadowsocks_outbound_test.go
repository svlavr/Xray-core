package core_test

import (
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func inspectionShadowsocksConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	_, _, outbound := inspectionShadowsocksReceiver(t, false, false)
	return outbound
}

func inspectionShadowsocksReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	port := tcp.PickPort()
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
