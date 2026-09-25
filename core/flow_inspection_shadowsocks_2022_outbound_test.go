package core_test

import (
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

const (
	inspectionShadowsocks2022Method = "2022-blake3-aes-128-gcm"
	inspectionShadowsocks2022Key    = "MDEyMzQ1Njc4OWFiY2RlZg=="
)

func inspectionShadowsocks2022Config(t *testing.T) *core.OutboundHandlerConfig {
	_, _, outbound := inspectionShadowsocks2022Receiver(t, false, false)
	return outbound
}

func inspectionShadowsocks2022Receiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	return inspectionShadowsocks2022ReceiverMode(t, enabled, sniff, false)
}

func inspectionShadowsocks2022MultiReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	return inspectionShadowsocks2022ReceiverMode(t, enabled, sniff, true)
}

func inspectionShadowsocks2022ReceiverMode(t *testing.T, enabled, sniff, multi bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	port := udp.PickPort()
	settings := serial.ToTypedMessage(&shadowsocks_2022.ServerConfig{
		Method: inspectionShadowsocks2022Method, Key: inspectionShadowsocks2022Key,
		Network: []cnet.Network{cnet.Network_TCP, cnet.Network_UDP},
	})
	clientKey := inspectionShadowsocks2022Key
	if multi {
		const userKey = "ZmVkY2JhOTg3NjU0MzIxMA=="
		settings = serial.ToTypedMessage(&shadowsocks_2022.MultiUserServerConfig{
			Method: inspectionShadowsocks2022Method, Key: inspectionShadowsocks2022Key,
			Network: []cnet.Network{cnet.Network_TCP, cnet.Network_UDP},
			Users:   []*protocol.User{{Email: "inspection@example.invalid", Account: serial.ToTypedMessage(&shadowsocks_2022.Account{Key: userKey})}},
		})
		clientKey += ":" + userKey
	}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		Tag: "ss2022-receiver",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:           cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList:         &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http"}},
		}),
		ProxySettings: settings,
	}); err != nil {
		t.Fatal(err)
	}
	return remote, view, &core.OutboundHandlerConfig{Tag: "shadowsocks-2022-proxy", ProxySettings: serial.ToTypedMessage(&shadowsocks_2022.ClientConfig{
		Address: cnet.NewIPOrDomain(cnet.LocalHostIP),
		Port:    uint32(port),
		Method:  inspectionShadowsocks2022Method,
		Key:     clientKey,
	})}
}

func TestFlowInspectionShadowsocks2022OutboundTCP(t *testing.T) {
	inspectionOutboundTCP(t, inspectionShadowsocks2022Config)
}

func TestFlowInspectionShadowsocks2022OutboundUDP(t *testing.T) {
	inspectionOutboundUDP(t, inspectionShadowsocks2022Config)
}

func TestFlowInspectionShadowsocks2022OutboundUDPBatch(t *testing.T) {
	instance, view, _ := inspectionUDPInboundThrough(t, cnet.UDPDestination(cnet.LocalHostIP, 9), true, false, inspectionShadowsocks2022Config(t))
	inspectionUDPBatchThrough(t, instance, view, "shadowsocks-2022-proxy")
}

func TestFlowInspectionShadowsocks2022OutboundDialFailure(t *testing.T) {
	outbound := inspectionShadowsocks2022Config(t)
	message, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	config := message.(*shadowsocks_2022.ClientConfig)
	config.Port = uint32(tcp.PickPort())
	outbound.ProxySettings = serial.ToTypedMessage(config)
	inspectionOutboundPreparationFailure(t, outbound)
}
