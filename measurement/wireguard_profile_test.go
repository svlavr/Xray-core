package measurement_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"testing"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	statsfeature "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/testing/servers/udp"
)

func TestWireGuardProtocolMeasurements(t *testing.T) {
	// gVisor rejects loopback addresses arriving through a tunnel NIC. The inner
	// target is non-loopback; native Freedom redirects only its address to the
	// real local fixture, preserving its port. No host interface/TUN is required.
	const target = "198.18.0.1"
	const target6 = "fd00::1"
	v := instance(t, serial.ToTypedMessage(&appdns.Config{}))
	m := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := m.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	var counters [2]statsfeature.Counter
	for i, tag := range []string{"exact", "second"} {
		key := func() (string, string) {
			k, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return hex.EncodeToString(k.Bytes()), hex.EncodeToString(k.PublicKey().Bytes())
		}
		serverPrivate, serverPublic := key()
		clientPrivate, clientPublic := key()
		clientIP := fmt.Sprintf("198.18.0.%d", i+2)
		clientIP6 := fmt.Sprintf("fd00::%d", i+2)
		port := udp.PickPort()
		peer, err := core.New(&core.Config{
			App: protocolPeerApps(),
			Inbound: []*core.InboundHandlerConfig{{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}}),
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient: false, NoKernelTun: true, Mtu: 1420, Endpoint: []string{target, target6}, SecretKey: serverPrivate,
					Users: []*protocol.User{{Email: tag, Account: serial.ToTypedMessage(&wireguard.PeerConfig{PublicKey: clientPublic, AllowedIps: []string{clientIP + "/32", clientIP6 + "/128"}})}},
				}),
			}},
			Outbound: []*core.OutboundHandlerConfig{{
				Tag: "peer-direct", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
				ProxySettings: serial.ToTypedMessage(&freedom.Config{DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP)}}, FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.Start(); err != nil {
			peer.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		counters[i] = addProtocolOutbound(t, v, &core.OutboundHandlerConfig{
			Tag: tag, SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				IsClient: true, NoKernelTun: true, Mtu: 1420, Endpoint: []string{clientIP, clientIP6}, SecretKey: clientPrivate,
				Peers: []*wireguard.PeerConfig{{PublicKey: serverPublic, Endpoint: net.JoinHostPort("127.0.0.1", port.String()), AllowedIps: []string{target + "/32", target6 + "/128"}}},
			}),
		})
	}
	e := executor(t, v)
	testProtocolMeasurementsAt(t, e, v, counters, target, true)
	limit, abovePeer := 8192, false
	if runtime.GOOS == "windows" {
		// The pinned native device receives 2016 wire bytes on Windows. With
		// MTU 1420, IPv4/UDP 28, WG 32 and native 16-byte padding, 1952 echoes fit;
		// 1953 reaches the endpoint, but its unfragmented raw reply is 2028 bytes.
		limit, abovePeer = 1952, true
	}
	testProtocolPacketBoundary(t, e, target, limit, abovePeer)
	if carrierDials == nil {
		t.Run("ipv6-inner", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				limit -= 20
			}
			testProtocolPacketBoundaryAt(t, e, target6, limit, abovePeer, "127.0.0.1")
		})
	}
}
