package core_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/wireguard"
	testtcp "github.com/xtls/xray-core/testing/servers/tcp"
	testudp "github.com/xtls/xray-core/testing/servers/udp"
	"golang.org/x/crypto/curve25519"
)

const (
	inspectionWireGuardServerIP = "10.231.77.1"
	inspectionWireGuardClientIP = "10.231.77.2"
)

func inspectionWireGuardKey(t *testing.T) (string, string) {
	t.Helper()
	var private, public [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&public, &private)
	return hex.EncodeToString(private[:]), hex.EncodeToString(public[:])
}

func inspectionWireGuardApps() []*serial.TypedMessage {
	return []*serial.TypedMessage{
		serial.ToTypedMessage(&appstats.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&router.Config{}),
	}
}

func inspectionWireGuardPair(t *testing.T, enabled bool) (*core.Instance, fs.FlowInspection, string, *core.Instance, fs.FlowInspection) {
	t.Helper()
	serverPrivate, serverPublic := inspectionWireGuardKey(t)
	clientPrivate, clientPublic := inspectionWireGuardKey(t)
	physicalPort := testudp.PickPort()

	server, err := core.New(&core.Config{
		App: inspectionWireGuardApps(),
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "wireguard-server",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(physicalPort)}},
			}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				SecretKey:   serverPrivate,
				Endpoint:    []string{inspectionWireGuardServerIP},
				Mtu:         1420,
				IsClient:    false,
				NoKernelTun: true,
				Users: []*protocol.User{{
					Email: "wireguard-client",
					Account: serial.ToTypedMessage(&wireguard.PeerConfig{
						PublicKey:  clientPublic,
						AllowedIps: []string{inspectionWireGuardClientIP + "/32"},
					}),
				}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "wireguard-server-direct",
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
					Address: cnet.NewIPOrDomain(cnet.LocalHostIP),
				}},
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	var serverView fs.FlowInspection
	if enabled {
		serverView, err = core.EnableFlowInspection(server, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}

	clientPort := testtcp.PickPort()
	client, err := core.New(&core.Config{
		App: inspectionWireGuardApps(),
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "wireguard-client-socks",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(clientPort)}},
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UdpEnabled: true}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:            "wireguard-client",
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				SecretKey:   clientPrivate,
				Endpoint:    []string{inspectionWireGuardClientIP},
				Mtu:         1420,
				IsClient:    true,
				NoKernelTun: true,
				DNS:         []string{"127.0.0.1"},
				Peers: []*wireguard.PeerConfig{{
					PublicKey:  serverPublic,
					Endpoint:   net.JoinHostPort("127.0.0.1", physicalPort.String()),
					AllowedIps: []string{"0.0.0.0/0"},
				}},
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	var clientView fs.FlowInspection
	if enabled {
		clientView, err = core.EnableFlowInspection(client, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	return client, clientView, net.JoinHostPort("127.0.0.1", clientPort.String()), server, serverView
}

func inspectionWireGuardRow(t *testing.T, view fs.FlowInspection, kind fs.FlowKind, uplink, downlink uint64) fs.FlowRecord {
	t.Helper()
	var found fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range live.Rows {
			if row.Kind != kind || row.Uplink.Known != uplink || row.Downlink.Known != downlink {
				continue
			}
			if row.Uplink.Incomplete || row.Downlink.Incomplete {
				return false
			}
			found = row
			return true
		}
		return false
	})
	return found
}

func inspectionWireGuardAssertRow(t *testing.T, row fs.FlowRecord, initial cnet.Destination, outbound string, effective cnet.Destination) {
	t.Helper()
	if row.Origin != fs.TrafficOriginUser || row.InitialDestination != initial || row.AccountingRoute.Outbound.Tag != outbound || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != effective || row.Uplink.Incomplete || row.Downlink.Incomplete {
		t.Fatalf("WireGuard logical facts: %+v", row)
	}
	if row.Kind == fs.FlowKindUDPAssociation && initial.IsValid() && (len(row.Destinations) != 1 || row.Destinations[0] != initial) {
		t.Fatalf("WireGuard UDP destinations: %+v", row)
	}
}

func inspectionWireGuardStop(t *testing.T, view fs.FlowInspection, ref fs.FlowRef) {
	t.Helper()
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("WireGuard exact stop: %+v %v", outcomes, err)
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Rows {
			if row.Flow.Ref == ref {
				if row.Reason != fs.EndReasonLocalStop {
					t.Fatalf("WireGuard stopped terminal: %+v", row)
				}
				return true
			}
		}
		return false
	})
}

func TestFlowInspectionWireGuardDisabled(t *testing.T) {
	client, _, address, server, _ := inspectionWireGuardPair(t, false)
	tcpDestination := startOutboundStatsTCPServer(t)
	virtualTCP := cnet.TCPDestination(cnet.ParseAddress(inspectionWireGuardServerIP), tcpDestination.Port)
	inspectionSOCKS(t, address, virtualTCP, []byte("disabled WireGuard TCP")).Close()

	const mask = byte(0x2d)
	udpDestination := startOutboundStatsUDPServer(t, mask)
	virtualUDP := cnet.UDPDestination(cnet.ParseAddress(inspectionWireGuardServerIP), udpDestination.Port)
	control, packet, relay := inspectionSOCKSAssociation(t, address)
	inspectionSOCKSPacket(t, packet, relay, virtualUDP, []byte("disabled WireGuard UDP"), mask)
	control.Close()

	for name, instance := range map[string]*core.Instance{"client": client, "server": server} {
		if provider := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider); provider.Observation() != nil {
			t.Fatalf("disabled WireGuard %s allocated inspection state", name)
		}
	}
}

func TestFlowInspectionWireGuardTCPUDP(t *testing.T) {
	_, clientView, address, _, serverView := inspectionWireGuardPair(t, true)
	tcpDestination := startOutboundStatsTCPServer(t)
	virtualTCP := cnet.TCPDestination(cnet.ParseAddress(inspectionWireGuardServerIP), tcpDestination.Port)
	firstPayload := append([]byte("first WireGuard TCP "), bytes.Repeat([]byte("a"), 4096)...)
	siblingPayload := append([]byte("sibling WireGuard TCP "), bytes.Repeat([]byte("b"), 2048)...)
	first := inspectionSOCKS(t, address, virtualTCP, firstPayload)
	sibling := inspectionSOCKS(t, address, virtualTCP, siblingPayload)

	clientFirst := inspectionWireGuardRow(t, clientView, fs.FlowKindTCP, uint64(len(firstPayload)), uint64(len(firstPayload)))
	clientSibling := inspectionWireGuardRow(t, clientView, fs.FlowKindTCP, uint64(len(siblingPayload)), uint64(len(siblingPayload)))
	inspectionWireGuardAssertRow(t, clientFirst, virtualTCP, "wireguard-client", virtualTCP)
	inspectionWireGuardAssertRow(t, clientSibling, virtualTCP, "wireguard-client", virtualTCP)
	serverFirst := inspectionWireGuardRow(t, serverView, fs.FlowKindTCP, uint64(len(firstPayload)), uint64(len(firstPayload)))
	serverSibling := inspectionWireGuardRow(t, serverView, fs.FlowKindTCP, uint64(len(siblingPayload)), uint64(len(siblingPayload)))
	inspectionWireGuardAssertRow(t, serverFirst, virtualTCP, "wireguard-server-direct", tcpDestination)
	inspectionWireGuardAssertRow(t, serverSibling, virtualTCP, "wireguard-server-direct", tcpDestination)
	if serverFirst.Source.Address != cnet.ParseAddress(inspectionWireGuardClientIP) || serverSibling.Source.Address != cnet.ParseAddress(inspectionWireGuardClientIP) {
		t.Fatalf("WireGuard virtual sources: %v %v", serverFirst.Source, serverSibling.Source)
	}

	inspectionWireGuardStop(t, clientView, clientFirst.Ref)
	if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("stopped WireGuard client endpoint returned %d, %v", n, err)
	}
	tcpExtra := []byte("TCP sibling survives client exact stop")
	if _, err := sibling.Write(tcpExtra); err != nil {
		t.Fatal(err)
	}
	inspectionResponse(t, sibling, tcpExtra)

	const mask = byte(0x6b)
	udpDestination := startOutboundStatsUDPServer(t, mask)
	virtualUDP := cnet.UDPDestination(cnet.ParseAddress(inspectionWireGuardServerIP), udpDestination.Port)
	control, packet, relay := inspectionSOCKSAssociation(t, address)
	udpPayload := []byte("WireGuard UDP virtual association")
	inspectionSOCKSPacket(t, packet, relay, virtualUDP, udpPayload, mask)
	clientUDP := inspectionWireGuardRow(t, clientView, fs.FlowKindUDPAssociation, uint64(len(udpPayload)), uint64(len(udpPayload)))
	serverUDP := inspectionWireGuardRow(t, serverView, fs.FlowKindUDPAssociation, uint64(len(udpPayload)), uint64(len(udpPayload)))
	// SOCKS admits the UDP association before its first packet; the original
	// destination is unavailable, while the packet destination is recorded.
	inspectionWireGuardAssertRow(t, clientUDP, cnet.Destination{}, "wireguard-client", virtualUDP)
	if len(clientUDP.Destinations) != 1 || clientUDP.Destinations[0] != virtualUDP {
		t.Fatalf("WireGuard client UDP destinations: %+v", clientUDP)
	}
	inspectionWireGuardAssertRow(t, serverUDP, virtualUDP, "wireguard-server-direct", udpDestination)
	if serverUDP.Source.Address != cnet.ParseAddress(inspectionWireGuardClientIP) {
		t.Fatalf("WireGuard UDP virtual source: %v", serverUDP.Source)
	}

	inspectionWireGuardStop(t, serverView, serverUDP.Ref)
	replacementPayload := []byte("WireGuard UDP after server exact stop")
	inspectionSOCKSPacket(t, packet, relay, virtualUDP, replacementPayload, mask)
	replacement := inspectionWireGuardRow(t, serverView, fs.FlowKindUDPAssociation, uint64(len(replacementPayload)), uint64(len(replacementPayload)))
	inspectionWireGuardAssertRow(t, replacement, virtualUDP, "wireguard-server-direct", udpDestination)
	if replacement.Ref == serverUDP.Ref {
		t.Fatal("stopped WireGuard UDP owner was reused")
	}

	tcpExtraAfterServerStop := []byte("TCP sibling survives server UDP stop")
	if _, err := sibling.Write(tcpExtraAfterServerStop); err != nil {
		t.Fatal(err)
	}
	inspectionResponse(t, sibling, tcpExtraAfterServerStop)

	want := uint64(len(firstPayload) + len(siblingPayload) + len(tcpExtra) + len(udpPayload) + len(replacementPayload) + len(tcpExtraAfterServerStop))
	inspectionOutboundTotals(t, clientView, "wireguard-client", want)
	inspectionOutboundTotals(t, serverView, "wireguard-server-direct", want)
	control.Close()
	sibling.Close()
}
