package core_test

import (
	"bytes"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	app_log "github.com/xtls/xray-core/app/log"
	app_policy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	app_router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	feature_routing "github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	hyproxy "github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	testingudp "github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	hytransport "github.com/xtls/xray-core/transport/internet/hysteria"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
)

const (
	hysteriaUDPFlowServerInboundTag  = "f2-hysteria-udp-inbound"
	hysteriaUDPFlowServerOutboundTag = "f2-hysteria-udp-direct"
	hysteriaUDPFlowServerRuleTag     = "f2-hysteria-udp-direct-rule"
	hysteriaUDPFlowClientInboundTag  = "f2-hysteria-udp-client-inbound"
	hysteriaUDPFlowClientOutboundTag = "f2-hysteria-udp-client-outbound"
)

func TestHysteriaUDPExternalOwnerEpochLifecycle(t *testing.T) {
	remote := startVLESSUDPFlowEcho(t)
	defer remote.Close()
	server, client, clientInbound, observer := startHysteriaUDPFlowCores(t, remote.LocalAddr().(*stdnet.UDPAddr))
	defer server.Close()
	defer client.Close()

	connection, err := stdnet.DialUDP("udp4", nil, clientInbound)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("f2-hysteria-udp-payload")
	for packet := 0; packet < 2; packet++ {
		writeAndReadHysteriaUDPEcho(t, connection, payload)
	}

	live := waitForHysteriaFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState != flow_observation.CompletionTerminal
	})
	first := live.Records[0]
	assertHysteriaUDPFlowRecord(t, first, false, uint64(2*len(payload)), remote.LocalAddr().String())

	terminal := waitForHysteriaFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal
	})
	assertHysteriaUDPFlowRecord(t, terminal.Records[0], true, uint64(2*len(payload)), remote.LocalAddr().String())

	writeAndReadHysteriaUDPEcho(t, connection, payload)
	recreated := waitForHysteriaFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		if len(snapshot.Records) != 2 {
			return false
		}
		oldTerminal := false
		newEpoch := false
		for _, record := range snapshot.Records {
			if record.FlowID == first.FlowID {
				oldTerminal = record.CompletionState == flow_observation.CompletionTerminal
			} else {
				newEpoch = true
			}
		}
		return oldTerminal && newEpoch
	})
	for _, record := range recreated.Records {
		if record.FlowID == first.FlowID {
			if record.CompletionState != flow_observation.CompletionTerminal {
				t.Fatalf("retired Hysteria owner root reopened: %+v", record)
			}
			continue
		}
		if record.CompletionState == flow_observation.CompletionIndeterminate {
			t.Fatalf("recreated Hysteria owner root became indeterminate: %+v", record)
		}
		assertHysteriaUDPFlowRecord(t, record, record.CompletionState == flow_observation.CompletionTerminal, uint64(len(payload)), remote.LocalAddr().String())
	}
}

func writeAndReadHysteriaUDPEcho(t testing.TB, connection *stdnet.UDPConn, payload []byte) {
	t.Helper()
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	n, err := connection.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || !bytes.Equal(response[:n], payload) {
		t.Fatalf("Hysteria UDP payload changed: got %q want %q", response[:n], payload)
	}
}

func waitForHysteriaFlowSnapshot(t testing.TB, observer flow_observation.Observer, predicate func(flow_observation.Snapshot) bool) flow_observation.Snapshot {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	var snapshot flow_observation.Snapshot
	for time.Now().Before(deadline) {
		snapshot = observer.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Hysteria flow snapshot did not reach required state: %+v", snapshot)
	return flow_observation.Snapshot{}
}

func assertHysteriaUDPFlowRecord(t testing.TB, record flow_observation.Record, terminal bool, uplinkBytes uint64, remote string) {
	t.Helper()
	expectedDestination := "udp:" + remote
	if record.FlowKind != flow_observation.KindUDPAssociation || record.OriginalDestination != expectedDestination || record.EffectiveDestination != expectedDestination || record.Route.MatchedNativeRuleTag != hysteriaUDPFlowServerRuleTag || record.Route.SelectedTopLevelOutboundTag != hysteriaUDPFlowServerOutboundTag {
		t.Fatalf("Hysteria UDP lost association identity or route: %+v", record)
	}
	if (record.CompletionState == flow_observation.CompletionTerminal) != terminal {
		t.Fatalf("Hysteria UDP terminal state = %s, want terminal=%t", record.CompletionState, terminal)
	}
	uplink, ok := unixExternalLinkObservation(record, flow_observation.DirectionUplink)
	if !ok || uplink.State != flow_observation.ByteObservationStateProven || uplink.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: uplinkBytes}) {
		t.Fatalf("Hysteria UDP uplink external-link bytes are not exact: %+v", uplink)
	}
	downlink, ok := unixExternalLinkObservation(record, flow_observation.DirectionDownlink)
	if !ok || downlink.State != flow_observation.ByteObservationStateIndeterminate || downlink.ObservedBytes.Known {
		t.Fatalf("Hysteria UDP downlink did not retain silent-drop uncertainty: %+v", downlink)
	}
	if terminal && (record.TerminalClass == "" || record.CompletionEvidence != flow_observation.CompletionEvidenceRootLogicalLinkQuiesced) {
		t.Fatalf("Hysteria UDP terminal state has no external-owner receipt: %+v", record)
	}
}

func startHysteriaUDPFlowCores(t testing.TB, remote *stdnet.UDPAddr) (*core.Instance, *core.Instance, *stdnet.UDPAddr, flow_observation.Observer) {
	t.Helper()
	const auth = "f2-hysteria-udp-auth"
	serverPort := testingudp.PickPort()
	clientPort := testingudp.PickPort()
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	serverCertificate := transporttls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true

	apps := func(rule *app_router.RoutingRule) []*serial.TypedMessage {
		return []*serial.TypedMessage{
			serial.ToTypedMessage(&app_log.Config{}),
			serial.ToTypedMessage(&app_policy.Config{Level: map[uint32]*app_policy.Policy{0: {Timeout: &app_policy.Policy_Timeout{ConnectionIdle: &app_policy.Second{Value: 30}}}}}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&app_router.Config{Rule: []*app_router.RoutingRule{rule}}),
		}
	}
	serverConfig := &core.Config{
		App: apps(&app_router.RoutingRule{InboundTag: []string{hysteriaUDPFlowServerInboundTag}, Networks: []net.Network{net.Network_UDP}, RuleTag: hysteriaUDPFlowServerRuleTag, TargetTag: &app_router.RoutingRule_Tag{Tag: hysteriaUDPFlowServerOutboundTag}}),
		Inbound: []*core.InboundHandlerConfig{{
			Tag: hysteriaUDPFlowServerInboundTag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: &internet.StreamConfig{
					ProtocolName:      "hysteria",
					TransportSettings: []*internet.TransportConfig{{ProtocolName: "hysteria", Settings: serial.ToTypedMessage(&hytransport.Config{Auth: auth, UdpIdleTimeout: 1})}},
					SecurityType:      serial.GetMessageType(&transporttls.Config{}),
					SecuritySettings:  []*serial.TypedMessage{serial.ToTypedMessage(&transporttls.Config{Certificate: []*transporttls.Certificate{serverCertificate}, NextProtocol: []string{"h3"}})},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&hyproxy.ServerConfig{Users: []*protocol.User{{Account: serial.ToTypedMessage(&hyaccount.Account{Auth: auth})}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{Tag: hysteriaUDPFlowServerOutboundTag, ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	server, err := core.New(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		server.Close()
		t.Fatal(err)
	}

	clientConfig := &core.Config{
		App: apps(&app_router.RoutingRule{InboundTag: []string{hysteriaUDPFlowClientInboundTag}, Networks: []net.Network{net.Network_UDP}, TargetTag: &app_router.RoutingRule_Tag{Tag: hysteriaUDPFlowClientOutboundTag}}),
		Inbound: []*core.InboundHandlerConfig{{
			Tag:              hysteriaUDPFlowClientInboundTag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}),
			ProxySettings:    serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(net.IPAddress(remote.IP)), RewritePort: uint32(remote.Port), AllowedNetworks: []net.Network{net.Network_UDP}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           hysteriaUDPFlowClientOutboundTag,
			ProxySettings: serial.ToTypedMessage(&hyproxy.ClientConfig{Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort), User: &protocol.User{Account: serial.ToTypedMessage(&hyaccount.Account{Auth: auth})}}}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
				ProtocolName:      "hysteria",
				TransportSettings: []*internet.TransportConfig{{ProtocolName: "hysteria", Settings: serial.ToTypedMessage(&hytransport.Config{Auth: auth, UdpIdleTimeout: 60})}},
				SecurityType:      serial.GetMessageType(&transporttls.Config{}),
				SecuritySettings:  []*serial.TypedMessage{serial.ToTypedMessage(&transporttls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{certificateHash[:]}, NextProtocol: []string{"h3"}})},
			}}),
		}},
	}
	client, err := core.New(clientConfig)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		client.Close()
		server.Close()
		t.Fatal(err)
	}
	dispatcherFeature := server.GetFeature(feature_routing.DispatcherType())
	provider, ok := dispatcherFeature.(flow_observation.Provider)
	if !ok || provider.FlowObserver() == nil {
		client.Close()
		server.Close()
		t.Fatalf("Hysteria UDP server dispatcher has no flow observer: %T", dispatcherFeature)
	}
	return server, client, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(clientPort)}, provider.FlowObserver()
}
