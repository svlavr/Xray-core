package core_test

import (
	"bytes"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	app_log "github.com/xtls/xray-core/app/log"
	app_policy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	app_router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	feature_routing "github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/testing/servers/udp"
)

const (
	dokodemoUDPFlowInboundTag  = "f2-dokodemo-udp-inbound"
	dokodemoUDPFlowOutboundTag = "f2-dokodemo-udp-direct"
	dokodemoUDPFlowRuleTag     = "f2-dokodemo-udp-direct-rule"
)

func TestDokodemoUDPExternalOwnerFlow(t *testing.T) {
	remote := startVLESSUDPFlowEcho(t)
	defer remote.Close()
	instance, inbound, observer := startDokodemoUDPFlowCore(t, remote.LocalAddr().(*stdnet.UDPAddr), 1)

	client, err := stdnet.DialUDP("udp4", nil, inbound)
	if err != nil {
		instance.Close()
		t.Fatal(err)
	}
	defer client.Close()
	payload := []byte("f2-dokodemo-udp-payload")
	for packet := 0; packet < 2; packet++ {
		if _, err := client.Write(payload); err != nil {
			instance.Close()
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		n, err := client.Read(response)
		if err != nil {
			instance.Close()
			t.Fatal(err)
		}
		if n != len(payload) || !bytes.Equal(response[:n], payload) {
			instance.Close()
			t.Fatalf("dokodemo UDP packet %d changed: got %q want %q", packet, response[:n], payload)
		}
	}

	live := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1
	})
	record := live.Records[0]
	if record.FlowKind != flow_observation.KindUDPAssociation || record.OriginalDestination != "udp:"+remote.LocalAddr().String() || record.EffectiveDestination != "udp:"+remote.LocalAddr().String() || record.Route.MatchedNativeRuleTag != dokodemoUDPFlowRuleTag || record.Route.SelectedTopLevelOutboundTag != dokodemoUDPFlowOutboundTag {
		instance.Close()
		t.Fatalf("dokodemo UDP lost association identity or route: %+v", record)
	}
	if record.CompletionState == flow_observation.CompletionTerminal {
		instance.Close()
		t.Fatalf("dokodemo UDP terminalized before exact owner close: %+v", record)
	}
	for _, observation := range record.ByteObservations {
		if observation.ByteScope != flow_observation.ByteScopeDispatcherExternalLinkIO {
			continue
		}
		switch observation.Direction {
		case flow_observation.DirectionUplink:
			if observation.State != flow_observation.ByteObservationStateProven || observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: uint64(2 * len(payload))}) {
				instance.Close()
				t.Fatalf("dokodemo UDP uplink was not exact: %+v", observation)
			}
		case flow_observation.DirectionDownlink:
			if observation.State != flow_observation.ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
				instance.Close()
				t.Fatalf("dokodemo UDP downlink fabricated numeric success: %+v", observation)
			}
		}
	}
	terminal := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal
	})
	if terminal.Records[0].TerminalClass == "" || terminal.Records[0].CompletionEvidence != flow_observation.CompletionEvidenceRootLogicalLinkQuiesced {
		instance.Close()
		t.Fatalf("dokodemo UDP terminal state has no owner receipt: %+v", terminal.Records[0])
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDokodemoUDPInstanceShutdownWaitsForExternalOwnerReceipt(t *testing.T) {
	remote := startVLESSUDPFlowEcho(t)
	defer remote.Close()
	instance, inbound, observer := startDokodemoUDPFlowCore(t, remote.LocalAddr().(*stdnet.UDPAddr), 300)
	client, err := stdnet.DialUDP("udp4", nil, inbound)
	if err != nil {
		instance.Close()
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("f2-dokodemo-udp-stop")); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	response := make([]byte, len("f2-dokodemo-udp-stop"))
	if _, err := client.Read(response); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState != flow_observation.CompletionTerminal
	})
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	terminal := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal
	})
	if terminal.Records[0].CompletionEvidence != flow_observation.CompletionEvidenceRootLogicalLinkQuiesced {
		t.Fatalf("instance shutdown lost the external owner receipt: %+v", terminal.Records[0])
	}
}

func startDokodemoUDPFlowCore(t testing.TB, remote *stdnet.UDPAddr, connectionIdle uint32) (*core.Instance, *stdnet.UDPAddr, flow_observation.Observer) {
	t.Helper()
	inboundPort := udp.PickPort()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&app_log.Config{}), serial.ToTypedMessage(&app_policy.Config{Level: map[uint32]*app_policy.Policy{0: {Timeout: &app_policy.Policy_Timeout{ConnectionIdle: &app_policy.Second{Value: connectionIdle}}}}}), serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&app_router.Config{Rule: []*app_router.RoutingRule{{InboundTag: []string{dokodemoUDPFlowInboundTag}, Networks: []net.Network{net.Network_UDP}, RuleTag: dokodemoUDPFlowRuleTag, TargetTag: &app_router.RoutingRule_Tag{Tag: dokodemoUDPFlowOutboundTag}}}}),
		},
		Inbound:  []*core.InboundHandlerConfig{{Tag: dokodemoUDPFlowInboundTag, ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(inboundPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(net.IPAddress(remote.IP)), RewritePort: uint32(remote.Port), AllowedNetworks: []net.Network{net.Network_UDP}})}},
		Outbound: []*core.OutboundHandlerConfig{{Tag: dokodemoUDPFlowOutboundTag, ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	dispatcherFeature := instance.GetFeature(feature_routing.DispatcherType())
	provider, ok := dispatcherFeature.(flow_observation.Provider)
	if !ok || provider.FlowObserver() == nil {
		instance.Close()
		t.Fatalf("dokodemo UDP dispatcher has no flow observer: %T", dispatcherFeature)
	}
	return instance, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(inboundPort)}, provider.FlowObserver()
}
