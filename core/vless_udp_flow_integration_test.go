package core_test

import (
	"bytes"
	"encoding/binary"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	app_log "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	app_router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	feature_routing "github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vless_encoding "github.com/xtls/xray-core/proxy/vless/encoding"
	vless_inbound "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

const (
	vlessUDPFlowInboundTag  = "f2-vless-udp-inbound"
	vlessUDPFlowOutboundTag = "f2-vless-udp-direct"
	vlessUDPFlowRuleTag     = "f2-vless-udp-direct-rule"
)

func TestVLESSUDPExternalOwnerFlow(t *testing.T) {
	remote := startVLESSUDPFlowEcho(t)
	defer remote.Close()
	userID := uuid.New()
	instance, inbound, observer := startVLESSUDPFlowCore(t, userID)
	defer instance.Close()

	connection, err := stdnet.DialTCP("tcp4", nil, inbound)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	account, err := (&vless.Account{Id: userID.String()}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		Version: vless_encoding.Version,
		User:    &protocol.MemoryUser{Account: account},
		Command: protocol.RequestCommandUDP,
		Address: net.IPAddress(remote.LocalAddr().(*stdnet.UDPAddr).IP),
		Port:    net.Port(remote.LocalAddr().(*stdnet.UDPAddr).Port),
	}
	if err := vless_encoding.EncodeRequestHeader(connection, request, &vless_encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("f2-vless-udp-payload")
	if err := writeVLESSUDPPacket(connection, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := vless_encoding.DecodeResponseHeader(connection, request); err != nil {
		t.Fatal(err)
	}
	response, err := readVLESSUDPPacket(connection)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("VLESS UDP payload changed: got %q want %q", response, payload)
	}

	live := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState != flow_observation.CompletionTerminal
	})
	expectedDestination := request.Destination().String()
	assertVLESSUDPFlowRecord(t, live.Records[0], false, uint64(len(payload)), expectedDestination)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	terminal := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal
	})
	assertVLESSUDPFlowRecord(t, terminal.Records[0], true, uint64(len(payload)), expectedDestination)
}

func TestVLESSUDPExternalOwnerOversizedDownlinkIsIndeterminate(t *testing.T) {
	remote := startVLESSUDPFlowEcho(t)
	defer remote.Close()
	userID := uuid.New()
	instance, inbound, observer := startVLESSUDPFlowCore(t, userID)
	defer instance.Close()
	connection, request := dialVLESSUDPFlow(t, inbound, remote.LocalAddr().(*stdnet.UDPAddr), userID)
	defer connection.Close()
	payload := bytes.Repeat([]byte{'x'}, buf.Size-1)
	if err := writeVLESSUDPPacket(connection, payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := vless_encoding.DecodeResponseHeader(connection, request); err == nil {
		t.Fatal("oversized VLESS UDP response header unexpectedly bypassed stock packet writer drop")
	}
	live := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1
	})
	for _, observation := range live.Records[0].ByteObservations {
		if observation.Direction == flow_observation.DirectionDownlink && observation.ByteScope == flow_observation.ByteScopeDispatcherExternalLinkIO {
			if observation.State != flow_observation.ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
				t.Fatalf("oversized VLESS UDP downlink fabricated proven bytes: %+v", observation)
			}
			return
		}
	}
	t.Fatalf("oversized VLESS UDP has no downlink external-link observation: %+v", live.Records[0])
}

func TestVLESSUDPExternalOwnerNegativeCommands(t *testing.T) {
	remote := startVLESSUDPFlowEcho(t)
	defer remote.Close()
	userID := uuid.New()
	instance, inbound, observer := startVLESSUDPFlowCore(t, userID)
	defer instance.Close()

	t.Run("xrv_udp", func(t *testing.T) {
		xrvInstance, xrvInbound, xrvObserver := startVLESSUDPFlowCoreWithFlow(t, userID, vless.XRV)
		defer xrvInstance.Close()
		connection, err := stdnet.DialTCP("tcp4", nil, xrvInbound)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		account, err := (&vless.Account{Id: userID.String(), Flow: vless.XRV}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		request := &protocol.RequestHeader{Version: vless_encoding.Version, User: &protocol.MemoryUser{Account: account}, Command: protocol.RequestCommandUDP, Address: net.IPAddress(remote.LocalAddr().(*stdnet.UDPAddr).IP), Port: net.Port(remote.LocalAddr().(*stdnet.UDPAddr).Port)}
		if err := vless_encoding.EncodeRequestHeader(connection, request, &vless_encoding.Addons{Flow: vless.XRV}); err != nil {
			t.Fatal(err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := vless_encoding.DecodeResponseHeader(connection, request); err == nil {
			t.Fatal("XRV UDP was accepted")
		}
		assertNoVLESSUDPAssociation(t, xrvObserver.Snapshot())
	})

	t.Run("tcp", func(t *testing.T) {
		connection, err := stdnet.DialTCP("tcp4", nil, inbound)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		account, err := (&vless.Account{Id: userID.String()}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		request := &protocol.RequestHeader{Version: vless_encoding.Version, User: &protocol.MemoryUser{Account: account}, Command: protocol.RequestCommandTCP, Address: net.IPAddress(remote.LocalAddr().(*stdnet.UDPAddr).IP), Port: net.Port(remote.LocalAddr().(*stdnet.UDPAddr).Port)}
		if err := vless_encoding.EncodeRequestHeader(connection, request, &vless_encoding.Addons{}); err != nil {
			t.Fatal(err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := vless_encoding.DecodeResponseHeader(connection, request); err == nil {
			t.Fatal("non-UDP VLESS request unexpectedly returned a packet response header")
		}
		waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool { return len(snapshot.Records) == 1 })
		assertNoVLESSUDPAssociation(t, observer.Snapshot())
	})
}

func startVLESSUDPFlowEcho(t testing.TB) *stdnet.UDPConn {
	t.Helper()
	connection, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		payload := make([]byte, 64*1024)
		for {
			n, peer, err := connection.ReadFromUDP(payload)
			if err != nil {
				return
			}
			_, _ = connection.WriteToUDP(payload[:n], peer)
		}
	}()
	return connection
}

func dialVLESSUDPFlow(t testing.TB, inbound *stdnet.TCPAddr, remote *stdnet.UDPAddr, userID uuid.UUID) (*stdnet.TCPConn, *protocol.RequestHeader) {
	t.Helper()
	connection, err := stdnet.DialTCP("tcp4", nil, inbound)
	if err != nil {
		t.Fatal(err)
	}
	account, err := (&vless.Account{Id: userID.String()}).AsAccount()
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{Version: vless_encoding.Version, User: &protocol.MemoryUser{Account: account}, Command: protocol.RequestCommandUDP, Address: net.IPAddress(remote.IP), Port: net.Port(remote.Port)}
	if err := vless_encoding.EncodeRequestHeader(connection, request, &vless_encoding.Addons{}); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection, request
}

func startVLESSUDPFlowCore(t testing.TB, userID uuid.UUID) (*core.Instance, *stdnet.TCPAddr, flow_observation.Observer) {
	return startVLESSUDPFlowCoreWithFlow(t, userID, "")
}

func startVLESSUDPFlowCoreWithFlow(t testing.TB, userID uuid.UUID, userFlow string) (*core.Instance, *stdnet.TCPAddr, flow_observation.Observer) {
	t.Helper()
	inboundPort := tcp.PickPort()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&app_log.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&app_router.Config{Rule: []*app_router.RoutingRule{{
				InboundTag: []string{vlessUDPFlowInboundTag},
				Networks:   []net.Network{net.Network_UDP},
				RuleTag:    vlessUDPFlowRuleTag,
				TargetTag:  &app_router.RoutingRule_Tag{Tag: vlessUDPFlowOutboundTag},
			}}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: vlessUDPFlowInboundTag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(inboundPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&vless_inbound.Config{Users: []*protocol.User{{
				Account: serial.ToTypedMessage(&vless.Account{Id: userID.String(), Flow: userFlow}),
			}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: vlessUDPFlowOutboundTag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
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
		t.Fatalf("VLESS UDP dispatcher has no flow observer: %T", dispatcherFeature)
	}
	return instance, &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(inboundPort)}, provider.FlowObserver()
}

func writeVLESSUDPPacket(writer io.Writer, payload []byte) error {
	if len(payload) > 0xffff {
		return io.ErrShortBuffer
	}
	packet := make([]byte, len(payload)+2)
	binary.BigEndian.PutUint16(packet, uint16(len(payload)))
	copy(packet[2:], payload)
	written, err := writer.Write(packet)
	if err != nil {
		return err
	}
	if written != len(packet) {
		return io.ErrShortWrite
	}
	return nil
}

func readVLESSUDPPacket(reader io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint16(size[:]))
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func assertVLESSUDPFlowRecord(t testing.TB, record flow_observation.Record, terminal bool, payloadBytes uint64, destination string) {
	t.Helper()
	if record.FlowKind != flow_observation.KindUDPAssociation || record.OriginalDestination != destination || record.EffectiveDestination != destination || record.Route.MatchedNativeRuleTag != vlessUDPFlowRuleTag || record.Route.SelectedTopLevelOutboundTag != vlessUDPFlowOutboundTag || record.Route.SelectedHandlerType != "*outbound.Handler" {
		t.Fatalf("VLESS UDP flow lost identity or route: %+v", record)
	}
	if record.Protocol != "" {
		t.Fatalf("VLESS UDP protocol fact was unexpectedly inferred: %+v", record)
	}
	if len(record.ByteObservations) != 2 {
		t.Fatalf("VLESS UDP has unexpected byte cells: %+v", record.ByteObservations)
	}
	if (record.CompletionState == flow_observation.CompletionTerminal) != terminal {
		t.Fatalf("VLESS UDP terminal state = %s, want terminal=%t", record.CompletionState, terminal)
	}
	for _, direction := range []flow_observation.Direction{flow_observation.DirectionUplink, flow_observation.DirectionDownlink} {
		observation, ok := unixExternalLinkObservation(record, direction)
		if !ok || observation.State != flow_observation.ByteObservationStateProven || observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: payloadBytes}) {
			t.Fatalf("VLESS UDP %s external-link payload bytes are not exact: %+v", direction, observation)
		}
	}
}

func assertNoVLESSUDPAssociation(t testing.TB, snapshot flow_observation.Snapshot) {
	t.Helper()
	for _, record := range snapshot.Records {
		if record.FlowKind == flow_observation.KindUDPAssociation {
			t.Fatalf("non-ordinary VLESS UDP path created UDP association: %+v", record)
		}
	}
}
