package core_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	proxyhysteria "github.com/xtls/xray-core/proxy/hysteria"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	vless "github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	vmess "github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessout "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	transporthysteria "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func inspectionVMessConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	_, _, outbound := inspectionVMessReceiver(t, false, false)
	return outbound
}

func inspectionVMessReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	return inspectionVMessReceiverSecurity(t, enabled, sniff, protocol.SecurityType_AES128_GCM)
}

func inspectionVMessReceiverSecurity(t *testing.T, enabled, sniff bool, security protocol.SecurityType) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	port := tcp.PickPort()
	id := protocol.NewID(uuid.New())
	serverUser := &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{Id: id.String()})}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen: cnet.NewIPOrDomain(cnet.LocalHostIP), PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http", "quic"}},
		}),
		ProxySettings: serial.ToTypedMessage(&vmessin.Config{User: []*protocol.User{serverUser}}),
	}); err != nil {
		t.Fatal(err)
	}
	clientUser := &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{
		Id: id.String(), SecuritySettings: &protocol.SecurityConfig{Type: security},
	})}
	outbound := &core.OutboundHandlerConfig{Tag: "vmess-proxy", ProxySettings: serial.ToTypedMessage(&vmessout.Config{
		Receiver: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(port), User: clientUser},
	})}
	return remote, view, outbound
}

func inspectionVLESSConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	_, _, outbound := inspectionVLESSReceiver(t, false, false)
	return outbound
}

func inspectionVLESSReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	return inspectionVLESSReceiverSettings(t, enabled, sniff, 0, 0)
}

func inspectionVLESSEncryptedReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	return inspectionVLESSReceiverSettings(t, enabled, sniff, 2, 120)
}

func inspectionVLESSReceiverSettings(t *testing.T, enabled, sniff bool, xorMode, seconds uint32) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	port := tcp.PickPort()
	id := protocol.NewID(uuid.New())
	serverAccount := &vless.Account{Id: id.String()}
	clientAccount := &vless.Account{Id: id.String()}
	inboundConfig := &vlessin.Config{}
	if seconds != 0 || xorMode != 0 {
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		inboundConfig.Decryption = base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
		inboundConfig.XorMode = xorMode
		inboundConfig.SecondsFrom = int64(seconds)
		inboundConfig.SecondsTo = int64(seconds)
		clientAccount.Encryption = base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
		clientAccount.XorMode = xorMode
		clientAccount.Seconds = seconds
	}
	serverUser := &protocol.User{Account: serial.ToTypedMessage(serverAccount)}
	inboundConfig.Users = []*protocol.User{serverUser}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen: cnet.NewIPOrDomain(cnet.LocalHostIP), PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http"}},
		}),
		ProxySettings: serial.ToTypedMessage(inboundConfig),
	}); err != nil {
		t.Fatal(err)
	}
	clientUser := &protocol.User{Account: serial.ToTypedMessage(clientAccount)}
	outbound := &core.OutboundHandlerConfig{Tag: "vless-proxy", ProxySettings: serial.ToTypedMessage(&vlessout.Config{
		Vnext: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(port), User: clientUser},
	})}
	return remote, view, outbound
}

func inspectionVLESSResponseServer(t *testing.T, response []byte, reset bool) (*core.OutboundHandlerConfig, <-chan error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		requestPrefix := make([]byte, 18)
		if _, err = io.ReadFull(conn, requestPrefix); err != nil {
			done <- err
			return
		}
		if reset && len(response) == 0 {
			if err = conn.SetLinger(0); err != nil {
				done <- err
				return
			}
			done <- conn.Close()
			return
		}
		_, err = conn.Write(response)
		if err == nil && reset {
			if err = conn.SetLinger(0); err == nil {
				err = conn.Close()
			}
			done <- err
			return
		}
		if err == nil {
			err = conn.CloseWrite()
		}
		done <- err
		if err == nil {
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	id := protocol.NewID(uuid.New())
	account := &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id.String()})}
	return &core.OutboundHandlerConfig{Tag: "vless-proxy", ProxySettings: serial.ToTypedMessage(&vlessout.Config{
		Vnext: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(listener.Addr().(*net.TCPAddr).Port), User: account},
	})}, done
}

func inspectionHysteriaConfig(t *testing.T) *core.OutboundHandlerConfig {
	t.Helper()
	_, _, outbound := inspectionHysteriaReceiver(t, false, false)
	return outbound
}

func inspectionHysteriaReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	port := udp.PickPort()
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	user := &protocol.User{Account: serial.ToTypedMessage(&hysteriaaccount.Account{Auth: "inspection-test-only"})}
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverStream := &internet.StreamConfig{
		ProtocolName: "hysteria",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "hysteria", Settings: serial.ToTypedMessage(&transporthysteria.Config{}),
		}},
		SecurityType:     serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{Certificate: []*tls.Certificate{serverCertificate}})},
		QuicParams:       &internet.QuicParams{DisableChromeParrot: true, DisableStatelessReset: true},
	}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen: cnet.NewIPOrDomain(cnet.LocalHostIP), PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}}, StreamSettings: serverStream,
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http"}},
		}),
		ProxySettings: serial.ToTypedMessage(&proxyhysteria.ServerConfig{Users: []*protocol.User{user}}),
	}); err != nil {
		t.Fatal(err)
	}
	clientStream := &internet.StreamConfig{
		ProtocolName: "hysteria",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "hysteria", Settings: serial.ToTypedMessage(&transporthysteria.Config{Auth: "inspection-test-only"}),
		}},
		SecurityType:     serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}})},
		QuicParams:       &internet.QuicParams{DisableChromeParrot: true, DisableStatelessReset: true},
	}
	outbound := &core.OutboundHandlerConfig{
		Tag: "hysteria-proxy",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			StreamSettings: clientStream,
		}),
		ProxySettings: serial.ToTypedMessage(&proxyhysteria.ClientConfig{Server: &protocol.ServerEndpoint{
			Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(port), User: user,
		}}),
	}
	return remote, view, outbound
}

func TestFlowInspectionP2AVMessOutbound(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	t.Run("TCP", func(t *testing.T) { inspectionOutboundTCP(t, inspectionVMessConfig) })
	t.Run("UDP", func(t *testing.T) { inspectionOutboundUDP(t, inspectionVMessConfig) })
	t.Run("dial-failure", func(t *testing.T) {
		outbound := inspectionVMessConfig(t)
		message, err := outbound.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		config := message.(*vmessout.Config)
		config.Receiver.Port = uint32(tcp.PickPort())
		outbound.ProxySettings = serial.ToTypedMessage(config)
		inspectionOutboundPreparationFailure(t, outbound)
	})
}

func TestFlowInspectionP2AVLESSOutbound(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	t.Run("TCP", func(t *testing.T) { inspectionOutboundTCP(t, inspectionVLESSConfig) })
	t.Run("UDP", func(t *testing.T) { inspectionOutboundUDP(t, inspectionVLESSConfig) })
	t.Run("dial-failure", func(t *testing.T) {
		outbound := inspectionVLESSConfig(t)
		message, err := outbound.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		config := message.(*vlessout.Config)
		config.Vnext.Port = uint32(tcp.PickPort())
		outbound.ProxySettings = serial.ToTypedMessage(config)
		inspectionOutboundPreparationFailure(t, outbound)
	})
}

func TestFlowInspectionP2GVLESSResponseEnding(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		reset    bool
		want     fs.EndReason
	}{
		{name: "natural-EOF", response: []byte{0, 0}, want: fs.EndReasonEOF},
		{name: "body-reset", response: []byte{0, 0}, reset: true, want: fs.EndReasonReadError},
		{name: "truncated-header", response: []byte{0}, want: fs.EndReasonReadError},
		{name: "reset-header", reset: true, want: fs.EndReasonReadError},
	} {
		t.Run(test.name, func(t *testing.T) {
			outbound, serverDone := inspectionVLESSResponseServer(t, test.response, test.reset)
			_, view, address := inspectionTCPOutboundThrough(t, true, outbound)
			client := inspectionSOCKS(t, address, cnet.TCPDestination(cnet.LocalHostIP, 80), nil)
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			if tcpClient, ok := client.(*net.TCPConn); ok {
				_ = tcpClient.CloseWrite()
			}
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _ = client.Read(make([]byte, 1))
			inspectionWait(t, func() bool {
				page, err := view.ReadTerminals(context.Background())
				if err != nil || len(page.Rows) != 1 {
					return false
				}
				row := page.Rows[0]
				if row.Flow.AccountingRoute.Outbound.Tag != outbound.Tag || row.Flow.AccountingRoute.Outbound.Serial == 0 || row.Flow.Downlink.Known != 0 {
					t.Fatalf("response ending facts: %+v", row)
				}
				if row.Reason != test.want {
					t.Fatalf("response end reason = %v, want %v", row.Reason, test.want)
				}
				return true
			})
		})
	}
}

func TestFlowInspectionP2AHysteriaOutbound(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "TCP-disabled"
		if enabled {
			name = "TCP-enabled"
		}
		t.Run(name, func(t *testing.T) {
			outbound := inspectionHysteriaConfig(t)
			instance, view, address := inspectionTCPOutboundThrough(t, enabled, outbound)
			destination := startOutboundStatsTCPServer(t)
			payload := []byte("Hysteria TCP payload")
			client := inspectionSOCKS(t, address, destination, payload)
			if !enabled {
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled Hysteria TCP acquired inspection state")
				}
				return
			}
			var row fs.FlowRecord
			inspectionWait(t, func() bool {
				live, err := view.ReadLive(context.Background())
				if err != nil || len(live.Rows) != 1 || live.Rows[0].Uplink.Known != uint64(len(payload)) || live.Rows[0].Downlink.Known != uint64(len(payload)) {
					return false
				}
				row = live.Rows[0]
				return true
			})
			if row.AccountingRoute.Outbound.Tag != outbound.Tag || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != destination || row.Uplink.Incomplete || row.Downlink.Incomplete {
				t.Fatalf("Hysteria TCP facts: %+v", row)
			}
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
			if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("Hysteria TCP exact stop: %+v %v", outcomes, err)
			}
			if n, err := client.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("stopped Hysteria TCP endpoint returned %d, %v", n, err)
			}
		})
	}
	t.Run("UDP-disabled", func(t *testing.T) {
		const mask = byte(0x2d)
		destination := startOutboundStatsUDPServer(t, mask)
		instance, _, address := inspectionUDPInboundThrough(t, destination, false, false, inspectionHysteriaConfig(t))
		inspectionUDPExchange(t, inspectionUDPClient(t), address, []byte("disabled Hysteria UDP"), mask)
		if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
			t.Fatal("disabled Hysteria UDP acquired inspection state")
		}
	})
	t.Run("UDP-stop-sibling", func(t *testing.T) {
		const mask = byte(0x31)
		destination := startOutboundStatsUDPServer(t, mask)
		outbound := inspectionHysteriaConfig(t)
		_, view, address := inspectionUDPInboundThrough(t, destination, true, false, outbound)
		first, sibling := inspectionUDPClient(t), inspectionUDPClient(t)
		payload := []byte("Hysteria UDP payload")
		inspectionUDPExchange(t, first, address, payload, mask)
		inspectionUDPExchange(t, sibling, address, payload, mask)
		var firstRow, siblingRow fs.FlowRecord
		inspectionWait(t, func() bool {
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 2 {
				return false
			}
			for _, row := range live.Rows {
				if row.Uplink.Known != uint64(len(payload)) || row.Downlink.Known != uint64(len(payload)) {
					return false
				}
				if row.AccountingRoute.Outbound.Tag != outbound.Tag || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != destination || row.Uplink.Incomplete || row.Downlink.Incomplete {
					t.Fatalf("Hysteria UDP facts: %+v", row)
				}
				switch row.Source.Port {
				case cnet.Port(first.LocalAddr().(*net.UDPAddr).Port):
					firstRow = row
				case cnet.Port(sibling.LocalAddr().(*net.UDPAddr).Port):
					siblingRow = row
				}
			}
			return firstRow.Ref.ID != 0 && siblingRow.Ref.ID != 0
		})
		outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{firstRow.Ref})
		if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("Hysteria UDP exact stop: %+v %v", outcomes, err)
		}
		extra := []byte("sibling after exact stop")
		inspectionUDPExchange(t, sibling, address, extra, mask)
		inspectionWait(t, func() bool {
			live, _ := view.ReadLive(context.Background())
			return len(live.Rows) == 1 && live.Rows[0].Ref == siblingRow.Ref && live.Rows[0].Uplink.Known == uint64(len(payload)+len(extra)) && live.Rows[0].Downlink.Known == uint64(len(payload)+len(extra))
		})
		outcomes, err = view.CloseFlows(context.Background(), []fs.FlowRef{siblingRow.Ref})
		if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("Hysteria UDP sibling close: %+v %v", outcomes, err)
		}
		inspectionOutboundTotals(t, view, outbound.Tag, uint64(2*len(payload)+len(extra)))
	})
	t.Run("UDP-fragmented", func(t *testing.T) {
		const mask = byte(0x2d)
		destination := startOutboundStatsUDPServer(t, mask)
		outbound := inspectionHysteriaConfig(t)
		_, view, address := inspectionUDPInboundThrough(t, destination, true, false, outbound)
		client := inspectionUDPClient(t)
		payload := bytes.Repeat([]byte("hysteria-fragment"), 240)
		inspectionUDPExchange(t, client, address, payload, mask)
		var row fs.FlowRecord
		inspectionWait(t, func() bool {
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) != 1 || live.Rows[0].Uplink.Known != uint64(len(payload)) || live.Rows[0].Downlink.Known != uint64(len(payload)) {
				return false
			}
			row = live.Rows[0]
			return true
		})
		if row.AccountingRoute.Outbound.Tag != outbound.Tag || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Effective != destination || row.Uplink.Incomplete || row.Downlink.Incomplete {
			t.Fatalf("fragmented UDP attribution: %+v", row)
		}
		outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
		if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("fragmented UDP close: %+v %v", outcomes, err)
		}
	})
	t.Run("dial-failure", func(t *testing.T) {
		outbound := inspectionHysteriaConfig(t)
		message, err := outbound.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		config := message.(*proxyhysteria.ClientConfig)
		outbound.ProxySettings = serial.ToTypedMessage(config)
		senderMessage, err := outbound.SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		sender := senderMessage.(*proxyman.SenderConfig)
		transportMessage, err := sender.StreamSettings.TransportSettings[0].Settings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		transportConfig := transportMessage.(*transporthysteria.Config)
		transportConfig.Auth = "wrong-auth"
		sender.StreamSettings.TransportSettings[0].Settings = serial.ToTypedMessage(transportConfig)
		outbound.SenderSettings = serial.ToTypedMessage(sender)
		inspectionOutboundPreparationFailure(t, outbound)
	})
}

func TestFlowInspectionP2AMuxLogicalEndpoint(t *testing.T) {
	for _, test := range []struct {
		name   string
		config func(*testing.T) *core.OutboundHandlerConfig
	}{
		{name: "VMess-MUX", config: inspectionVMessConfig},
		{name: "Hysteria-MUX", config: inspectionHysteriaConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			outbound := test.config(t)
			var sender *proxyman.SenderConfig
			if outbound.SenderSettings != nil {
				message, err := outbound.SenderSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				sender = message.(*proxyman.SenderConfig)
			} else {
				sender = new(proxyman.SenderConfig)
			}
			sender.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4}
			outbound.SenderSettings = serial.ToTypedMessage(sender)
			_, view, address := inspectionTCPOutboundThrough(t, true, outbound)
			destination := startOutboundStatsTCPServer(t)
			payload := []byte("special carrier payload")
			conn := inspectionSOCKS(t, address, destination, payload)
			inspectionOnlyMuxFlow(t, view, conn, destination, payload, outbound.Tag)
		})
	}
}
