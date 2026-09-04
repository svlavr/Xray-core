package scenarios

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestVlessXtlsVisionConcurrentBidirectionalTraffic(t *testing.T) {
	banner := []byte("vision-send-first-banner")
	target := tcp.Server{
		SendFirst: banner,
		MsgProcessor: func(message []byte) []byte {
			return append([]byte(nil), message...)
		},
	}
	destination, err := target.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	userID := protocol.NewID(uuid.New())
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: &internet.StreamConfig{
					ProtocolName: "tcp",
					SecurityType: serial.GetMessageType(&tls.Config{}),
					SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{
						Certificate: []*tls.Certificate{serverCertificate},
					})},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{Users: []*protocol.User{{
				Account: serial.ToTypedMessage(&vless.Account{Id: userID.String(), Flow: vless.XRV}),
			}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}

	clientConfig := &core.Config{
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: &internet.StreamConfig{
					ProtocolName: "tcp",
					TransportSettings: []*internet.TransportConfig{{
						ProtocolName: "tcp",
						Settings:     serial.ToTypedMessage(&transtcp.Config{}),
					}},
					SecurityType: serial.GetMessageType(&tls.Config{}),
					SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{
						PinnedPeerCertSha256: [][]byte{certificateHash[:]},
					})},
				},
			}),
			ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{Vnext: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.LocalHostIP),
				Port:    uint32(serverPort),
				User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
					Id: userID.String(), Flow: vless.XRV,
				})},
			}}),
		}},
	}

	server := startVisionTestInstance(t, serverConfig)
	defer server.Close()
	client := startVisionTestInstance(t, clientConfig)
	defer client.Close()

	const rounds = 24
	const writesPerRound = 8
	const payloadSize = 97
	for round := range rounds {
		connection, err := core.Dial(context.Background(), client, destination)
		if err != nil {
			t.Fatalf("round %d: dial through VLESS Vision: %v", round, err)
		}

		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			connection.Close()
			t.Fatalf("round %d: set deadline: %v", round, err)
		}

		payloads := make([][]byte, writesPerRound)
		expected := append([]byte(nil), banner...)
		for writeIndex := range payloads {
			payloads[writeIndex] = bytes.Repeat([]byte{byte(round), byte(writeIndex)}, (payloadSize+1)/2)[:payloadSize]
			expected = append(expected, payloads[writeIndex]...)
		}

		start := make(chan struct{})
		writeResult := make(chan error, 1)
		readResult := make(chan error, 1)
		var workers sync.WaitGroup
		workers.Add(2)

		go func() {
			defer workers.Done()
			<-start
			for writeIndex, payload := range payloads {
				n, err := connection.Write(payload)
				if err != nil {
					writeResult <- fmt.Errorf("write %d: %w", writeIndex, err)
					return
				}
				if n != len(payload) {
					writeResult <- fmt.Errorf("write %d: wrote %d of %d bytes", writeIndex, n, len(payload))
					return
				}
			}
			writeResult <- nil
		}()

		go func() {
			defer workers.Done()
			<-start
			actual := make([]byte, len(expected))
			if _, err := io.ReadFull(connection, actual); err != nil {
				readResult <- fmt.Errorf("read banner and echoes: %w", err)
				return
			}
			if !bytes.Equal(actual, expected) {
				readResult <- fmt.Errorf("unexpected response content")
				return
			}
			readResult <- nil
		}()

		close(start)
		workers.Wait()
		writeErr := <-writeResult
		readErr := <-readResult
		connection.Close()
		if writeErr != nil {
			t.Fatalf("round %d: %v", round, writeErr)
		}
		if readErr != nil {
			t.Fatalf("round %d: %v", round, readErr)
		}
	}
}

func startVisionTestInstance(t *testing.T, config *core.Config) *core.Instance {
	t.Helper()
	instance, err := core.New(withDefaultApps(config))
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	return instance
}
