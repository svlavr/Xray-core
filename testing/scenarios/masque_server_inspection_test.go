package scenarios

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestFlowInspectionMasqueNativeServer(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("h2=%v/enabled=%v", h2, enabled), func(t *testing.T) {
				tcpServer := tcp.Server{MsgProcessor: xor}
				tcpDest, err := tcpServer.Start()
				if err != nil {
					t.Fatal(err)
				}
				defer tcpServer.Close()
				udpConn, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				udpDest := net.DestinationFromAddr(udpConn.LocalAddr())
				done := make(chan struct{})
				go func() {
					defer close(done)
					packet := make([]byte, 2048)
					for {
						n, peer, err := udpConn.ReadFromUDP(packet)
						if err != nil {
							return
						}
						if _, err := udpConn.WriteToUDP(xor(packet[:n]), peer); err != nil {
							return
						}
					}
				}()
				defer func() { udpConn.Close(); <-done }()
				ct, hash := cert.MustGenerate(nil, cert.CommonName("localhost"))
				serverPort := udp.PickPort()
				if h2 {
					serverPort = tcp.PickPort()
				}
				tcpPort, tcp6Port, udpPort := tcp.PickPort(), tcp.PickPort(), udp.PickPort()
				cfg := masqueServerConfig(serverPort, tls.ParseCertificate(ct), h2, tcpDest, udpDest)
				cfg.App = append(cfg.App, serial.ToTypedMessage(&appstats.Config{}))
				server, err := core.New(withDefaultApps(cfg))
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				var view fs.FlowInspection
				if enabled {
					view, err = core.EnableFlowInspection(server, fs.ObservationOptions{})
					if err != nil {
						t.Fatal(err)
					}
				}
				if err = server.Start(); err != nil {
					t.Fatal(err)
				}
				client, err := core.New(withDefaultApps(masqueClientConfig(serverPort, hash, h2, masqueAuthorization, tcpPort, tcp6Port, udpPort, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"))))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if err = client.Start(); err != nil {
					t.Fatal(err)
				}
				dial := func(network string, port net.Port) stdnet.Conn {
					t.Helper()
					c, err := stdnet.DialTimeout(network, "127.0.0.1:"+port.String(), 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.Close() })
					return c
				}
				payload := []byte("decoded masque payload")
				exchange := func(c stdnet.Conn) {
					t.Helper()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					if _, err := c.Write(payload); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, len(payload))
					if _, err := io.ReadFull(c, response); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(response, xor(payload)) {
						t.Fatalf("bad payload %x", response)
					}
				}
				waitRows := func(count int) []fs.FlowRecord {
					t.Helper()
					deadline := time.Now().Add(3 * time.Second)
					for {
						snapshot, err := view.ReadLive()
						if err != nil {
							t.Fatal(err)
						}
						if len(snapshot.Rows) == count {
							ready := true
							for _, row := range snapshot.Rows {
								ready = ready && row.Uplink >= uint64(len(payload)) && row.Downlink >= uint64(len(payload))
							}
							if ready {
								return snapshot.Rows
							}
						}
						if time.Now().After(deadline) {
							t.Fatalf("expected %d decoded flows: %+v", count, snapshot.Rows)
						}
						time.Sleep(time.Millisecond * 10)
					}
				}
				first := dial("tcp", tcpPort)
				exchange(first)
				var firstRef fs.FlowRef
				if enabled {
					firstRef = waitRows(1)[0].Ref
				}
				sibling := dial("tcp", tcpPort)
				exchange(sibling)
				packet := dial("udp", udpPort)
				exchange(packet)
				if !enabled {
					if server.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
						t.Fatal("collection enabled unexpectedly")
					}
					return
				}
				rows := waitRows(3)
				var packetRef fs.FlowRef
				for _, row := range rows {
					if row.Origin != fs.TrafficOriginUser || row.Uplink != uint64(len(payload)) || row.Downlink != uint64(len(payload)) {
						t.Fatalf("carrier/framing counted: %+v", row)
					}
					if row.Kind == net.Network_UDP {
						packetRef = row.Ref
						if row.EffectiveDestination != udpDest {
							t.Fatalf("UDP destination: %+v", row)
						}
					} else if row.EffectiveDestination != tcpDest {
						t.Fatalf("TCP destination: %+v", row)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				outcomes, err := view.CloseFlows(ctx, []fs.FlowRef{firstRef, packetRef})
				if err != nil {
					t.Fatal(err)
				}
				for _, outcome := range outcomes {
					if outcome.Err != nil {
						t.Fatal(outcome.Err)
					}
				}
				first.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := first.Read(make([]byte, 1)); err == nil {
					t.Fatal("stopped TCP child remained readable")
				}
				exchange(sibling)
				// The same UDP source creates a fresh virtual child after exact retirement.
				exchange(packet)
				rows = waitRows(2)
				for _, row := range rows {
					if row.Ref == firstRef || row.Ref == packetRef {
						t.Fatalf("retired child survived: %+v", row)
					}
				}
			})
		}
	}
}
