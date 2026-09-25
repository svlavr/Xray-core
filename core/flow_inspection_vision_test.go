package core_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"sync/atomic"
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
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func inspectionVisionReceiver(t *testing.T, enabled, sniff bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	return inspectionVisionReceiverMode(t, enabled, sniff, false)
}

func inspectionVisionReceiverMode(t *testing.T, enabled, sniff, encrypted bool) (*core.Instance, fs.FlowInspection, *core.OutboundHandlerConfig) {
	t.Helper()
	remote, view, _ := inspectionCore(t, enabled, false)
	if enabled {
		t.Cleanup(func() {
			if t.Failed() {
				live, _ := view.ReadLive(context.Background())
				t.Logf("receiver diagnostic: %+v", live.Rows)
			}
		})
	}
	port := tcp.PickPort()
	uid := uuid.New()
	id := uid.String()
	serverAccount := &vless.Account{Id: id, Flow: vless.XRV}
	clientAccount := &vless.Account{Id: id, Flow: vless.XRV}
	inbound := &vlessin.Config{Users: []*protocol.User{{Account: serial.ToTypedMessage(serverAccount)}}}
	var serverStream, clientStream *internet.StreamConfig
	if encrypted {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		inbound.Decryption = base64.RawURLEncoding.EncodeToString(key.Bytes())
		inbound.SecondsFrom, inbound.SecondsTo = 120, 120
		clientAccount.Encryption = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		clientAccount.Seconds = 120
	} else {
		certificate, hash := cert.MustGenerate(nil, cert.CommonName("localhost"))
		entry := xtls.ParseCertificate(certificate)
		entry.OneTimeLoading = true
		serverStream = &internet.StreamConfig{ProtocolName: "tcp", SecurityType: serial.GetMessageType(&xtls.Config{}), SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&xtls.Config{Certificate: []*xtls.Certificate{entry}, MinVersion: "1.3", MaxVersion: "1.3"})}}
		clientStream = &internet.StreamConfig{ProtocolName: "tcp", SecurityType: serial.GetMessageType(&xtls.Config{}), SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&xtls.Config{PinnedPeerCertSha256: [][]byte{hash[:]}, MinVersion: "1.3", MaxVersion: "1.3"})}}
	}
	if err := core.AddInboundHandler(remote, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen: cnet.NewIPOrDomain(cnet.LocalHostIP), PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}}, StreamSettings: serverStream,
			SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, RouteOnly: true, DestinationOverride: []string{"http", "tls"}},
		}), ProxySettings: serial.ToTypedMessage(inbound),
	}); err != nil {
		t.Fatal(err)
	}
	return remote, view, &core.OutboundHandlerConfig{Tag: "vision", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: clientStream}), ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: cnet.NewIPOrDomain(cnet.LocalHostIP), Port: uint32(port), User: &protocol.User{Account: serial.ToTypedMessage(clientAccount)}}})}
}

func TestFlowInspectionVisionAdmissions(t *testing.T) {
	inspectionDecodedTCPReceiverAcceptance(t, inspectionVisionReceiver)
}

type inspectionVisionWire struct {
	net.Conn
	read, written atomic.Uint64
}

func (c *inspectionVisionWire) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(uint64(n))
	return n, err
}

func (c *inspectionVisionWire) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n))
	return n, err
}

func inspectionVisionTLS(t *testing.T) (cnet.Destination, *stdtls.Config) {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certPEM, keyPEM := certificate.ToPEM()
	pair, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	config := &stdtls.Config{Certificates: []stdtls.Certificate{pair}, MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13, SessionTicketsDisabled: true}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				inner := stdtls.Server(conn, config)
				_, _ = io.Copy(inner, inner)
			}()
		}
	}()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	t.Logf("inner TLS destination=%s", listener.Addr())
	return cnet.DestinationFromAddr(listener.Addr()), &stdtls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13, SessionTicketsDisabled: true}
}

func TestFlowInspectionVisionTLS13(t *testing.T) {
	for _, mode := range []string{"disabled", "tls", "encrypted"} {
		t.Run(mode, func(t *testing.T) {
			enabled := mode != "disabled"
			_, receiving, outbound := inspectionVisionReceiverMode(t, enabled, true, mode == "encrypted")
			_, sending, address := inspectionTCPOutboundThrough(t, enabled, outbound)
			destination, config := inspectionVisionTLS(t)
			connect := func() (*stdtls.Conn, *inspectionVisionWire) {
				wire := &inspectionVisionWire{Conn: inspectionSOCKS(t, address, destination, nil)}
				inner := stdtls.Client(wire, config)
				if err := inner.Handshake(); err != nil {
					t.Fatal(err)
				}
				t.Logf("inner TLS ready via SOCKS %s->%s, cipher=%x", wire.LocalAddr(), wire.RemoteAddr(), inner.ConnectionState().CipherSuite)
				return inner, wire
			}
			first, wire := connect()
			burst := func(conn *stdtls.Conn, value string) {
				if _, err := conn.Write([]byte(value)); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(value))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, []byte(value)) {
					t.Fatalf("inner TLS payload: %q %v", got, err)
				}
			}
			burst(first, "first open-stream burst")
			if !enabled {
				burst(first, "disabled raw continuation")
				wire.Close()
				return
			}
			check := func(view fs.FlowInspection, tag string, count int) fs.FlowRecord {
				var row fs.FlowRecord
				inspectionWait(t, func() bool {
					live, err := view.ReadLive(context.Background())
					if err != nil || len(live.Rows) != count {
						return false
					}
					for _, candidate := range live.Rows {
						if candidate.Uplink.Known == wire.written.Load() && candidate.Downlink.Known == wire.read.Load() {
							row = candidate
							return true
						}
					}
					return false
				})
				if row.AccountingRoute.Outbound.Tag != tag || row.AccountingRoute.Outbound.Serial == 0 || row.Uplink.Incomplete || row.Downlink.Incomplete || row.Origin != fs.TrafficOriginUser {
					t.Fatalf("Vision live facts: %+v", row)
				}
				if count == 1 {
					totals, err := view.ReadTotals(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					var up, down uint64
					for _, total := range totals.Rows {
						up += total.Uplink.Known
						down += total.Downlink.Known
					}
					if up != row.Uplink.Known || down != row.Downlink.Known {
						t.Fatalf("active Vision totals %d/%d, live %d/%d", up, down, row.Uplink.Known, row.Downlink.Known)
					}
				}
				return row
			}
			firstRow := check(receiving, "direct", 1)
			check(sending, "vision", 1)
			burst(first, "second low-rate burst while both endpoints remain open")
			secondRow := check(receiving, "direct", 1)
			check(sending, "vision", 1)
			if firstRow.Ref != secondRow.Ref || firstRow.Downlink.Incomplete || secondRow.Downlink.Incomplete || secondRow.Downlink.Known <= firstRow.Downlink.Known {
				t.Fatal("raw transition lost active progress or continuity")
			}
			// The second write publishes native inbound splice readiness only
			// after that write completes. A third burst exercises its raw pump.
			burst(first, "third burst through both native splice handoffs")
			thirdRow := check(receiving, "direct", 1)
			check(sending, "vision", 1)
			if thirdRow.Ref != firstRow.Ref || thirdRow.Downlink.Incomplete || thirdRow.Downlink.Known <= secondRow.Downlink.Known {
				t.Fatal("inbound raw pump lost progress")
			}
			sibling, siblingWire := connect()
			burst(sibling, "raw sibling")
			check(receiving, "direct", 2)
			outcomes, err := receiving.CloseFlows(context.Background(), []fs.FlowRef{firstRow.Ref})
			if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("Vision stop: %+v %v", outcomes, err)
			}
			if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("stopped Vision returned %d %v", n, err)
			}
			burst(sibling, "sibling after raw stop")
			siblingWire.Close()
			for _, view := range []fs.FlowInspection{receiving, sending} {
				inspectionWait(t, func() bool {
					page, err := view.ReadTerminals(context.Background())
					if err != nil || len(page.Rows) != 2 {
						return false
					}
					var up, down uint64
					sawEOF := false
					for _, row := range page.Rows {
						if view == receiving && row.Flow.Ref == firstRow.Ref && row.Reason != fs.EndReasonLocalStop {
							t.Fatalf("Vision local stop cause: %+v", row)
						}
						sawEOF = sawEOF || row.Reason == fs.EndReasonEOF
						up += row.Flow.Uplink.Known
						down += row.Flow.Downlink.Known
					}
					if view == sending && !sawEOF {
						t.Fatalf("Vision natural raw completion missing EOF: %+v", page.Rows)
					}
					if up != wire.written.Load()+siblingWire.written.Load() || down != wire.read.Load()+siblingWire.read.Load() {
						t.Fatalf("Vision terminal double count: %d/%d want %d/%d", up, down, wire.written.Load()+siblingWire.written.Load(), wire.read.Load()+siblingWire.read.Load())
					}
					totals, _ := view.ReadTotals(context.Background())
					var totalUp, totalDown uint64
					for _, row := range totals.Rows {
						totalUp += row.Uplink.Known
						totalDown += row.Downlink.Known
					}
					if totalUp != up || totalDown != down {
						t.Fatal("Vision totals disagree with terminal facts")
					}
					return true
				})
			}
		})
	}
}
