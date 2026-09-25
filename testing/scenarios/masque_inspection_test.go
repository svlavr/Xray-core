package scenarios

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	transmasque "github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func inspectionMasqueCore(t *testing.T) (fs.FlowInspection, string, string, xnet.Destination, xnet.Destination) {
	t.Helper()
	serverPort, certHash := startMasqueServer(t)
	return inspectionMasqueCoreAt(t, serverPort, certHash)
}

func inspectionMasqueCoreAt(t *testing.T, serverPort xnet.Port, certHash [32]byte) (fs.FlowInspection, string, string, xnet.Destination, xnet.Destination) {
	t.Helper()
	tcpPort, udpPort := tcp.PickPort(), udp.PickPort()
	tcpTarget := xnet.TCPDestination(xnet.IPAddress(masqueServerV4.AsSlice()), masqueEchoPort)
	udpTarget := xnet.UDPDestination(xnet.IPAddress(masqueServerV4.AsSlice()), masqueEchoPort)
	inbound := func(port xnet.Port, target xnet.Destination) *core.InboundHandlerConfig {
		return &core.InboundHandlerConfig{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  xnet.NewIPOrDomain(target.Address),
				RewritePort:     uint32(target.Port),
				AllowedNetworks: []xnet.Network{target.Network},
			}),
		}
	}
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			inbound(tcpPort, tcpTarget), inbound(udpPort, udpTarget),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "masque-inspected",
			ProxySettings: serial.ToTypedMessage(&masque.ClientConfig{Server: &protocol.ServerEndpoint{
				Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(serverPort),
			}}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
				ProtocolName: "masque",
				TransportSettings: []*internet.TransportConfig{{
					ProtocolName: "masque",
					Settings: serial.ToTypedMessage(&transmasque.Config{
						Path: transmasque.DefaultPath, Headers: map[string]string{"Authorization": masqueAuthorization},
					}),
				}},
				SecurityType: serial.GetMessageType(&tls.Config{}),
				SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{
					ServerName: "localhost", PinnedPeerCertSha256: [][]byte{certHash[:]},
				})},
			}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	view, err := core.EnableFlowInspection(instance, fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return view, "127.0.0.1:" + tcpPort.String(), "127.0.0.1:" + udpPort.String(), tcpTarget, udpTarget
}

type masqueFirstDatagramGate struct {
	client    *stdnet.UDPConn
	server    *stdnet.UDPConn
	first     chan struct{}
	release   chan struct{}
	closed    chan struct{}
	firstDo   sync.Once
	releaseDo sync.Once
	closeDo   sync.Once
	wg        sync.WaitGroup

	mu         sync.Mutex
	clientAddr *stdnet.UDPAddr
	sources    map[string]struct{}
	forwarded  uint64
	err        error
}

func newMasqueFirstDatagramGate(t *testing.T, serverPort xnet.Port) *masqueFirstDatagramGate {
	t.Helper()
	client, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server, err := stdnet.DialUDP("udp4", nil, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(serverPort)})
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	gate := &masqueFirstDatagramGate{
		client: client, server: server, first: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}),
		sources: make(map[string]struct{}),
	}
	gate.wg.Add(2)
	go gate.forwardToServer()
	go gate.forwardToClient()
	return gate
}

func (g *masqueFirstDatagramGate) forwardToServer() {
	defer g.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := g.client.ReadFromUDP(buf)
		if err != nil {
			g.recordError(err)
			return
		}
		g.mu.Lock()
		g.sources[addr.String()] = struct{}{}
		if g.clientAddr == nil {
			g.clientAddr = stdnet.UDPAddrFromAddrPort(addr.AddrPort())
		}
		g.mu.Unlock()
		g.firstDo.Do(func() {
			close(g.first)
			<-g.release
		})
		if _, err := g.server.Write(buf[:n]); err != nil {
			g.recordError(err)
			return
		}
		g.mu.Lock()
		g.forwarded++
		g.mu.Unlock()
	}
}

func (g *masqueFirstDatagramGate) forwardToClient() {
	defer g.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		n, err := g.server.Read(buf)
		if err != nil {
			g.recordError(err)
			return
		}
		g.mu.Lock()
		addr := g.clientAddr
		g.mu.Unlock()
		if addr == nil {
			continue
		}
		if _, err := g.client.WriteToUDP(buf[:n], addr); err != nil {
			g.recordError(err)
			return
		}
	}
}

func (g *masqueFirstDatagramGate) recordError(err error) {
	select {
	case <-g.closed:
		return
	default:
	}
	g.mu.Lock()
	if g.err == nil {
		g.err = err
	}
	g.mu.Unlock()
}

func (g *masqueFirstDatagramGate) Release() {
	g.releaseDo.Do(func() { close(g.release) })
}

func (g *masqueFirstDatagramGate) Close() {
	g.closeDo.Do(func() {
		g.Release()
		close(g.closed)
		g.client.Close()
		g.server.Close()
		g.wg.Wait()
	})
}

func (g *masqueFirstDatagramGate) Snapshot() (sources int, forwarded uint64, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sources), g.forwarded, g.err
}

func inspectionMasqueTCPRow(t *testing.T, row fs.FlowRecord, target xnet.Destination, known uint64) {
	t.Helper()
	route := row.AccountingRoute
	if row.Ref.ID == 0 || row.Kind != fs.FlowKindTCP || row.Origin != fs.TrafficOriginUser || row.InitialDestination != target || row.Uplink != (fs.ByteFact{Known: known}) || row.Downlink != (fs.ByteFact{Known: known}) || route.Selection != fs.SelectionDefault || route.Outbound.Tag != "masque-inspected" || route.Outbound.Serial == 0 || route.Original != target || route.SelectedTarget != target || route.Effective != target || len(row.Routes) != 1 || row.Routes[0] != route {
		t.Fatalf("logical MASQUE TCP flow: %+v", row)
	}
}

func inspectionMasqueExchange(t *testing.T, conn stdnet.Conn, payload []byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("MASQUE write %d/%d: %v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil || !bytes.Equal(response, xor(payload)) {
		t.Fatalf("MASQUE response %x: %v", response, err)
	}
}

func TestFlowInspectionMasqueLogicalAndSharedTunnel(t *testing.T) {
	view, tcpAddress, udpAddress, tcpTarget, udpTarget := inspectionMasqueCore(t)
	first, err := stdnet.DialTimeout("tcp", tcpAddress, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	sibling, err := stdnet.DialTimeout("tcp", tcpAddress, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	firstPayload := []byte("first MASQUE flow")
	siblingPayload := []byte("second MASQUE sibling flow")
	inspectionMasqueExchange(t, first, firstPayload)
	inspectionMasqueExchange(t, sibling, siblingPayload)
	var firstRef fs.FlowRef
	firstSource := xnet.DestinationFromAddr(first.LocalAddr())
	siblingSource := xnet.DestinationFromAddr(sibling.LocalAddr())
	wantBytes := map[xnet.Destination]uint64{firstSource: uint64(len(firstPayload)), siblingSource: uint64(len(siblingPayload))}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 2 {
			ready := true
			// Receiving socket data can precede the writer's returned-byte receipt.
			// Wait for both directions, then keep the complete strict row assertions.
			for _, row := range live.Rows {
				want, ok := wantBytes[row.Source]
				if !ok {
					t.Fatalf("unexpected MASQUE source: %+v", row)
				}
				if row.Uplink.Known != want || row.Downlink.Known != want {
					ready = false
				}
			}
			if ready {
				for _, row := range live.Rows {
					inspectionMasqueTCPRow(t, row, tcpTarget, wantBytes[row.Source])
					if row.Source == firstSource {
						firstRef = row.Ref
					}
				}
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if firstRef.ID == 0 {
		t.Fatal("two logical MASQUE flows were not observed")
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{firstRef})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("MASQUE exact stop: %+v %v", outcomes, err)
	}
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("stopped MASQUE endpoint remained open: %d %v", n, err)
	}
	extra := []byte("sibling survives MASQUE stop")
	inspectionMasqueExchange(t, sibling, extra)

	udpConn, err := stdnet.DialTimeout("udp", udpAddress, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpPayload := []byte("MASQUE UDP logical association")
	inspectionMasqueExchange(t, udpConn, udpPayload)
	var udpRef fs.FlowRef
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range live.Rows {
			if row.Kind == fs.FlowKindUDPAssociation && row.Uplink.Known == uint64(len(udpPayload)) && row.Downlink.Known == uint64(len(udpPayload)) {
				if row.Origin != fs.TrafficOriginUser || row.AccountingRoute.Outbound.Tag != "masque-inspected" || row.AccountingRoute.Effective != udpTarget || row.Downlink.Known != row.Uplink.Known {
					t.Fatalf("logical MASQUE UDP flow: %+v", row)
				}
				udpRef = row.Ref
			}
		}
		if udpRef.ID != 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if udpRef.ID == 0 {
		t.Fatal("MASQUE UDP association was not observed")
	}
	outcomes, err = view.CloseFlows(context.Background(), []fs.FlowRef{udpRef})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("MASQUE UDP exact stop: %+v %v", outcomes, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	var stoppedUDP bool
	for time.Now().Before(deadline) {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Rows {
			if row.Flow.Ref == udpRef {
				if row.Reason != fs.EndReasonLocalStop || row.Flow.Uplink.Known != uint64(len(udpPayload)) || row.Flow.Downlink.Known != uint64(len(udpPayload)) {
					t.Fatalf("stopped MASQUE UDP terminal: %+v", row)
				}
				stoppedUDP = true
			}
		}
		if stoppedUDP {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !stoppedUDP {
		t.Fatal("stopped MASQUE UDP association did not terminalize")
	}
	replacement, err := stdnet.DialTimeout("udp", udpAddress, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	replacementPayload := []byte("replacement MASQUE UDP association")
	inspectionMasqueExchange(t, replacement, replacementPayload)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range live.Rows {
			if row.Kind == fs.FlowKindUDPAssociation && row.Uplink.Known == uint64(len(replacementPayload)) && row.Downlink.Known == row.Uplink.Known {
				if row.Ref == udpRef {
					t.Fatal("stopped MASQUE UDP association was reused")
				}
				postStopTCP := []byte("TCP sibling survives UDP stop")
				inspectionMasqueExchange(t, sibling, postStopTCP)
				want := uint64(len(firstPayload) + len(siblingPayload) + len(extra) + len(udpPayload) + len(replacementPayload) + len(postStopTCP))
				totalDeadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(totalDeadline) {
					totals, err := view.ReadTotals(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					var up, down uint64
					for _, total := range totals.Rows {
						if total.Origin != fs.TrafficOriginUser || total.Uplink.Known == 0 && total.Downlink.Known == 0 && !total.Uplink.Incomplete && !total.Downlink.Incomplete {
							continue
						}
						if total.Outbound.Tag != "masque-inspected" || total.Outbound.Serial == 0 || total.Uplink.Incomplete || total.Downlink.Incomplete {
							t.Fatalf("unexpected MASQUE USER bucket: %+v", total)
						}
						up += total.Uplink.Known
						down += total.Downlink.Known
					}
					if up == want && down == want {
						return
					}
					time.Sleep(time.Millisecond)
				}
				t.Fatalf("MASQUE USER totals did not reach %d/%d", want, want)
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("replacement MASQUE UDP association was not observed")
}

func TestFlowInspectionMasqueFirstStopDuringSuccessfulEstablishment(t *testing.T) {
	serverPort, certHash := startMasqueServer(t)
	gate := newMasqueFirstDatagramGate(t, serverPort)
	defer gate.Close()
	view, tcpAddress, _, tcpTarget, _ := inspectionMasqueCoreAt(t, xnet.Port(gate.client.LocalAddr().(*stdnet.UDPAddr).Port), certHash)

	first, err := stdnet.DialTimeout("tcp", tcpAddress, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-gate.first:
	case <-time.After(5 * time.Second):
		t.Fatal("first MASQUE QUIC datagram did not reach the relay")
	}

	var firstRef fs.FlowRef
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 {
			inspectionMasqueTCPRow(t, live.Rows[0], tcpTarget, 0)
			if live.Rows[0].State != fs.FlowStateOpen {
				t.Fatalf("first MASQUE flow state while gated: %+v", live.Rows[0])
			}
			firstRef = live.Rows[0].Ref
			break
		}
		time.Sleep(time.Millisecond)
	}
	if firstRef.ID == 0 {
		t.Fatal("first logical MASQUE flow was not bound while tunnel establishment was gated")
	}

	sibling, err := stdnet.DialTimeout("tcp", tcpAddress, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	var siblingRef fs.FlowRef
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 2 {
			for _, row := range live.Rows {
				inspectionMasqueTCPRow(t, row, tcpTarget, 0)
				if row.State != fs.FlowStateOpen {
					t.Fatalf("bound MASQUE flow state while gated: %+v", row)
				}
				if row.Ref != firstRef {
					siblingRef = row.Ref
				}
			}
			if siblingRef.ID != 0 {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if siblingRef.ID == 0 {
		t.Fatal("sibling logical MASQUE flow was not bound behind the establishing client lock")
	}
	if sources, forwarded, relayErr := gate.Snapshot(); sources != 1 || forwarded != 0 || relayErr != nil {
		t.Fatalf("gated MASQUE carrier before exact stop: sources=%d forwarded=%d err=%v", sources, forwarded, relayErr)
	}

	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{firstRef})
	if err != nil || len(outcomes) != 1 || outcomes[0].Ref != firstRef || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("first MASQUE exact stop: %+v %v", outcomes, err)
	}
	if err := first.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("stopped first MASQUE endpoint remained open: %d %v", n, err)
	} else if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
		t.Fatalf("stopped first MASQUE endpoint only timed out: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	var firstStopped, siblingStillLive bool
	for time.Now().Before(deadline) {
		terminals, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range terminals.Rows {
			if row.Flow.Ref == firstRef {
				inspectionMasqueTCPRow(t, row.Flow, tcpTarget, 0)
				if row.Flow.State != fs.FlowStateEnded || row.Reason != fs.EndReasonLocalStop {
					t.Fatalf("first MASQUE terminal reason: %+v", row)
				}
				firstStopped = true
			}
		}
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		siblingStillLive = false
		for _, row := range live.Rows {
			if row.Ref == siblingRef {
				inspectionMasqueTCPRow(t, row, tcpTarget, 0)
				if row.State != fs.FlowStateOpen {
					t.Fatalf("sibling MASQUE flow state before carrier release: %+v", row)
				}
				siblingStillLive = true
			}
		}
		if firstStopped && siblingStillLive {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !firstStopped || !siblingStillLive {
		t.Fatalf("exact stop isolation before carrier release: firstStopped=%t siblingLive=%t", firstStopped, siblingStillLive)
	}
	if sources, forwarded, relayErr := gate.Snapshot(); sources != 1 || forwarded != 0 || relayErr != nil {
		t.Fatalf("stopped first flow changed gated carrier: sources=%d forwarded=%d err=%v", sources, forwarded, relayErr)
	}

	gate.Release()
	payload := []byte("sibling succeeds after first MASQUE stop")
	inspectionMasqueExchange(t, sibling, payload)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range live.Rows {
			if row.Ref == siblingRef && row.Uplink.Known == uint64(len(payload)) && row.Downlink.Known == uint64(len(payload)) {
				inspectionMasqueTCPRow(t, row, tcpTarget, uint64(len(payload)))
				if row.State != fs.FlowStateOpen {
					t.Fatalf("successful sibling MASQUE flow state: %+v", row)
				}
				sources, forwarded, relayErr := gate.Snapshot()
				if sources != 1 || forwarded == 0 || relayErr != nil {
					t.Fatalf("successful shared MASQUE carrier: sources=%d forwarded=%d err=%v", sources, forwarded, relayErr)
				}
				totals, err := view.ReadTotals(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				var userRows int
				for _, total := range totals.Rows {
					if total.Origin != fs.TrafficOriginUser || total.Uplink.Known == 0 && total.Downlink.Known == 0 && !total.Uplink.Incomplete && !total.Downlink.Incomplete {
						continue
					}
					userRows++
					if total.Outbound.Tag != "masque-inspected" || total.Outbound.Serial == 0 || total.Uplink != (fs.ByteFact{Known: uint64(len(payload))}) || total.Downlink != (fs.ByteFact{Known: uint64(len(payload))}) {
						t.Fatalf("successful MASQUE USER total: %+v", total)
					}
				}
				if userRows != 1 {
					t.Fatalf("successful MASQUE USER total rows: %d %+v", userRows, totals.Rows)
				}
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("sibling MASQUE flow did not expose exact successful payload facts")
}
