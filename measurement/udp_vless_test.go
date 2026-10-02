package measurement_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/measurement"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

type udpCarrierPrefix struct{ bytes []byte }

func (p *udpCarrierPrefix) Write(b []byte) (int, error) {
	n := len(b)
	if len(p.bytes) < 128 {
		p.bytes = append(p.bytes, b[:min(len(b), 128-len(p.bytes))]...)
	}
	return n, nil
}

// A local forwarding fixture independently observes each dedicated carrier EOF.
func udpCarrierFixture(t *testing.T, target string) (net.Addr, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan []byte, 64)
	accepted := make(chan struct{})
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	var wg sync.WaitGroup
	go func() {
		defer close(accepted)
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[client] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { client.Close(); mu.Lock(); delete(active, client); mu.Unlock() }()
				peer, err := net.DialTimeout("tcp4", target, time.Second)
				if err != nil {
					return
				}
				defer peer.Close()
				prefix := new(udpCarrierPrefix)
				copied := make(chan struct{})
				go func() { io.Copy(peer, io.TeeReader(client, prefix)); peer.Close(); close(copied) }()
				io.Copy(client, peer)
				client.Close()
				<-copied
				closed <- prefix.bytes
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-accepted
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr(), closed
}

func udpVLESSExecutor(t *testing.T) (*measurement.Executor, *core.Instance, <-chan []byte) {
	t.Helper()
	port := tcp.PickPort()
	peerID := uuid.New()
	id := peerID.String()
	peer, err := core.New(&core.Config{
		App:      []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}}}), ProxySettings: serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: id})}}})}},
		Outbound: []*core.OutboundHandlerConfig{config("peer-direct", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	front, closed := udpCarrierFixture(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	v := instance(t)
	manager := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := manager.RemoveHandler(context.Background(), "exact"); err != nil {
		t.Fatal(err)
	}
	if err := core.AddOutboundHandler(v, &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(front.(*net.TCPAddr).Port), User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"})}}})}); err != nil {
		t.Fatal(err)
	}
	return executor(t, v), v, closed
}

func assertUDPDedicatedCarrier(t *testing.T, closed <-chan []byte) {
	t.Helper()
	select {
	case wire := <-closed:
		// VLESS version+UUID+zero addons+Mux command, then one NEW with an IPv4
		// destination. Its 12-byte metadata has no trailing 8-byte GlobalID.
		if len(wire) < 33 || wire[17] != 0 || wire[18] != byte(protocol.RequestCommandMux) || binary.BigEndian.Uint16(wire[19:21]) != 12 || wire[23] != 1 || wire[25] != 2 || wire[28] != byte(protocol.AddressTypeIPv4) {
			t.Fatalf("unexpected or shared carrier prefix %x", wire)
		}
	case <-time.After(time.Second):
		t.Fatal("dedicated local carrier did not close")
	}
}

func TestUDPEchoVLESSSourcesDedicatedCleanupAndOrdinaryContinuity(t *testing.T) {
	for _, disabled := range []string{"false", "true"} {
		t.Run("cone-disabled-"+disabled, func(t *testing.T) {
			t.Setenv("xray.cone.disabled", disabled)
			e, v, closed := udpVLESSExecutor(t)
			other, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { other.Close() })
			pc := udpFixture(t, func(pc net.PacketConn, b []byte, a net.Addr) {
				if len(b) >= 24 {
					other.WriteTo(b, a)
				}
				pc.WriteTo(b, a)
			})
			// Same configured handler; ordinary context deliberately carries the
			// source requirement too. OriginUser must preserve ordinary codec choice.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.SetForcedOutboundTagToContext(ctx, "exact")
			ctx = session.ContextWithTrafficOrigin(ctx, session.OriginUser)
			ctx = session.ContextWithUDPPacketSource(ctx)
			dest, _ := xnet.ParseDestination("udp:" + pc.LocalAddr().String())
			ordinary, err := core.Dial(ctx, v, dest)
			if err != nil {
				t.Fatal(err)
			}
			defer ordinary.Close()
			for i := range 3 {
				if _, err := ordinary.Write([]byte("ordinary")); err != nil {
					t.Fatal(err)
				}
				read := make(chan error, 1)
				go func() {
					var b [64]byte
					n, err := ordinary.Read(b[:])
					if string(b[:n]) != "ordinary" {
						err = errors.Join(err, errors.New("ordinary echo mismatch"))
					}
					read <- err
				}()
				select {
				case err := <-read:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("ordinary VLESS stalled")
				}
				if i == 2 {
					break
				}
				got, err := e.UDPEcho(context.Background(), udpRequest(pc.LocalAddr(), measurement.ExactOutbound))
				if err != nil || !got.WindowComplete || len(got.Replies) != 6 {
					t.Fatalf("VLESS %+v %v", got, err)
				}
				var valid, wrong int
				for _, reply := range got.Replies {
					if reply.Issue == measurement.UDPReplyValid {
						valid++
					}
					if reply.Issue == measurement.UDPReplyWrongSource {
						wrong++
					}
				}
				if valid != 3 || wrong != 3 {
					t.Fatalf("peer sources %+v", got.Replies)
				}
				assertUDPDedicatedCarrier(t, closed)
			}
			// Explicitly cancel an active decoding read, then exercise the same
			// ordinary carrier again without closing that session.
			entered := make(chan struct{}, 1)
			quiet := udpFixture(t, func(net.PacketConn, []byte, net.Addr) {
				select {
				case entered <- struct{}{}:
				default:
				}
			})
			r := udpRequest(quiet.LocalAddr(), measurement.ExactOutbound)
			r.ReplyWait = time.Second
			ctx2, cancel2 := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, err := e.UDPEcho(ctx2, r); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				cancel2()
				t.Fatal("not active VLESS read")
			}
			cancel2()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			assertUDPDedicatedCarrier(t, closed)
			if _, err := ordinary.Write([]byte("after-cancel")); err != nil {
				t.Fatal(err)
			}
			after := make(chan error, 1)
			go func() {
				var b [64]byte
				n, err := ordinary.Read(b[:])
				if string(b[:n]) != "after-cancel" {
					err = errors.Join(err, errors.New("ordinary session failed after cancel"))
				}
				after <- err
			}()
			select {
			case err := <-after:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel closed ordinary sibling")
			}
			ordinary.Close()
			cancel()
			select {
			case prefix := <-closed:
				want := byte(protocol.RequestCommandMux)
				if disabled == "true" {
					want = byte(protocol.RequestCommandUDP)
				}
				if len(prefix) < 19 || prefix[18] != want {
					t.Fatalf("source flag changed ordinary codec: %x", prefix)
				}
			case <-time.After(time.Second):
				t.Fatal("ordinary carrier did not close")
			}
		})
	}
}

func TestUDPEchoVLESSSpecialPortsWithConeDisabled(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	e, _, closed := udpVLESSExecutor(t)
	for _, port := range []int{53, 443} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			pc, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Skipf("local fixture port unavailable: %v", err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				var b [2048]byte
				for {
					n, a, err := pc.ReadFrom(b[:])
					if err != nil {
						return
					}
					pc.WriteTo(b[:n], a)
				}
			}()
			t.Cleanup(func() { pc.Close(); <-done })
			// Binding a low port does not prove host delivery (e.g. OS DNS policy).
			probe, err := net.DialTimeout("udp4", pc.LocalAddr().String(), time.Second)
			if err != nil {
				t.Skipf("native fixture unavailable: %v", err)
			}
			probe.SetDeadline(time.Now().Add(100 * time.Millisecond))
			probe.Write([]byte("native-fixture-echo"))
			var probeBytes [64]byte
			n, probeErr := probe.Read(probeBytes[:])
			probe.Close()
			if probeErr != nil || string(probeBytes[:n]) != "native-fixture-echo" {
				t.Skipf("independent native low-port echo unavailable: %v", probeErr)
			}
			got, err := e.UDPEcho(context.Background(), udpRequest(pc.LocalAddr(), measurement.ExactOutbound))
			if err != nil || len(got.Replies) != 3 {
				t.Fatalf("special port %+v %v", got, err)
			}
			for _, reply := range got.Replies {
				if reply.Issue != measurement.UDPReplyValid {
					t.Fatalf("no source %+v", reply)
				}
			}
			assertUDPDedicatedCarrier(t, closed)
		})
	}
}

func TestUDPEchoVLESSNativeResponseFraming(t *testing.T) {
	t.Setenv("xray.cone.disabled", "true")
	for _, mode := range []string{"valid53", "valid443", "no-address", "domain-empty", "oversized", "partial", "cancel-partial"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			requestSeen := make(chan []byte, 1)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				var header [19]byte
				if _, err := io.ReadFull(c, header[:]); err != nil {
					return
				}
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				meta := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(c, meta); err != nil {
					return
				}
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				payload := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(c, payload); err != nil {
					return
				}
				requestSeen <- append(header[:], meta...)
				responseMeta := []byte{0, 0, 2, 1, 2, 0, 9, 1, 127, 0, 0, 1}
				if mode == "valid53" {
					responseMeta[6] = 53
				}
				if mode == "valid443" {
					responseMeta[5] = 1
					responseMeta[6] = 187
				}
				if mode == "no-address" {
					responseMeta = responseMeta[:4]
				}
				if mode == "domain-empty" {
					responseMeta = []byte{0, 0, 2, 1, 2, 0, 9, 2, 0}
				}
				wire := []byte{0, 0, 0, byte(len(responseMeta))} // VLESS response then metadata length.
				wire = append(wire, responseMeta...)
				length := len(payload)
				if mode == "oversized" {
					length = 8193
				}
				wire = append(wire, byte(length>>8), byte(length))
				if mode == "partial" || mode == "cancel-partial" {
					payload = payload[:len(payload)/2]
				}
				wire = append(wire, payload...)
				c.Write(wire)
				if mode == "partial" || mode == "oversized" || mode == "domain-empty" {
					return
				}
				io.Copy(io.Discard, c)
			}()
			v := instance(t)
			manager := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
			manager.RemoveHandler(context.Background(), "exact")
			cfg := &core.OutboundHandlerConfig{Tag: "exact", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(ln.Addr().(*net.TCPAddr).Port), User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: "00000000-0000-0000-0000-000000000001", Encryption: "none"})}}})}
			if err := core.AddOutboundHandler(v, cfg); err != nil {
				t.Fatal(err)
			}
			r := udpRequest(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, measurement.ExactOutbound)
			r.Count, r.Interval = 1, 0
			if mode == "valid53" {
				r.Destination = netip.MustParseAddrPort("127.0.0.1:53")
			}
			if mode == "valid443" {
				r.Destination = netip.MustParseAddrPort("127.0.0.1:443")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type outcome struct {
				receipt measurement.UDPEchoReceipt
				err     error
			}
			done := make(chan outcome, 1)
			e := executor(t, v)
			go func() { receipt, err := e.UDPEcho(ctx, r); done <- outcome{receipt, err} }()
			select {
			case request := <-requestSeen:
				if request[18] != byte(protocol.RequestCommandMux) || len(request) != 31 || binary.BigEndian.Uint16(request[24:26]) != r.Destination.Port() {
					t.Fatalf("wrong native framing %x", request)
				}
			case <-time.After(time.Second):
				t.Fatal("native request not observed")
			}
			if mode == "cancel-partial" {
				cancel()
			}
			got := <-done
			switch mode {
			case "valid53", "valid443":
				if got.err != nil || len(got.receipt.Replies) != 1 || got.receipt.Replies[0].Issue != measurement.UDPReplyValid {
					t.Fatalf("valid %+v %v", got.receipt, got.err)
				}
			case "no-address":
				if got.err != nil || len(got.receipt.Replies) != 1 || got.receipt.Replies[0].Issue != measurement.UDPReplyWrongSource || got.receipt.Replies[0].Source.IsValid() {
					t.Fatalf("source invented %+v %v", got.receipt, got.err)
				}
			case "cancel-partial":
				if !errors.Is(got.err, context.Canceled) {
					t.Fatal(got.err)
				}
			default:
				if got.err == nil || len(got.receipt.Replies) != 0 {
					t.Fatalf("malformed native frame accepted %+v %v", got.receipt, got.err)
				}
			}
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("native peer carrier not closed")
			}
		})
	}
}
