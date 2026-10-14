package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func TestInspectionUDPLargePacketAndDestination(t *testing.T) {
	destination := net.UDPDestination(net.LocalHostIP, 5353)
	payload := bytes.Repeat([]byte{0x5a}, buf.Size+73)
	queue := newPacketQueue(1)
	if !queue.push(&packet{p: payload, dest: &destination}) {
		t.Fatal("packet rejected")
	}
	queue.close()
	c := &udpConn{queue: queue}
	mb, err := c.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || *mb[0].UDP != destination {
		t.Fatalf("packet lost or changed: %v %v", mb, err)
	}
}

func TestInspectionUDPQueueRetirement(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(fmt.Sprint(replaced), func(t *testing.T) {
			src := net.UDPDestination(net.LocalHostIP, 1234)
			dst := net.UDPDestination(net.LocalHostIP, 5353)
			retired := &udpConn{src: src, queue: newPacketQueue(udpQueueLimit)}
			for i := 0; i < udpQueueLimit; i++ {
				if !retired.queue.push(&packet{p: []byte{1}, dest: &dst}) {
					t.Fatal("packet rejected below limit")
				}
			}
			current := retired
			if replaced {
				current = &udpConn{src: src, queue: newPacketQueue(udpQueueLimit)}
			}
			manager := &udpManager{m: map[string]*udpConn{src.NetAddr(): current}}
			manager.mutex.Lock()
			manager.close(retired)
			manager.close(retired)
			manager.mutex.Unlock()
			if retired.queue.items != nil || retired.queue.push(&packet{}) {
				t.Fatal("retired queue retained packets or accepted new input")
			}
			if _, ok := retired.queue.pop(); ok {
				t.Fatal("retired queue delivered pending input")
			}
			if replaced {
				if manager.m[src.NetAddr()] != current || !current.queue.push(&packet{}) {
					t.Fatal("retirement removed or closed replacement")
				}
			} else if len(manager.m) != 0 {
				t.Fatal("retired owner remained indexed")
			}
		})
	}
}

func TestInspectionUDPPrefixAndPendingWrite(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	dst := net.UDPDestination(net.LocalHostIP, 53)
	alternate := net.UDPDestination(net.LocalHostIP, 5353)
	calls := 0
	write := func(payload []byte, from, to net.Destination) error {
		calls++
		if calls == 1 && from != dst {
			t.Errorf("default destination: %v", from)
		}
		if calls == 2 {
			if from != alternate {
				t.Errorf("packet destination: %v", from)
			}
			close(entered)
			<-release
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	c := &udpConn{writeFunc: write, dst: dst}
	writer := c
	done := make(chan error, 1)
	first, second, tail := buf.New(), buf.New(), buf.New()
	first.WriteString("ok")
	second.WriteString("fail")
	tail.WriteString("tail")
	second.UDP = &alternate
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{first, second, tail, buf.FromBytes(nil)}) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("native write did not start")
	}
	close(release)
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("native partial result: calls=%d", calls)
	}
	for _, b := range []*buf.Buffer{first, second, tail} {
		if !b.IsEmpty() {
			t.Fatal("native packet input not released")
		}
	}
}

type inspectionWGHandler struct{ outbound.Handler }

func (*inspectionWGHandler) Tag() string { return "wg-device" }

type inspectionWGDialer struct {
	internet.DefaultSystemDialer
	contexts chan context.Context
	sockets  chan net.Conn
}

func (d *inspectionWGDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, options *internet.SocketConfig) (net.Conn, error) {
	d.contexts <- ctx
	conn, err := d.DefaultSystemDialer.Dial(ctx, src, dest, options)
	if conn != nil && d.sockets != nil {
		d.sockets <- conn
	}
	return conn, err
}

func TestInspectionWireGuardDeviceReconnectContext(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), instance))
	defer cancel()
	parent = session.ContextWithFullHandler(parent, new(inspectionWGHandler))
	parent = session.ContextWithStreamSettings(parent, &internet.MemoryStreamConfig{})
	parent = session.ContextWithTrafficOrigin(parent, session.TrafficOriginUser)
	parent = session.ContextWithLogicalObservation(parent, &session.LogicalObservation{})
	parent = session.ContextWithInbound(parent, &session.Inbound{Tag: "first-request"})
	h, err := NewClient(parent, &DeviceConfig{SecretKey: strings.Repeat("01", 32), Endpoint: []string{"10.232.77.2"}, DNS: []string{"127.0.0.1"}, Mtu: 1420, IsClient: true, NoKernelTun: true, Peers: []*PeerConfig{{PublicKey: strings.Repeat("02", 32), Endpoint: "127.0.0.1:9", AllowedIps: []string{"0.0.0.0/0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &inspectionWGDialer{contexts: make(chan context.Context, 8), sockets: make(chan net.Conn, 8)}
	internet.UseAlternativeSystemDialer(dialer)
	defer internet.UseAlternativeSystemDialer(nil)
	defer h.Close()
	initCtx := session.ContextWithOutbounds(parent, []*session.Outbound{{Gateway: net.LocalHostIP}})
	if err = h.init(initCtx); err != nil {
		t.Fatal(err)
	}
	first := <-dialer.contexts
	firstSocket := <-dialer.sockets
	checkBackend := func(ctx context.Context) {
		t.Helper()
		if core.FromContext(ctx) != instance || session.FullHandlerFromContext(ctx).Tag() != "wg-device" || session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal || session.LogicalObservationFromContext(ctx) != nil {
			t.Fatal("physical bind inherited USER accounting or lost native owner")
		}
		outbounds := session.OutboundsFromContext(ctx)
		if len(outbounds) != 1 || outbounds[0] == nil {
			t.Fatal("physical bind has no exact backend metadata")
		}
		ob := outbounds[0]
		if ob.Gateway != net.LocalHostIP || ob.Target != net.UDPDestination(net.LocalHostIP, 9) || ob.Tag != "wg-device" {
			t.Fatalf("physical metadata: %+v", ob)
		}
	}
	checkBackend(first)
	if first.Err() != nil {
		t.Fatal("provisional bind lost live caller context")
	}
	device := h.dev
	cancel()
	if first.Err() != context.Canceled || h.dev != device {
		t.Fatal("caller cancellation lost provisional context or retired established shared device")
	}
	if err = h.dev.Down(); err != nil {
		t.Fatal(err)
	}
	if err = h.dev.Up(); err != nil {
		t.Fatal(err)
	}
	var next context.Context
	select {
	case next = <-dialer.contexts:
	case <-time.After(3 * time.Second):
		t.Fatal("device did not reopen after caller cancellation")
	}
	nextSocket := <-dialer.sockets
	checkBackend(next)
	if next.Err() != nil || session.InboundFromContext(next) != nil {
		t.Fatal("durable reconnect inherited caller cancellation or inbound")
	}
	if session.OutboundsFromContext(first)[0] == session.OutboundsFromContext(next)[0] {
		t.Fatal("reopen reused mutable request metadata")
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if h.dev != nil || h.tun != nil || h.newTun != nil {
		t.Fatal("native device close retained physical owner or retry admission")
	}
	for _, socket := range []net.Conn{firstSocket, nextSocket} {
		if _, err := socket.Write([]byte("closed")); !errors.Is(err, stdnet.ErrClosed) {
			t.Fatalf("native device close left physical socket usable: %v", err)
		}
	}
}

type inspectionWGProvisionalDialer struct {
	internet.DefaultSystemDialer
	entered chan context.Context
}

func (d *inspectionWGProvisionalDialer) Dial(ctx context.Context, _ net.Address, _ net.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	d.entered <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestInspectionWireGuardProvisionalCallerCancellation(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), instance))
	defer cancel()
	parent = session.ContextWithFullHandler(parent, new(inspectionWGHandler))
	parent = session.ContextWithStreamSettings(parent, &internet.MemoryStreamConfig{})
	parent = session.ContextWithTrafficOrigin(parent, session.TrafficOriginUser)
	parent = session.ContextWithLogicalObservation(parent, &session.LogicalObservation{})
	h, err := NewClient(parent, &DeviceConfig{SecretKey: strings.Repeat("01", 32), Endpoint: []string{"10.232.79.2"}, DNS: []string{"127.0.0.1"}, Mtu: 1420, IsClient: true, NoKernelTun: true, Peers: []*PeerConfig{{PublicKey: strings.Repeat("02", 32), Endpoint: "127.0.0.1:9", AllowedIps: []string{"0.0.0.0/0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	dialer := &inspectionWGProvisionalDialer{entered: make(chan context.Context, 8)}
	internet.UseAlternativeSystemDialer(dialer)
	defer internet.UseAlternativeSystemDialer(nil)
	ctx := session.ContextWithOutbounds(parent, []*session.Outbound{{Gateway: net.LocalHostIP}})
	result := make(chan error, 1)
	go func() { result <- h.init(ctx) }()
	var physical context.Context
	select {
	case physical = <-dialer.entered:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("provisional bind did not start")
	}
	if physical.Err() != nil || session.TrafficOriginFromContext(physical) != session.TrafficOriginInternal || session.LogicalObservationFromContext(physical) != nil {
		cancel()
		t.Fatal("provisional backend lost live cancellation or inherited USER accounting")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil || physical.Err() != context.Canceled {
			t.Fatalf("provisional caller cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("provisional initialization survived caller cancellation")
	}
	if h.dev != nil || h.tun != nil || h.tnet != nil || h.newTun == nil {
		t.Fatal("canceled provisional bind retained native resources or lost retry")
	}
}

type inspectionWGPolicy struct{ policy.Manager }

func (inspectionWGPolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Minute}}
}

type inspectionWGProcessDialer struct{ internet.Dialer }

func (inspectionWGProcessDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func TestInspectionWireGuardStopPendingVirtualDial(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	base := context.WithValue(context.Background(), core.XrayKey(1), instance)
	base = session.ContextWithFullHandler(base, new(inspectionWGHandler))
	base = session.ContextWithStreamSettings(base, &internet.MemoryStreamConfig{})
	h, err := NewClient(base, &DeviceConfig{SecretKey: strings.Repeat("01", 32), Endpoint: []string{"10.232.78.2"}, DNS: []string{"127.0.0.1"}, Mtu: 1420, IsClient: true, NoKernelTun: true, Peers: []*PeerConfig{{PublicKey: strings.Repeat("02", 32), Endpoint: "127.0.0.1:9", AllowedIps: []string{"0.0.0.0/0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.policyManager = inspectionWGPolicy{}
	initCtx := session.ContextWithOutbounds(base, []*session.Outbound{{}})
	if err = h.init(initCtx); err != nil {
		t.Fatal(err)
	}
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	target := net.TCPDestination(net.ParseAddress("10.232.78.1"), 443)
	local, peer := stdnet.Pipe()
	defer local.Close()
	defer peer.Close()
	link := &transport.Link{Reader: buf.NewReader(local), Writer: buf.NewWriter(local)}
	ctx, finish := proxy.ObserveTCP(context.Background(), manager, local, target, link)
	defer finish()
	observation := session.LogicalObservationFromContext(ctx)
	observation.Exchange.Route(fs.OutboundRef{Tag: "wg-device"})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, link, inspectionWGProcessDialer{}) }()
	deadline := time.Now().Add(3 * time.Second)
	var liveStorage207 []fs.FlowRecord
	for {
		live, err := view.ReadLiveInto(liveStorage207)
		liveStorage207 = live.Rows
		if err != nil {
			t.Fatal(err)
		}
		if len(live.Rows) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flow did not bind")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("virtual dial was not pending: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err = view.CloseFlows(context.Background(), []fs.FlowRef{observation.Exchange.Ref()}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stopped pending dial succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exact stop did not cancel zero-handshake timeout-only dial")
	}
	if h.dev == nil {
		t.Fatal("virtual stop retired shared device")
	}
	if err = h.dev.Down(); err != nil {
		t.Fatal(err)
	}
	if err = h.dev.Up(); err != nil {
		t.Fatal(err)
	}
}
