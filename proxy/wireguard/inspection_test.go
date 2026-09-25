package wireguard

import (
	"bytes"
	"context"
	"errors"
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
	queue := make(chan *packet, 1)
	queue <- &packet{p: payload, dest: &destination}
	close(queue)
	c := &udpConn{queue: queue}
	mb, err := c.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || *mb[0].UDP != destination {
		t.Fatalf("packet lost or changed: %v %v", mb, err)
	}
}

func TestInspectionUDPPrefixAndPendingWrite(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
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
	writer := c.WithWriterReceipt(flow)
	done := make(chan error, 1)
	first, second, tail := buf.FromBytes([]byte("ok")), buf.FromBytes([]byte("fail")), buf.FromBytes([]byte("tail"))
	second.UDP = &alternate
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{first, second, tail, buf.FromBytes(nil)}) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("native write did not start")
	}
	flow.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 2 || page.Rows[0].Flow.Downlink.Incomplete {
		t.Errorf("owner-end write snapshot: %+v %v", page, err)
	}
	close(release)
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	page, err = view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	fact := page.Rows[0].Flow.Downlink
	if calls != 2 || fact.Known != 2 || fact.Incomplete {
		t.Fatalf("native partial result: calls=%d fact=%+v", calls, fact)
	}
	totals, _ := view.ReadTotals(context.Background())
	var incomplete bool
	for _, total := range totals.Rows {
		incomplete = incomplete || total.Downlink.Incomplete
	}
	if !incomplete {
		t.Fatalf("late error missing from totals: %+v", totals)
	}
}

type inspectionWGHandler struct{ outbound.Handler }

func (*inspectionWGHandler) Tag() string { return "wg-device" }

type inspectionWGDialer struct {
	internet.DefaultSystemDialer
	contexts chan context.Context
}

func (d *inspectionWGDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, options *internet.SocketConfig) (net.Conn, error) {
	d.contexts <- ctx
	return d.DefaultSystemDialer.Dial(ctx, src, dest, options)
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
	dialer := &inspectionWGDialer{contexts: make(chan context.Context, 8)}
	internet.UseAlternativeSystemDialer(dialer)
	defer internet.UseAlternativeSystemDialer(nil)
	defer h.Close()
	if err = h.init(net.LocalHostIP); err != nil {
		t.Fatal(err)
	}
	first := <-dialer.contexts
	cancel()
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
		t.Fatal("device did not reopen")
	}
	for _, ctx := range []context.Context{first, next} {
		if ctx.Err() != nil || core.FromContext(ctx) != instance || session.FullHandlerFromContext(ctx).Tag() != "wg-device" || session.TrafficOriginFromContext(ctx) != session.TrafficOriginInternal || session.LogicalObservationFromContext(ctx) != nil || session.InboundFromContext(ctx) != nil {
			t.Fatal("physical bind inherited request state")
		}
		ob := session.OutboundsFromContext(ctx)[0]
		if ob.Gateway != net.LocalHostIP || ob.Target != net.UDPDestination(net.LocalHostIP, 9) || ob.Tag != "wg-device" || ob.Name != "wireguard" {
			t.Fatalf("physical metadata: %+v", ob)
		}
	}
	if session.OutboundsFromContext(first)[0] == session.OutboundsFromContext(next)[0] {
		t.Fatal("reopen reused mutable request metadata")
	}
	h.Close()
	if first.Err() != context.Canceled || next.Err() != context.Canceled {
		t.Fatal("device shutdown did not cancel its physical contexts")
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
	if err = h.init(nil); err != nil {
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
	observation.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "wg-device", Serial: 1}})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, link, inspectionWGProcessDialer{}) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		live, err := view.ReadLive(context.Background())
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
	if h.deviceCtx.Err() != nil {
		t.Fatal("virtual stop canceled shared device")
	}
	if err = h.dev.Down(); err != nil {
		t.Fatal(err)
	}
	if err = h.dev.Up(); err != nil {
		t.Fatal(err)
	}
}
