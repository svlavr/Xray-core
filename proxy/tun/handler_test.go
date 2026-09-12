package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type testCounter struct {
	value int64
}

func (c *testCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value) - value
}

type testConn struct {
	reader    *bytes.Reader
	writer    bytes.Buffer
	closeHook func()
}

func newTestConn(input []byte) *testConn {
	return &testConn{reader: bytes.NewReader(input)}
}

func (c *testConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

func (c *testConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

func (c *testConn) Close() error {
	if c.closeHook != nil {
		c.closeHook()
	}
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}

func (c *testConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testDispatcher struct {
	writePayload []byte
	readBytes    int32
}

func (d *testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *testDispatcher) Start() error {
	return nil
}

func (d *testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

func TestHandlerCountsTunConnectionTraffic(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	dispatcher := &testDispatcher{writePayload: []byte("downlink")}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("dispatcher read unexpected bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("connection write mismatch: got %q, want %q", got, "downlink")
	}
}

func TestHandlerSealsExternalOwnerOnlyAfterConnectionClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	dispatcher := &ownerScopeTestDispatcher{registry: registry}
	conn := newTestConn(nil)
	conn.closeHook = func() {
		if dispatcher.handle == nil {
			t.Error("connection closed before external owner admission")
			return
		}
		if phase := dispatcher.handle.LogicalRoot().View().Phase; phase != flow_observation.LifecyclePhaseOpen {
			t.Errorf("external owner sealed before connection close: %s", phase)
		}
	}
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))
	if dispatcher.handle == nil || dispatcher.handle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("external owner did not seal after connection close: %+v", dispatcher.handle)
	}
}

type ownerScopeTestDispatcher struct {
	registry *flow_observation.Registry
	handle   *flow_observation.Handle
}

func (*ownerScopeTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*ownerScopeTestDispatcher) Start() error      { return nil }
func (*ownerScopeTestDispatcher) Close() error      { return nil }
func (*ownerScopeTestDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *ownerScopeTestDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	scope := flow_observation.ExternalOwnerScopeFromContext(ctx)
	if scope == nil {
		return errors.New("missing external owner scope")
	}
	if dest.Network == xnet.Network_UDP {
		d.handle = d.registry.AdmitExternalUDP(ctx, "", dest.String(), "", scope, link)
	} else {
		d.handle = d.registry.AdmitExternalTCP(ctx, "", dest.String(), "", scope, link)
	}
	return nil
}

func TestHandlerUDPUsesExternalAssociationOwnerAndSealsAfterClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	dispatcher := &ownerScopeTestDispatcher{registry: registry}
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher}
	handler.HandleConnection(newTestConn(nil), xnet.UDPDestination(xnet.LocalHostIP, 53))
	records := registry.Snapshot().Records
	if dispatcher.handle == nil || len(records) != 1 || records[0].FlowKind != flow_observation.KindUDPAssociation || dispatcher.handle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("TUN UDP owner did not create and seal one association: %+v", dispatcher.handle)
	}
}

func TestHandlerUDPStatsPreservePacketTargetsAndAcceptedWrites(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	finished := make(chan struct{})
	dispatcher := &udpStatsTestDispatcher{registry: registry}
	var writes int
	connectionHandler := newUdpConnectionHandler(func(conn net.Conn, destination xnet.Destination) {
		handler := &Handler{
			ctx:             context.Background(),
			config:          &Config{},
			dispatcher:      dispatcher,
			uplinkCounter:   uplinkCounter,
			downlinkCounter: downlinkCounter,
		}
		handler.HandleConnection(conn, destination)
		close(finished)
	}, func([]byte, xnet.Destination, xnet.Destination) error {
		writes++
		if writes == 2 {
			return errors.New("injected packet write failure")
		}
		return nil
	})
	source := xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234)
	first := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	second := xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 5353)
	connectionHandler.HandlePacket(source, first, []byte("one"))
	connectionHandler.HandlePacket(source, second, []byte("two"))
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("UDP handler did not complete")
	}
	if got := dispatcher.packetTargets; len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("dispatcher packet targets = %v, want %v then %v", got, first, second)
	}
	if got := uplinkCounter.Value(); got != int64(len("one")+len("two")) {
		t.Fatalf("uplink counter = %d, want %d", got, len("one")+len("two"))
	}
	if got := downlinkCounter.Value(); got != int64(len("ok")) {
		t.Fatalf("downlink counter = %d, want %d", got, len("ok"))
	}
	records := registry.Snapshot().Records
	if len(records) != 1 || records[0].CompletionState != flow_observation.CompletionTerminal || records[0].TerminalClass != flow_observation.TerminalClassLocalError {
		t.Fatalf("injected write error did not reach owner outcome: %+v", records)
	}
	for _, observation := range records[0].ByteObservations {
		if observation.Direction == flow_observation.DirectionDownlink && observation.ByteScope == flow_observation.ByteScopeDispatcherExternalLinkIO && (observation.ObservedBytes.Known || observation.AccountingFault != flow_observation.AccountingFaultBoundaryUnproven) {
			t.Fatalf("failed write retained successful external-link bytes: %+v", observation)
		}
	}
}

type udpStatsTestDispatcher struct {
	registry      *flow_observation.Registry
	packetTargets []xnet.Destination
}

func (*udpStatsTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*udpStatsTestDispatcher) Start() error      { return nil }
func (*udpStatsTestDispatcher) Close() error      { return nil }
func (*udpStatsTestDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *udpStatsTestDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	scope := flow_observation.ExternalOwnerScopeFromContext(ctx)
	if scope == nil {
		return errors.New("missing external owner scope")
	}
	if d.registry.AdmitExternalUDP(ctx, "", dest.String(), "", scope, link) == nil {
		return errors.New("external UDP admission failed")
	}
	if _, bound := flow_observation.BindExternalLinkIO(ctx, link); !bound {
		return errors.New("external link accounting bind failed")
	}
	for range 2 {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		if len(mb) != 1 || mb[0].UDP == nil {
			buf.ReleaseMulti(mb)
			return errors.New("missing UDP packet target")
		}
		d.packetTargets = append(d.packetTargets, *mb[0].UDP)
		buf.ReleaseMulti(mb)
	}
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ok"))}); err != nil {
		return err
	}
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("fail"))})
}
