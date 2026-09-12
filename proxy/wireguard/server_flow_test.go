package wireguard

import (
	"context"
	"errors"
	stdnet "net"
	"net/netip"
	"sync"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

func TestServerSealsExternalOwnerOnlyAfterConnectionClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()

	dispatcher := &wireGuardOwnerScopeDispatcher{registry: registry}
	users := &sync.Map{}
	users.Store([32]byte{}, &protocol.MemoryUser{Account: &MemoryAccount{
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}})
	server := &Server{
		ctx:        context.Background(),
		dispatcher: dispatcher,
		users:      users,
	}
	conn := &wireGuardOwnerScopeConn{}
	conn.closeHook = func() {
		if dispatcher.handle == nil {
			t.Error("connection closed before external owner admission")
			return
		}
		if phase := dispatcher.handle.LogicalRoot().View().Phase; phase != flow_observation.LifecyclePhaseOpen {
			t.Errorf("external owner sealed before connection close: %s", phase)
		}
	}

	server.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))
	if dispatcher.handle == nil || dispatcher.handle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("external owner did not seal after connection close: %+v", dispatcher.handle)
	}
}

type wireGuardOwnerScopeDispatcher struct {
	registry *flow_observation.Registry
	handle   *flow_observation.Handle
}

func (*wireGuardOwnerScopeDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*wireGuardOwnerScopeDispatcher) Start() error      { return nil }
func (*wireGuardOwnerScopeDispatcher) Close() error      { return nil }
func (*wireGuardOwnerScopeDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *wireGuardOwnerScopeDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
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

func TestServerUDPUsesExternalAssociationOwnerAndSealsAfterClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	users := &sync.Map{}
	users.Store([32]byte{}, &protocol.MemoryUser{Account: &MemoryAccount{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}})
	dispatcher := &wireGuardOwnerScopeDispatcher{registry: registry}
	server := &Server{ctx: context.Background(), dispatcher: dispatcher, users: users}
	server.HandleConnection(&wireGuardOwnerScopeConn{}, xnet.UDPDestination(xnet.LocalHostIP, 53))
	records := registry.Snapshot().Records
	if dispatcher.handle == nil || len(records) != 1 || records[0].FlowKind != flow_observation.KindUDPAssociation || dispatcher.handle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("WireGuard UDP owner did not create and seal one association: %+v", dispatcher.handle)
	}
}

type wireGuardOwnerScopeConn struct {
	closeHook func()
}

func (*wireGuardOwnerScopeConn) Read([]byte) (int, error)    { return 0, errors.New("unused read") }
func (*wireGuardOwnerScopeConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *wireGuardOwnerScopeConn) Close() error {
	if c.closeHook != nil {
		c.closeHook()
	}
	return nil
}

func (*wireGuardOwnerScopeConn) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IP{10, 0, 0, 1}, Port: 1080}
}

func (*wireGuardOwnerScopeConn) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IP{10, 0, 0, 2}, Port: 12345}
}
func (*wireGuardOwnerScopeConn) SetDeadline(time.Time) error      { return nil }
func (*wireGuardOwnerScopeConn) SetReadDeadline(time.Time) error  { return nil }
func (*wireGuardOwnerScopeConn) SetWriteDeadline(time.Time) error { return nil }
