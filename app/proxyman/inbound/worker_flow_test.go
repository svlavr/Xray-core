package inbound

import (
	"bytes"
	"context"
	"errors"
	stdnet "net"
	"os"
	"path/filepath"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestTCPWorkerSealsExternalOwnerAfterExistingConnectionClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	inboundProxy := &ownerScopeInbound{registry: registry}
	conn := &ownerScopeConn{reader: bytes.NewReader(nil)}
	conn.closeHook = func() {
		if inboundProxy.handle == nil {
			t.Error("connection closed before external owner admission")
			return
		}
		if phase := inboundProxy.handle.LogicalRoot().View().Phase; phase != flow_observation.LifecyclePhaseOpen {
			t.Errorf("owner sealed before existing connection close: %s", phase)
		}
	}
	worker := &tcpWorker{
		address: xnet.LocalHostIP,
		port:    1080,
		proxy:   inboundProxy,
		ctx:     context.Background(),
	}
	worker.callback(conn)
	if inboundProxy.handle == nil || inboundProxy.handle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("owner did not seal after existing connection close: %+v", inboundProxy.handle)
	}
}

func TestDomainSocketWorkerSealsExternalOwnerAfterExistingConnectionClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	processErr := errors.New("process failed")
	inboundProxy := &ownerScopeInbound{registry: registry, processErr: processErr, expectedNetwork: xnet.Network_UNIX}
	conn := &ownerScopeConn{reader: bytes.NewReader(nil)}
	conn.closeHook = func() {
		if inboundProxy.handle == nil {
			t.Error("connection closed before external owner admission")
			return
		}
		if phase := inboundProxy.handle.LogicalRoot().View().Phase; phase != flow_observation.LifecyclePhaseOpen {
			t.Errorf("owner sealed before existing connection close: %s", phase)
		}
	}
	worker := &dsWorker{
		address: xnet.DomainAddress("/tmp/xray-flow-test.sock"),
		proxy:   inboundProxy,
		ctx:     context.Background(),
	}
	worker.callback(conn)
	if inboundProxy.scope == nil {
		t.Fatal("UNIX worker did not provide an external owner scope")
	}
	if conn.closeCalls != 1 {
		t.Fatalf("existing connection close ran %d times, want 1", conn.closeCalls)
	}
	if inboundProxy.handle == nil {
		t.Fatal("UNIX worker did not admit the external root")
	}
	view := inboundProxy.handle.LogicalRoot().View()
	if view.Phase != flow_observation.LifecyclePhaseTerminal || view.Terminal == nil {
		t.Fatalf("UNIX owner did not seal after existing connection close: %+v", view)
	}
	if view.Terminal.TerminalClass != flow_observation.TerminalClassLocalError || view.Terminal.TechnicalErrorCategory != "PARTICIPANT_ERROR" {
		t.Fatalf("UNIX owner did not retain process error outcome: %+v", view.Terminal)
	}
}

func TestDomainSocketWorkerHostListenerSealsExternalOwnerAfterConnectionClose(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	inboundProxy := &ownerScopeInbound{
		registry:        registry,
		expectedNetwork: xnet.Network_UNIX,
		processEntered:  entered,
		processRelease:  release,
	}
	socketDir, err := os.MkdirTemp("", "xr-u-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, "xray-flow.sock")
	worker := &dsWorker{
		address: xnet.DomainAddress(socketPath),
		proxy:   inboundProxy,
		ctx:     context.Background(),
	}
	if err := worker.Start(); err != nil {
		t.Fatalf("start UNIX listener: %v", err)
	}
	defer worker.hub.Close()
	client, err := stdnet.DialUnix("unix", nil, &stdnet.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial UNIX listener: %v", err)
	}
	defer client.Close()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("UNIX listener did not enter inbound Process")
	}
	if inboundProxy.scope == nil || inboundProxy.handle == nil {
		t.Fatal("UNIX listener did not admit an external owner root")
	}
	if phase := inboundProxy.handle.LogicalRoot().View().Phase; phase != flow_observation.LifecyclePhaseOpen {
		t.Fatalf("UNIX owner sealed before the live server connection closed: %s", phase)
	}
	close(release)
	released = true
	deadline := time.After(2 * time.Second)
	for {
		view := inboundProxy.handle.LogicalRoot().View()
		if view.Phase == flow_observation.LifecyclePhaseTerminal {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("UNIX owner did not seal after the server connection close: %+v", view)
		case <-time.After(time.Millisecond):
		}
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("UNIX client remained open after the server owner sealed")
	}
}

func TestUDPConnCloseBeforeCancelPublishesCancelOnce(t *testing.T) {
	_, writer := pipe.New()
	conn := &udpConn{done: done.New(), writer: writer}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	conn.setCancel(func() { calls++ })
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("cancel calls = %d, want 1", calls)
	}
}

func TestUDPConnConcurrentCloseWaitsForExactClose(t *testing.T) {
	writer := &blockingUDPConnWriter{started: make(chan struct{}), release: make(chan struct{})}
	conn := &udpConn{done: done.New(), writer: writer}
	firstDone := make(chan error, 1)
	go func() { firstDone <- conn.Close() }()
	<-writer.started

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondDone <- conn.Close()
	}()
	<-secondStarted
	select {
	case err := <-secondDone:
		t.Fatalf("concurrent close returned before exact writer close completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(writer.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestUDPWorkerStaleRemovalCannotDeleteReplacement(t *testing.T) {
	id := connID{src: xnet.UDPDestination(xnet.LocalHostIP, 1234)}
	old := &udpConn{}
	replacement := &udpConn{}
	worker := &udpWorker{activeConn: map[connID]*udpConn{id: replacement}}
	worker.removeConn(id, old)
	if worker.activeConn[id] != replacement {
		t.Fatal("stale UDP association removed replacement")
	}
	worker.removeConn(id, replacement)
	if _, found := worker.activeConn[id]; found {
		t.Fatal("exact UDP association was not removed")
	}
}

type blockingUDPConnWriter struct {
	started chan struct{}
	release chan struct{}
}

func (*blockingUDPConnWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (w *blockingUDPConnWriter) Close() error {
	close(w.started)
	<-w.release
	return nil
}

type ownerScopeInbound struct {
	registry        *flow_observation.Registry
	handle          *flow_observation.Handle
	scope           *flow_observation.ExternalOwnerScope
	processErr      error
	expectedNetwork xnet.Network
	processEntered  chan struct{}
	processRelease  <-chan struct{}
}

func (*ownerScopeInbound) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }
func (p *ownerScopeInbound) Process(ctx context.Context, network xnet.Network, conn stat.Connection, _ routing.Dispatcher) error {
	p.scope = flow_observation.ExternalOwnerScopeFromContext(ctx)
	if p.scope == nil {
		return errors.New("external owner scope missing")
	}
	if p.expectedNetwork != xnet.Network_Unknown && network != p.expectedNetwork {
		return errors.New("unexpected inbound network")
	}
	link := &transport.Link{Reader: buf.NewReader(conn), Writer: buf.NewWriter(conn)}
	p.handle = p.registry.AdmitExternalTCP(ctx, "", "tcp:example.com:443", "", p.scope, link)
	if p.processEntered != nil {
		close(p.processEntered)
		<-p.processRelease
	}
	return p.processErr
}

type ownerScopeConn struct {
	reader     *bytes.Reader
	closeHook  func()
	closeErr   error
	closeCalls int
}

func (c *ownerScopeConn) Read(payload []byte) (int, error) { return c.reader.Read(payload) }
func (*ownerScopeConn) Write(payload []byte) (int, error)  { return len(payload), nil }
func (c *ownerScopeConn) Close() error {
	c.closeCalls++
	if c.closeHook != nil {
		c.closeHook()
	}
	return c.closeErr
}

func (*ownerScopeConn) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 1080}
}

func (*ownerScopeConn) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 2), Port: 12345}
}
func (*ownerScopeConn) SetDeadline(time.Time) error      { return nil }
func (*ownerScopeConn) SetReadDeadline(time.Time) error  { return nil }
func (*ownerScopeConn) SetWriteDeadline(time.Time) error { return nil }
