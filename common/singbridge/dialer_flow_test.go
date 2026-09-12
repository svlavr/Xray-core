package singbridge

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	singbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func TestXrayOutboundDialerOwnsExactAsyncLinkUntilProcessReturns(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:example.com:443", "", flow_observation.ByteScopeLogicalLinkAccepted)
	ctx := flow_observation.ContextWithHandle(context.Background(), handle)
	ctx = flow_observation.ContextWithRootDispatchOwner(ctx, handle)
	ctx = flow_observation.ContextWithLinkBinding(ctx, handle, new(transport.Link), 0)
	started := make(chan struct{})
	release := make(chan struct{})
	wantErr := errors.New("process failed")
	outbound := asyncOutboundFunc(func(processCtx context.Context, link *transport.Link, _ internet.Dialer) error {
		if flow_observation.HandleFromContext(processCtx) != handle || flow_observation.RootDispatchOwnerFromContext(processCtx) != nil {
			t.Error("async outbound inherited owner authority or lost root identity")
		}
		continuationCtx := flow_observation.ContextWithLoopbackContinuation(processCtx, link)
		exactScope, internal := flow_observation.ConsumeLoopbackContinuation(continuationCtx, link)
		if !internal || exactScope == nil {
			t.Error("async outbound context was not rebound to the exact child link")
		} else {
			exactScope.Release(nil)
		}
		close(started)
		<-release
		return wantErr
	})
	dialer := NewOutboundDialer(outbound, nil)
	conn, err := dialer.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("async outbound did not start")
	}
	if view := handle.LogicalRoot().View(); view.LiveParticipantCount != 2 {
		t.Fatalf("async participant was not acquired before spawn: %+v", view)
	}
	handle.UplinkQuiesced()
	handle.DownlinkQuiesced()
	handle.HandlerReturned(context.Background(), "tcp:example.com:443")
	if view := handle.LogicalRoot().View(); view.Phase == flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("root terminalized before async Process return: %+v", view)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for handle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		if time.Now().After(deadline) {
			t.Fatalf("async Process return did not release lifecycle: %+v", handle.LogicalRoot().View())
		}
		time.Sleep(time.Millisecond)
	}
	record := registry.Snapshot().Records[0]
	if record.TerminalClass != flow_observation.TerminalClassLocalError || len(record.Route.KnownHandlerChain) != 0 {
		t.Fatalf("async Process outcome or route-neutrality was lost: record=%+v", record)
	}
}

func TestPinnedSingCopyConnWaitsForBothDirections(t *testing.T) {
	source := newJoinTestConn(true)
	destination := newJoinTestConn(false)
	result := make(chan error, 1)
	go func() {
		result <- singbufio.CopyConn(context.Background(), source, destination)
	}()
	select {
	case <-destination.readStarted:
	case <-time.After(time.Second):
		t.Fatal("download copy did not start")
	}
	select {
	case err := <-result:
		t.Fatalf("CopyConn returned before blocked sibling exited: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(destination.readRelease)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("CopyConn returned unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CopyConn did not return after both directions exited")
	}
	if source.closeWrite.Load() != 1 || destination.closeWrite.Load() != 1 {
		t.Fatalf("half-close behavior changed: source=%d destination=%d", source.closeWrite.Load(), destination.closeWrite.Load())
	}
}

type asyncOutboundFunc func(context.Context, *transport.Link, internet.Dialer) error

func (f asyncOutboundFunc) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	return f(ctx, link, dialer)
}

type joinTestConn struct {
	readStarted chan struct{}
	readRelease chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
	closeWrite  atomic.Int32
}

func newJoinTestConn(readReady bool) *joinTestConn {
	conn := &joinTestConn{readStarted: make(chan struct{}), readRelease: make(chan struct{})}
	if readReady {
		close(conn.readRelease)
	}
	return conn
}

func (c *joinTestConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.readRelease
	return 0, io.EOF
}

func (*joinTestConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *joinTestConn) Close() error {
	c.closeOnce.Do(func() {
		select {
		case <-c.readRelease:
		default:
			close(c.readRelease)
		}
	})
	return nil
}

func (c *joinTestConn) CloseWrite() error {
	c.closeWrite.Add(1)
	return nil
}

func (*joinTestConn) LocalAddr() stdnet.Addr           { return joinTestAddr("local") }
func (*joinTestConn) RemoteAddr() stdnet.Addr          { return joinTestAddr("remote") }
func (*joinTestConn) SetDeadline(time.Time) error      { return nil }
func (*joinTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*joinTestConn) SetWriteDeadline(time.Time) error { return nil }

type joinTestAddr string

func (a joinTestAddr) Network() string { return string(a) }
func (a joinTestAddr) String() string  { return string(a) }
