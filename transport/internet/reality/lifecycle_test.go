package reality

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

type lifecycleTestConn struct {
	closed chan struct{}
	once   sync.Once
}

func (c *lifecycleTestConn) Read([]byte) (int, error)         { <-c.closed; return 0, net.ErrClosed }
func (c *lifecycleTestConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *lifecycleTestConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *lifecycleTestConn) LocalAddr() net.Addr              { return lifecycleTestAddr("local") }
func (c *lifecycleTestConn) RemoteAddr() net.Addr             { return lifecycleTestAddr("remote") }
func (c *lifecycleTestConn) SetDeadline(time.Time) error      { return nil }
func (c *lifecycleTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *lifecycleTestConn) SetWriteDeadline(time.Time) error { return nil }

type lifecycleTestAddr string

func (a lifecycleTestAddr) Network() string { return string(a) }
func (a lifecycleTestAddr) String() string  { return string(a) }

func TestSpiderLifecycleOwnerStopClosesAndWaitsForRoot(t *testing.T) {
	owner := internet.NewResourceLifecycle(context.Background())
	conn := &lifecycleTestConn{closed: make(chan struct{})}
	spiderCtx, cancel := context.WithCancel(owner.Context())
	spider := &spiderLifecycle{conn: conn, ctx: spiderCtx, cancel: cancel, rootDone: make(chan struct{})}
	if err := owner.RegisterBound(spider, func(unregister func()) { spider.unregister = unregister }); err != nil {
		t.Fatal(err)
	}
	owner.SignalStop()
	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("owner stop did not close spider connection")
	}
	select {
	case <-spiderCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("owner stop did not cancel spider context")
	}
	done := make(chan struct{})
	go func() { _ = owner.CloseAndWait(); close(done) }()
	select {
	case <-done:
		t.Fatal("CloseAndWait returned before root receipt")
	case <-time.After(20 * time.Millisecond):
	}
	close(spider.rootDone)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CloseAndWait did not join root receipt")
	}
}

func TestWaitSpiderCancelsDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitSpider(ctx, time.Hour) {
		t.Fatal("cancelled spider delay completed")
	}
}

func TestInvalidPeerSpiderErrorMarksTransferredConnection(t *testing.T) {
	err := newInvalidPeerSpiderError()
	if !IsInvalidPeerSpiderError(err) {
		t.Fatal("invalid-peer ownership transfer marker was lost")
	}
	if IsInvalidPeerSpiderError(context.Canceled) {
		t.Fatal("ordinary error was classified as an ownership transfer")
	}
}
