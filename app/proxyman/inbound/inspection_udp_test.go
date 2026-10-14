package inbound

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
)

func TestUDPWorkerNativeCloseAndExpectedRemoval(t *testing.T) {
	w := &udpWorker{ctx: context.Background(), address: net.LocalHostIP, activeConn: make(map[connID]*udpConn)}
	id := connID{src: net.UDPDestination(net.LocalHostIP, 31001)}
	first, existing := w.getConnection(id)
	if existing || first.done.Done() {
		t.Fatal("new native association missing")
	}
	ctx, cancel := context.WithCancel(w.ctx)
	// The native callback publishes cancel immediately before Process.
	first.cancel = cancel
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != context.Canceled || !first.done.Done() {
		t.Fatal("native close failed to stop its association")
	}
	replacement, existing := w.getConnection(id)
	if existing || replacement == first {
		t.Fatal("closed association was reused")
	}
	t.Cleanup(func() { replacement.Close() })
	w.removeConn(id, first)
	if w.activeConn[id] != replacement {
		t.Fatal("stale removal deleted replacement")
	}
	atomic.StoreInt64(&replacement.lastActivityTime, time.Now().Add(-3*time.Minute).Unix())
	if err := w.clean(); err != nil {
		t.Fatal(err)
	}
	if len(w.activeConn) != 0 || !replacement.done.Done() {
		t.Fatal("native inactive cleanup left association")
	}
}

func TestUDPWorkerNativeScalarResult(t *testing.T) {
	native := errors.New("write failed after accepting bytes")
	counter := new(appstats.Counter)
	c := &udpConn{downlink: counter, output: func([]byte) (int, error) { return 2, native }}
	if n, err := c.Write([]byte("response")); n != 2 || !errors.Is(err, native) || counter.Value() != 2 {
		t.Fatalf("actual native scalar result: n=%d err=%v count=%d", n, err, counter.Value())
	}
}
