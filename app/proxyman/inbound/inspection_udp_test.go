package inbound

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestUDPWorkerConnectionCancellationAndExpectedRemoval(t *testing.T) {
	worker := &udpWorker{
		ctx:        context.Background(),
		address:    net.LocalHostIP,
		activeConn: make(map[connID]*udpConn),
	}
	id := connID{src: net.UDPDestination(net.LocalHostIP, 31001)}
	first, existing := worker.getConnection(id)
	if existing || first.cancel == nil {
		t.Fatal("new association did not publish cancellation before use")
	}
	select {
	case <-first.ctx.Done():
		t.Fatal("new association context started canceled")
	default:
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("association close did not cancel its published context")
	}

	replacement, existing := worker.getConnection(id)
	if existing || replacement == first {
		t.Fatal("closed association was reused")
	}
	worker.removeConn(id, first)
	if worker.activeConn[id] != replacement {
		t.Fatal("stale removal deleted the replacement association")
	}

	atomic.StoreInt64(&replacement.lastActivityTime, time.Now().Add(-3*time.Minute).Unix())
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); replacement.Close() }()
	go func() { defer wg.Done(); worker.removeConn(id, first) }()
	go func() { defer wg.Done(); _ = worker.clean() }()
	wg.Wait()
	worker.RLock()
	remaining := len(worker.activeConn)
	worker.RUnlock()
	if remaining != 0 {
		t.Fatalf("expired association remained after concurrent close/clean/removal: %d", remaining)
	}
	select {
	case <-replacement.ctx.Done():
	default:
		t.Fatal("replacement context remained active after cleanup")
	}
}
