package inbound

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestUDPWorkerPacketLifetimeAndResponseRebind(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	w := &udpWorker{
		ctx: context.Background(), packetCtx: lifetime, packetCancel: cancel,
		address: net.LocalHostIP, activeConn: make(map[connID]*udpConn),
	}
	t.Cleanup(func() { w.Close() })
	first, _ := w.getConnection(connID{src: net.UDPDestination(net.LocalHostIP, 10001)})
	values := session.ContextWithTrafficOrigin(first.ctx, session.TrafficOriginControlledMeasurement)
	parent := first.PacketContext(values)
	child, childCancel := context.WithCancel(parent)
	defer childCancel()
	atomic.StoreInt64(&first.lastActivityTime, time.Now().Add(-3*time.Minute).Unix())
	if err := w.clean(); err != nil {
		t.Fatal(err)
	}
	if first.ctx.Err() == nil || parent.Err() != nil || child.Err() != nil {
		t.Fatal("source expiry must not cancel the protocol session")
	}
	if session.TrafficOriginFromContext(child) != session.TrafficOriginControlledMeasurement {
		t.Fatal("packet origin was lost")
	}
	if deadline, ok := parent.Deadline(); ok {
		t.Fatalf("unexpected deadline %v", deadline)
	}
	peer := net.UDPDestination(net.LocalHostIP, 10002)
	peerAddr := &net.UDPAddr{IP: peer.Address.IP(), Port: int(peer.Port)}
	var seen net.Destination
	first.downlink = new(appstats.Counter)
	failure := errors.New("raw write failure")
	first.outputTo = func(payload []byte, destination net.Destination) (int, error) {
		seen = destination
		return 2, failure
	}
	if n, err := first.WriteTo([]byte("response"), peerAddr); n != 2 || !errors.Is(err, failure) || seen != peer || first.downlink.Value() != 2 {
		t.Fatalf("rebound response result %d %v %v", n, err, seen)
	}
	w.Close()
	select {
	case <-child.Done():
	case <-time.After(time.Second):
		t.Fatal("worker shutdown did not cancel session")
	}
	if n, err := first.WriteTo([]byte("late"), peerAddr); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("late response: %d %v", n, err)
	}
	if conn, _ := w.getConnection(connID{src: peer}); conn != nil {
		t.Fatal("closed worker admitted a source")
	}
}
