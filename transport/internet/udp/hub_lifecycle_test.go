package udp

import (
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
)

type blockingPacketConn struct {
	closed       chan struct{}
	writeStarted chan struct{}
	writeRelease chan struct{}
	closeOnce    sync.Once
}

func (c *blockingPacketConn) ReadFrom([]byte) (int, stdnet.Addr, error) {
	<-c.closed
	return 0, nil, stdnet.ErrClosed
}

func (c *blockingPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) {
	close(c.writeStarted)
	<-c.writeRelease
	return len(p), nil
}

func (c *blockingPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockingPacketConn) LocalAddr() stdnet.Addr           { return &stdnet.UDPAddr{} }
func (*blockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*blockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestHubCloseSignalsBeforeActiveWriteJoin(t *testing.T) {
	var tasks task.Lifecycle
	packetConn := &blockingPacketConn{
		closed:       make(chan struct{}),
		writeStarted: make(chan struct{}),
		writeRelease: make(chan struct{}),
	}
	h := &Hub{
		conn:      packetConn,
		cache:     make(chan *protocoludp.Packet, 1),
		lifecycle: &internet.InboundLifecycle{Tasks: &tasks},
	}
	if !tasks.Acquire() {
		t.Fatal("read-loop receipt was rejected")
	}
	go func() { defer tasks.Release(); h.start() }()
	writeDone := make(chan error, 1)
	go func() {
		_, err := h.WriteTo([]byte("payload"), net.UDPDestination(net.LocalHostIP, 1))
		writeDone <- err
	}()
	select {
	case <-packetConn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP write did not start")
	}
	tasks.Seal()
	closeDone := make(chan error, 1)
	go func() { closeDone <- h.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Hub.Close did not signal the packet connection while WriteTo was active")
	}
	writesJoined := make(chan struct{})
	go func() { h.Wait(); close(writesJoined) }()
	select {
	case <-writesJoined:
		t.Fatal("Hub.Wait returned before the active WriteTo receipt")
	case <-time.After(20 * time.Millisecond):
	}
	close(packetConn.writeRelease)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-writesJoined:
	case <-time.After(time.Second):
		t.Fatal("Hub.Wait did not join the active WriteTo")
	}
	joined := make(chan struct{})
	go func() { tasks.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("UDP read loop did not release its lifecycle receipt")
	}
	if _, err := h.WriteTo(nil, net.UDPDestination(net.LocalHostIP, 1)); err == nil {
		t.Fatal("closed UDP hub accepted a late write")
	}
	select {
	case _, ok := <-h.Receive():
		if ok {
			t.Fatal("UDP receive channel remained open after joined read loop")
		}
	default:
		t.Fatal("UDP receive channel was not closed after joined read loop")
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal("repeated packet close was not harmless")
	}
}
