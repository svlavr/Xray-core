package tun

import (
	"io"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func inspectionHalfOpenTCP(t *testing.T, handle func(net.Conn, net.Destination)) (*stack, *tcpConn) {
	t.Helper()
	l := newLink()
	l.out = func([]byte) {}
	s := &stack{tun: l, mtu: testMTU, window: tcpWindow, handle: handle, conns: make(map[flow]*tcpConn)}
	s.udp = newUdpConnectionHandler(handle, s.writeUDP)
	f := flow{src: netip.MustParseAddrPort("10.0.0.2:1234"), dst: netip.MustParseAddrPort("10.0.0.1:443")}
	c := newTCPConn(s, f, segment{seq: 1, window: 65535})
	s.conns[f] = c
	s.opening.Add(1)
	t.Cleanup(func() { s.Close(); l.Close() })
	return s, c
}

func inspectionWaitSealed(s *stack) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return true
		}
		runtime.Gosched()
	}
	return false
}

func TestInspectionTCPHalfOpenCompletionAfterSeal(t *testing.T) {
	var callbacks atomic.Int32
	s, c := inspectionHalfOpenTCP(t, func(net.Conn, net.Destination) { callbacks.Add(1) })
	// Close seals the stack before entering UDP shutdown. Hold that existing lock
	// so a previously selected half-open TCP connection receives its ACK after
	// the seal but before Close can acquire c.mu and reset it.
	s.udp.Lock()
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	if !inspectionWaitSealed(s) {
		s.udp.Unlock()
		t.Fatal("stack did not seal admission")
	}
	consumed := c.input(segment{seq: c.rcvNxt, ack: c.sndNxt, flags: tcpAck, window: 65535})
	c.mu.Lock()
	established := c.established
	c.mu.Unlock()
	s.udp.Unlock()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("stack close remained blocked")
	}
	if !consumed || established || callbacks.Load() != 0 || s.opening.Load() != 0 {
		t.Fatalf("sealed half-open completed: consumed=%t established=%t callbacks=%d opening=%d", consumed, established, callbacks.Load(), s.opening.Load())
	}
}

func inspectionEstablishedTCP(c *tcpConn) {
	c.mu.Lock()
	c.established = true
	c.sndUna, c.sndBase = c.sndNxt, c.sndNxt
	c.stack.opening.Add(-1)
	c.mu.Unlock()
}

func TestInspectionTCPScheduledCallbackAfterSeal(t *testing.T) {
	var callbacks atomic.Int32
	s, c := inspectionHalfOpenTCP(t, func(net.Conn, net.Destination) { callbacks.Add(1) })
	inspectionEstablishedTCP(c)
	scheduled, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// Pause the scheduled goroutine before its actual native callback admission.
	go func() {
		close(scheduled)
		<-release
		s.handleTCPConnection(c)
		close(done)
	}()
	<-scheduled
	s.Close()
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("scheduled callback remained blocked")
	}
	if callbacks.Load() != 0 {
		t.Fatalf("callback admitted after stack seal: %d", callbacks.Load())
	}
}

func TestInspectionTCPAdmittedCallbackRetainsNativeReset(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s, c := inspectionHalfOpenTCP(t, func(net.Conn, net.Destination) { close(entered); <-release })
	inspectionEstablishedTCP(c)
	go func() { s.handleTCPConnection(c); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("native callback was not admitted")
	}
	s.Close()
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("admitted native callback did not finish")
	}
	if err != io.ErrClosedPipe {
		t.Fatalf("admitted connection did not retain native reset: %v", err)
	}
}
