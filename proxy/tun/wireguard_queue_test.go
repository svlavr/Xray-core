package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestWireGuardSharedUDPLargePacketAndDestination(t *testing.T) {
	destination := net.UDPDestination(net.LocalHostIP, 5353)
	payload := bytes.Repeat([]byte{0x5a}, buf.Size+73)
	queue := newPacketQueue(1)
	if !queue.push(func() *buf.Buffer {
		b := buf.NewWithSize(int32(len(payload)))
		b.Write(payload)
		b.UDP = &destination
		return b
	}()) {
		t.Fatal("packet rejected")
	}
	queue.close()
	c := &udpConn{queue: queue}
	mb, err := c.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || *mb[0].UDP != destination {
		t.Fatalf("packet lost or changed: %v %v", mb, err)
	}
}

func TestWireGuardSharedUDPQueueRetirement(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(fmt.Sprint(replaced), func(t *testing.T) {
			src := net.UDPDestination(net.LocalHostIP, 1234)
			dst := net.UDPDestination(net.LocalHostIP, 5353)
			retired := &udpConn{src: src, queue: newPacketQueue(udpQueueLimit)}
			for i := 0; i < udpQueueLimit; i++ {
				if !retired.queue.push(func() *buf.Buffer { b := buf.FromBytes([]byte{1}); b.UDP = &dst; return b }()) {
					t.Fatal("packet rejected below limit")
				}
			}
			current := retired
			if replaced {
				current = &udpConn{src: src, queue: newPacketQueue(udpQueueLimit)}
			}
			manager := newUdpConnectionHandler(nil, nil)
			manager.udpConns[src] = current
			manager.connectionFinished(retired)
			manager.connectionFinished(retired)
			if retired.queue.items != nil || retired.queue.push(buf.New()) {
				t.Fatal("retired queue retained packets or accepted new input")
			}
			if _, ok := retired.queue.pop(); ok {
				t.Fatal("retired queue delivered pending input")
			}
			if replaced {
				if manager.udpConns[src] != current || !current.queue.push(buf.New()) {
					t.Fatal("retirement removed or closed replacement")
				}
			} else if len(manager.udpConns) != 0 {
				t.Fatal("retired owner remained indexed")
			}
		})
	}
}

func TestWireGuardSharedUDPPrefixAndPendingWrite(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	dst := net.UDPDestination(net.LocalHostIP, 53)
	alternate := net.UDPDestination(net.LocalHostIP, 5353)
	calls := 0
	write := func(_ context.Context, payload []byte, from, to net.Destination) error {
		calls++
		if calls == 1 && from != dst {
			t.Errorf("default destination: %v", from)
		}
		if calls == 2 {
			if from != alternate {
				t.Errorf("packet destination: %v", from)
			}
			close(entered)
			<-release
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	c := &udpConn{handler: newUdpConnectionHandler(nil, write), dst: dst}
	writer := c
	done := make(chan error, 1)
	first, second, tail := buf.New(), buf.New(), buf.New()
	first.WriteString("ok")
	second.WriteString("fail")
	tail.WriteString("tail")
	second.UDP = &alternate
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{first, second, tail, buf.FromBytes(nil)}) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("native write did not start")
	}
	close(release)
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("native partial result: calls=%d", calls)
	}
	for _, b := range []*buf.Buffer{first, second, tail} {
		if !b.IsEmpty() {
			t.Fatal("native packet input not released")
		}
	}
}
