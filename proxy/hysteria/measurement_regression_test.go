package hysteria

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type measurementTCPConn struct {
	net.Conn
	entered, interrupted, writeDone, readDone, failRead chan struct{}
	once                                                sync.Once
	deadline, closedBeforeDeadline                      atomic.Bool
	readError                                           error
}

func (c *measurementTCPConn) Write([]byte) (int, error) {
	close(c.entered)
	<-c.interrupted
	close(c.writeDone)
	return 0, io.ErrClosedPipe
}

func (c *measurementTCPConn) Read([]byte) (int, error) {
	defer close(c.readDone)
	select {
	case <-c.failRead:
		return 0, c.readError
	case <-c.interrupted:
		return 0, io.EOF
	}
}

func (c *measurementTCPConn) SetDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.deadline.Store(true)
		c.once.Do(func() { close(c.interrupted) })
	}
	return nil
}

func (c *measurementTCPConn) Close() error {
	c.closedBeforeDeadline.Store(!c.deadline.Load())
	return nil // Like native graceful Close, this does not interrupt Write.
}

type measurementTCPDialer struct {
	internet.Dialer
	conn stat.Connection
}

func (d *measurementTCPDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func TestMeasurementTCPFailureInterruptsWriter(t *testing.T) {
	for _, mode := range []string{"cancel", "response-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := &measurementTCPConn{entered: make(chan struct{}), interrupted: make(chan struct{}), writeDone: make(chan struct{}), readDone: make(chan struct{}), failRead: make(chan struct{}), readError: errors.New("native TCP response failure")}
			defer conn.SetDeadline(time.Now())
			manager, err := policy.New(ctx, &policy.Config{})
			if err != nil {
				t.Fatal(err)
			}
			dest := xnet.TCPDestination(xnet.LocalHostIP, 443)
			client := &Client{server: &protocol.ServerSpec{Destination: dest}, policyManager: manager}
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
			link := &transport.Link{Reader: buf.NewReader(bytes.NewReader(nil)), Writer: buf.NewWriter(io.Discard)}
			done := make(chan error, 1)
			go func() {
				done <- client.Process(ctx, link, &measurementTCPDialer{conn: &stat.CounterConnection{Connection: conn}})
			}()
			select {
			case <-conn.entered:
			case <-time.After(time.Second):
				t.Fatal("TCP request writer did not enter")
			}
			want := conn.readError
			if mode == "cancel" {
				want = context.Canceled
				cancel()
			} else {
				close(conn.failRead)
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) || !conn.deadline.Load() || conn.closedBeforeDeadline.Load() {
					t.Fatalf("TCP error teardown: deadline=%v close-before-deadline=%v err=%v", conn.deadline.Load(), conn.closedBeforeDeadline.Load(), err)
				}
			case <-time.After(time.Second):
				t.Fatal("TCP Process did not return its failure")
			}
			for _, exited := range []chan struct{}{conn.writeDone, conn.readDone} {
				select {
				case <-exited:
				case <-time.After(time.Second):
					t.Fatal("TCP error teardown retained its I/O worker")
				}
			}
		})
	}
}

type measurementUDPWriter struct {
	calls int
	short bool
	err   error
}

func (w *measurementUDPWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestMeasurementUDPSerializationFailure(t *testing.T) {
	wire := new(measurementUDPWriter)
	w := &UDPWriter{writer: wire}
	err := w.SendMessage(&UDPMessage{Addr: "127.0.0.1:9", FragCount: 1, Data: make([]byte, buf.Size)})
	if !errors.Is(err, io.ErrShortBuffer) || wire.calls != 0 {
		t.Fatalf("oversize packet falsely accepted: calls=%d err=%v", wire.calls, err)
	}
}

func TestMeasurementUDPShortWrite(t *testing.T) {
	wire := &measurementUDPWriter{short: true}
	w := &UDPWriter{writer: wire}
	err := w.SendMessage(&UDPMessage{Addr: "127.0.0.1:9", FragCount: 1, Data: []byte("payload")})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short packet accepted: %v", err)
	}
}

func TestMeasurementUDPImpossibleFragment(t *testing.T) {
	native := &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 8}
	wire := &measurementUDPWriter{err: native}
	w := &UDPWriter{writer: wire, addr: "127.0.0.1:9"}
	b := buf.FromBytes(make([]byte, 24))
	err := w.WriteMultiBuffer(buf.MultiBuffer{b})
	if !errors.Is(err, native) || wire.calls != 1 {
		t.Fatalf("impossible fragment accepted: %v, calls %d", err, wire.calls)
	}
}

func TestMeasurementUDPFragmentCountOverflow(t *testing.T) {
	msg := &UDPMessage{Addr: "127.0.0.1:9", Data: make([]byte, 256)}
	native := &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(msg.HeaderSize() + 1)}
	wire := &measurementUDPWriter{err: native}
	w := &UDPWriter{writer: wire, addr: msg.Addr}
	err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(msg.Data)})
	if !errors.Is(err, native) || wire.calls != 1 {
		t.Fatalf("unrepresentable fragment count: %v, calls %d", err, wire.calls)
	}
}
