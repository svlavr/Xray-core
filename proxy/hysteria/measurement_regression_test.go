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

func TestMeasurementUDPDynamicSerialization(t *testing.T) {
	wire := new(measurementUDPWriter)
	w := &UDPWriter{writer: wire}
	err := w.SendMessage(&UDPMessage{Addr: "127.0.0.1:9", FragCount: 1, Data: make([]byte, buf.Size)})
	if err != nil || wire.calls != 1 {
		t.Fatalf("dynamic packet serialization failed: calls=%d err=%v", wire.calls, err)
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

type measurementDatagramWire struct {
	maxSize, calls, failAt int
	failure                error
	packets                [][]byte
}

func (w *measurementDatagramWire) Write(p []byte) (int, error) {
	w.calls++
	if w.maxSize > 0 && len(p) > w.maxSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(w.maxSize)}
	}
	if w.calls == w.failAt {
		return len(p) - 1, w.failure
	}
	w.packets = append(w.packets, bytes.Clone(p))
	return len(p), nil
}

func TestMeasurementUDPAddressDynamicBufferBoundaries(t *testing.T) {
	for _, addr := range []string{"192.0.2.1:9000", "[2001:db8::1]:9000"} {
		t.Run(addr, func(t *testing.T) {
			limit := buf.Size - (&UDPMessage{Addr: addr}).HeaderSize()
			for _, size := range []int{limit - 1, limit, limit + 1} {
				wire := new(measurementDatagramWire)
				w := &UDPWriter{writer: wire}
				payload := bytes.Repeat([]byte{0xb4}, size)
				err := w.SendMessage(&UDPMessage{Addr: addr, FragCount: 1, Data: payload})
				if err != nil || len(wire.packets) != 1 {
					t.Fatalf("serialized datagram: size=%d calls=%d err=%v", size, wire.calls, err)
				}
				msg, err := ParseUDPMessage(wire.packets[0])
				if err != nil || msg.Addr != addr || !bytes.Equal(msg.Data, payload) {
					t.Fatalf("address/payload boundary: size=%d err=%v", size, err)
				}
			}
		})
	}
}

func TestMeasurementUDPFragmentationAndDestination(t *testing.T) {
	for _, addr := range []string{"192.0.2.1:9000", "[2001:db8::1]:9000"} {
		t.Run(addr, func(t *testing.T) {
			wire := &measurementDatagramWire{maxSize: 96}
			w := &UDPWriter{writer: wire, addr: "127.0.0.1:1"}
			dest, err := xnet.ParseDestination("udp:" + addr)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("fragment payload "), 18)
			b := buf.New()
			b.Write(payload)
			b.UDP = &dest
			if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				t.Fatal(err)
			}
			if len(wire.packets) < 2 || wire.calls != len(wire.packets)+1 || b.Cap() != 0 {
				t.Fatalf("fragment attempts/release: accepted=%d calls=%d capacity=%d", len(wire.packets), wire.calls, b.Cap())
			}
			var decoded []byte
			var packetID uint16
			for i, raw := range wire.packets {
				msg, err := ParseUDPMessage(raw)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					packetID = msg.PacketID
				}
				if len(raw) > wire.maxSize || msg.Addr != addr || msg.PacketID == 0 || msg.PacketID != packetID || int(msg.FragID) != i || int(msg.FragCount) != len(wire.packets) {
					t.Fatalf("fragment framing: index=%d size=%d msg=%+v", i, len(raw), msg)
				}
				decoded = append(decoded, msg.Data...)
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatal("fragment payload changed")
			}
		})
	}
}

func TestMeasurementUDPFragmentWriteFailure(t *testing.T) {
	native := errors.New("native fragment write failure")
	for _, tc := range []struct {
		name      string
		err, want error
	}{
		{"short-write", nil, io.ErrShortWrite},
		{"partial-native-error", native, native},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &measurementDatagramWire{maxSize: 64, failAt: 3, failure: tc.err}
			w := &UDPWriter{writer: wire, addr: "127.0.0.1:9000"}
			first, pending := buf.New(), buf.New()
			first.Write(bytes.Repeat([]byte{0x5a}, 200))
			pending.Write([]byte("pending"))
			err := w.WriteMultiBuffer(buf.MultiBuffer{first, pending})
			if !errors.Is(err, tc.want) || wire.calls != 3 || len(wire.packets) != 1 || first.Cap() != 0 || pending.Cap() != 0 {
				t.Fatalf("fragment failure: calls=%d accepted=%d first=%d pending=%d err=%v", wire.calls, len(wire.packets), first.Cap(), pending.Cap(), err)
			}
		})
	}
}

func TestMeasurementUDPDefragInterleavingRecovery(t *testing.T) {
	makeMessage := func(id uint16, text string) *UDPMessage {
		return &UDPMessage{PacketID: id, FragCount: 1, Addr: "[2001:db8::1]:9000", Data: []byte(text)}
	}
	d := new(Defragger)
	a := FragUDPMessage(makeMessage(11, "AAAAAA"), makeMessage(11, "").HeaderSize()+2)
	b := FragUDPMessage(makeMessage(12, "BBBBBB"), makeMessage(12, "").HeaderSize()+2)
	// The native owner retains one packet. Interleaving discards the old
	// packet instead of constructing an output from different packet IDs.
	for _, msg := range []*UDPMessage{&a[0], &b[0], &a[1], &b[1]} {
		if got := d.Feed(msg); got != nil {
			t.Fatalf("interleaved incomplete packet produced output: %+v", got)
		}
	}
	c := FragUDPMessage(makeMessage(13, "CCDD EE"), makeMessage(13, "").HeaderSize()+2)
	for _, msg := range []*UDPMessage{&c[2], &c[2], {PacketID: 13, FragID: 4, FragCount: 4, Data: []byte("invalid")}, &c[0], &c[3]} {
		if got := d.Feed(msg); got != nil {
			t.Fatalf("duplicate/invalid/incomplete fragments produced output: %+v", got)
		}
	}
	got := d.Feed(&c[1])
	if got == nil || got.PacketID != 13 || got.FragCount != 1 || got.FragID != 0 || got.Addr != "[2001:db8::1]:9000" || string(got.Data) != "CCDD EE" {
		t.Fatalf("reordered recovery: %+v", got)
	}
	plain := makeMessage(14, "unfragmented")
	if got := d.Feed(plain); got != plain {
		t.Fatal("unfragmented packet failed after reassembly")
	}
}

type measurementDatagramReader struct {
	data  []byte
	err   error
	calls int
}

func (r *measurementDatagramReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 1 {
		return 0, io.EOF
	}
	return copy(p, r.data), r.err
}

func TestMeasurementUDPReadDataAndError(t *testing.T) {
	native := errors.New("native datagram read failure")
	msg := &UDPMessage{Addr: "[2001:db8::2]:9000", FragCount: 1, Data: []byte("valid data and native error")}
	packet := make([]byte, msg.Size())
	msg.Serialize(packet)
	empty := &UDPMessage{Addr: msg.Addr, FragCount: 1}
	emptyPacket := make([]byte, empty.Size())
	empty.Serialize(emptyPacket)
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"valid", packet, true},
		// Native ParseUDPMessage requires at least one data byte.
		{"native-empty-rejected", emptyPacket, false},
		{"malformed", []byte{1, 2, 3}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &measurementDatagramReader{data: tc.data, err: native}
			r := &UDPReader{reader: wire, df: new(Defragger)}
			mb, err := r.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if !errors.Is(err, native) || wire.calls != 1 {
				t.Fatalf("terminal datagram error: calls=%d err=%v", wire.calls, err)
			}
			if !tc.valid {
				if len(mb) != 0 {
					t.Fatal("malformed datagram exposed payload")
				}
				return
			}
			if len(mb) != 1 || mb[0].UDP == nil || mb[0].UDP.NetAddr() != msg.Addr || !bytes.Equal(mb[0].Bytes(), msg.Data) {
				t.Fatalf("valid datagram was lost: buffers=%d err=%v", len(mb), err)
			}
		})
	}
}

type measurementDatagramSequence struct{ packets [][]byte }

func (r *measurementDatagramSequence) Read(p []byte) (int, error) {
	if len(r.packets) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.packets[0])
	r.packets = r.packets[1:]
	return n, nil
}

func TestMeasurementUDPMalformedThenValid(t *testing.T) {
	msg := &UDPMessage{Addr: "[2001:db8::2]:9000", FragCount: 1, Data: []byte("recovered")}
	packet := make([]byte, msg.Size())
	msg.Serialize(packet)
	r := &UDPReader{reader: &measurementDatagramSequence{packets: [][]byte{{1, 2, 3}, packet}}, df: new(Defragger)}
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 1 || mb[0].UDP == nil || mb[0].UDP.NetAddr() != msg.Addr || !bytes.Equal(mb[0].Bytes(), msg.Data) {
		t.Fatalf("malformed recovery: %v %v", mb, err)
	}
}
