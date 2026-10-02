package hysteria

import (
	"errors"
	"io"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
)

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
