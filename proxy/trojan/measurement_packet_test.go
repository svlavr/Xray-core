package trojan

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type measurementPacketWriter struct {
	calls int
	err   error
}

func (w *measurementPacketWriter) Write(p []byte) (int, error) {
	w.calls++
	return len(p) - 1, w.err
}

func TestMeasurementPacketWriteFailure(t *testing.T) {
	native := errors.New("native packet write failure")
	for _, tc := range []struct {
		name      string
		err, want error
	}{
		{"short-write", nil, io.ErrShortWrite},
		{"partial-native-error", native, native},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &measurementPacketWriter{err: tc.err}
			w := &PacketWriter{Writer: wire, Target: net.UDPDestination(net.LocalHostIP, 9)}
			first, pending := buf.New(), buf.New()
			first.Write([]byte("first"))
			pending.Write([]byte("pending"))
			err := w.WriteMultiBuffer(buf.MultiBuffer{first, pending})
			if !errors.Is(err, tc.want) || wire.calls != 1 || first.Cap() != 0 || pending.Cap() != 0 {
				t.Fatalf("packet failure: calls=%d first=%d pending=%d err=%v", wire.calls, first.Cap(), pending.Cap(), err)
			}
		})
	}
}

func TestMeasurementPacketHeaderShortWrite(t *testing.T) {
	wire := new(measurementPacketWriter)
	dest := net.UDPDestination(net.LocalHostIP, 9)
	w := &PacketWriter{Writer: &ConnWriter{Writer: wire, Target: dest, Account: &MemoryAccount{Key: make([]byte, 56)}}, Target: dest}
	b := buf.New()
	b.Write([]byte("packet"))
	if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); !errors.Is(err, io.ErrShortWrite) || wire.calls != 1 || b.Cap() != 0 {
		t.Fatalf("short connection header reached packet body: calls=%d err=%v", wire.calls, err)
	}
}

func TestMeasurementPacketSizeAndDestination(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address net.Address
		limit   int
	}{
		{"ipv4", net.ParseAddress("192.0.2.1"), 8181},
		{"ipv6", net.ParseAddress("2001:db8::1"), 8169},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := net.UDPDestination(tc.address, 9000)
			for _, size := range []int{tc.limit - 1, tc.limit, tc.limit + 1} {
				payload := bytes.Repeat([]byte{0xa7}, size)
				var wire bytes.Buffer
				w := &PacketWriter{Writer: &wire, Target: net.UDPDestination(net.LocalHostIP, 1)}
				b := buf.NewWithSize(int32(size))
				b.Write(payload)
				b.UDP = &dest
				err := w.WriteMultiBuffer(buf.MultiBuffer{b})
				if b.Cap() != 0 {
					t.Fatal("serializer retained input buffer")
				}
				if size > tc.limit {
					if !errors.Is(err, buf.ErrBufferFull) || wire.Len() != 0 {
						t.Fatalf("oversize packet: size=%d wire=%d err=%v", size, wire.Len(), err)
					}
					continue
				}
				if err != nil || wire.Len() != size+buf.Size-tc.limit {
					t.Fatalf("serialized boundary: size=%d wire=%d err=%v", size, wire.Len(), err)
				}
				r := &PacketReader{Reader: &wire}
				mb, err := r.ReadMultiBuffer()
				var decoded []byte
				for _, part := range mb {
					if part.UDP == nil || *part.UDP != dest {
						t.Errorf("packet destination: %v, want %v", part.UDP, dest)
					}
					decoded = append(decoded, part.Bytes()...)
				}
				buf.ReleaseMulti(mb)
				if err != nil || !bytes.Equal(decoded, payload) || wire.Len() != 0 {
					t.Fatalf("packet boundary lost: size=%d decoded=%d err=%v", size, len(decoded), err)
				}
			}
		})
	}
}

type measurementPacketReadError struct {
	*bytes.Reader
	err error
}

func (r *measurementPacketReadError) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 {
		err = r.err
	}
	return n, err
}

func TestMeasurementPacketTruncatedRead(t *testing.T) {
	var wire bytes.Buffer
	w := &PacketWriter{Writer: &wire, Target: net.UDPDestination(net.LocalHostIP, 9)}
	if _, err := w.writePacket([]byte("payload"), w.Target); err != nil {
		t.Fatal(err)
	}
	native := errors.New("native truncated packet")
	r := &PacketReader{Reader: &measurementPacketReadError{Reader: bytes.NewReader(wire.Bytes()[:wire.Len()-1]), err: native}}
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if !errors.Is(err, native) || len(mb) != 0 {
		t.Fatalf("truncated frame exposed payload or lost error: buffers=%d err=%v", len(mb), err)
	}
}
