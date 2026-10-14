package proxy

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

var measurementVisionSeed = []uint32{0, 1, 0, 1} // Native padding with no random bytes.

func measurementServerHello(tls13 bool) []byte {
	hello := make([]byte, 85)
	copy(hello, []byte{0x16, 0x03, 0x03, 0, 80, 2})
	hello[44], hello[45] = 0x13, 0x01
	if tls13 {
		copy(hello[79:], Tls13SupportedVersions)
	}
	return hello
}

func TestMeasurementVisionFragmentedServerHelloAndCommands(t *testing.T) {
	for _, tls13 := range []bool{false, true} {
		t.Run(map[bool]string{false: "tls12", true: "tls13"}[tls13], func(t *testing.T) {
			uuid := bytes.Repeat([]byte{0x31}, 16)
			state := NewTrafficState(uuid)
			hello := measurementServerHello(tls13)
			first := buf.MultiBuffer{buf.FromBytes(hello[:79])}
			XtlsFilterTls(first, state, context.Background())
			buf.ReleaseMulti(first)
			if state.Cipher != 0x1301 || state.RemainingServerHello != 6 || state.EnableXtls || !state.IsTLS12orAbove {
				t.Fatalf("fragmented ServerHello lost parser state: %+v", state)
			}
			last := buf.MultiBuffer{buf.FromBytes(hello[79:])}
			XtlsFilterTls(last, state, context.Background())
			buf.ReleaseMulti(last)
			if state.NumberOfPacketToFilter != 0 || state.RemainingServerHello != 0 || state.EnableXtls != tls13 {
				t.Fatalf("ServerHello completion: %+v", state)
			}
			capture := new(measurementVisionCapture)
			writer := NewVisionWriter(capture, state, true, context.Background(), nil, nil, measurementVisionSeed)
			record := []byte{0x17, 0x03, 0x03, 0, 1, 0x42}
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(record)}); err != nil {
				t.Fatal(err)
			}
			peer := NewTrafficState(uuid)
			decoded := XtlsUnpadding(buf.FromBytes(capture.wire), peer, false, context.Background())
			defer decoded.Release()
			wantCommand := int(CommandPaddingEnd)
			if tls13 {
				wantCommand = int(CommandPaddingDirect)
			}
			if !bytes.Equal(decoded.Bytes(), record) || peer.Outbound.CurrentCommand != wantCommand || state.Outbound.UplinkWriterDirectCopy != tls13 {
				t.Fatalf("native command/payload: command%d want%d payload%v", peer.Outbound.CurrentCommand, wantCommand, decoded.Bytes())
			}
		})
	}
}

func TestMeasurementVisionFilterPreservesEnteredBatchBudget(t *testing.T) {
	state := NewTrafficState(nil)
	state.NumberOfPacketToFilter = 1
	mb := buf.MultiBuffer{nil, buf.FromBytes([]byte("one")), buf.FromBytes([]byte("two"))}
	defer buf.ReleaseMulti(mb)
	XtlsFilterTls(mb, state, context.Background())
	if state.NumberOfPacketToFilter != -1 {
		t.Fatalf("filter clamped or stopped an entered batch: %d", state.NumberOfPacketToFilter)
	}
}

type measurementVisionInput struct{ mb buf.MultiBuffer }

func (r *measurementVisionInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, io.EOF
}

type measurementVisionCapture struct{ wire []byte }

func (w *measurementVisionCapture) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		w.wire = append(w.wire, b.Bytes()...)
	}
	return nil
}

type measurementVisionBlockedWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (w *measurementVisionBlockedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	close(w.entered)
	<-w.release
	return nil
}
