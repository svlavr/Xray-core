package proxy

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

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

func TestMeasurementVisionConcurrentReaderWriterDetector(t *testing.T) {
	for range 32 {
		uuid := bytes.Repeat([]byte{0x32}, 16)
		state := NewTrafficState(uuid)
		peerUUID := append([]byte(nil), uuid...)
		incoming := XtlsPadding(buf.FromBytes([]byte("plain-response")), CommandPaddingContinue, &peerUUID, false, context.Background(), measurementVisionSeed)
		reader := NewVisionReader(&measurementVisionInput{mb: buf.MultiBuffer{incoming}}, state, false, context.Background(), nil, nil, nil, nil)
		writer := NewVisionWriter(buf.Discard, state, true, context.Background(), nil, nil, measurementVisionSeed)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			mb, err := reader.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if err != nil && err != io.EOF {
				t.Error(err)
			}
			if len(mb) != 1 || string(mb[0].Bytes()) != "plain-response" {
				t.Error("reader lost native padded response")
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte{0x16, 0x03, 0, 0, 0, 1})}); err != nil {
				t.Error(err)
			}
		}()
		close(start)
		wg.Wait()
		if state.NumberOfPacketToFilter != 6 || !state.IsTLS || state.IsTLS12orAbove || state.EnableXtls {
			t.Fatalf("bidirectional detector lost knowledge/budget: %+v", state)
		}
	}
}

func TestMeasurementVisionBlockedWriteDoesNotLockDetector(t *testing.T) {
	state := NewTrafficState(bytes.Repeat([]byte{0x33}, 16))
	sink := &measurementVisionBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	writer := NewVisionWriter(sink, state, true, context.Background(), nil, nil, measurementVisionSeed)
	returned := make(chan error, 1)
	go func() { returned <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}) }()
	<-sink.entered
	filtered := make(chan struct{})
	go func() {
		mb := buf.MultiBuffer{buf.FromBytes(measurementServerHello(true))}
		defer buf.ReleaseMulti(mb)
		XtlsFilterTls(mb, state, context.Background())
		close(filtered)
	}()
	select {
	case <-filtered:
	case <-time.After(3 * time.Second):
		close(sink.release)
		<-returned
		<-filtered
		t.Fatal("detector mutex held across native blocked Write")
	}
	close(sink.release)
	if err := <-returned; err != nil || !state.EnableXtls {
		t.Fatalf("blocked write/detector completion: %v", err)
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
