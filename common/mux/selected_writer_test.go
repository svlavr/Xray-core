package mux

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

type selectedVisionCarrierGate struct {
	mu      sync.Mutex
	calls   int
	wire    bytes.Buffer
	entered chan int
	release chan struct{}
}

func (w *selectedVisionCarrierGate) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.mu.Lock()
	w.calls++
	call := w.calls
	w.mu.Unlock()
	w.entered <- call
	if call == 1 {
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range mb {
		w.wire.Write(b.Bytes())
	}
	return nil
}

func TestMuxSelectedServerSuppliedVisionWriterPreservesFrameOrder(t *testing.T) {
	carrier := &selectedVisionCarrierGate{entered: make(chan int, 8), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	uuid := bytes.Repeat([]byte{0xaa}, 16)
	vision := proxy.NewVisionWriter(carrier, proxy.NewTrafficState(uuid), true, context.Background(), nil, nil, []uint32{32, 1, 32, 1})
	worker := retainedWorker(t, nil, vision)
	first, a := muxInspectionFlow(t)
	second, b := muxInspectionFlow(t)
	var wg sync.WaitGroup
	for i, flow := range []struct {
		writer *Writer
		body   string
	}{
		{NewResponseWriter(1, worker.carrierWriter(), protocol.TransferTypeStream), "a"},
		{NewResponseWriter(2, worker.carrierWriter(), protocol.TransferTypeStream), "b"},
	} {
		if i == 0 {
			flow.writer.receipt = first
		} else {
			flow.writer.receipt = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := flow.writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(flow.body))}); err != nil {
				t.Errorf("selected frame write: %v", err)
			}
		}()
		if i == 0 {
			select {
			case <-carrier.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("first selected frame never reached codec")
			}
		}
	}
	select {
	case <-carrier.entered:
		t.Fatal("second selected child bypassed first Vision frame commit")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case <-carrier.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second selected frame did not resume")
	}
	wg.Wait()
	if muxServerFact(t, a).Downlink != 1 || muxServerFact(t, b).Downlink != 1 {
		t.Fatal("supplied codec mixed selected child receipts")
	}
	first.Finish()
	second.Finish()
	carrier.mu.Lock()
	encoded := append([]byte(nil), carrier.wire.Bytes()...)
	carrier.mu.Unlock()
	decoded := proxy.NewVisionReader(buf.NewReader(bytes.NewReader(encoded)), proxy.NewTrafficState(uuid), true, context.Background(), nil, nil, nil, nil)
	var plain bytes.Buffer
	if err := buf.Copy(decoded, &buf.SequentialWriter{Writer: &plain}); err != nil {
		t.Fatal(err)
	}
	frames := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(plain.Bytes()))}
	bodies := make(map[uint16]string)
	for {
		var meta FrameMetadata
		if err := meta.Unmarshal(frames, false); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if meta.Option.Has(OptionData) {
			mb, err := NewStreamReader(frames).ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			bodies[meta.SessionID] += mb.String()
			buf.ReleaseMulti(mb)
		}
	}
	if bodies[1] != "a" || bodies[2] != "b" {
		t.Fatalf("selected Vision frame content/order: %+v", bodies)
	}
}
