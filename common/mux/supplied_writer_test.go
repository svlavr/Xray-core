package mux

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type visionCarrierGate struct {
	mu      sync.Mutex
	calls   int
	wire    bytes.Buffer
	entered chan int
	release chan struct{}
}

func (w *visionCarrierGate) WriteMultiBuffer(mb buf.MultiBuffer) error {
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

func TestMuxSuppliedVisionWriterPreservesFrameOrder(t *testing.T) {
	carrier := &visionCarrierGate{entered: make(chan int, 8), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(carrier.release) })
	t.Cleanup(release)
	uuid := bytes.Repeat([]byte{0xaa}, 16)
	vision := proxy.NewVisionWriter(carrier, proxy.NewTrafficState(uuid), true, context.Background(), nil, nil, []uint32{32, 1, 32, 1})
	reader, keepOpen := pipe.New()
	defer keepOpen.Close()
	worker, err := NewClientWorker(transport.Link{Reader: reader, Writer: vision}, ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 80)}})
	var inputs []*pipe.Writer
	for i := 0; i < 2; i++ {
		r, w := pipe.New()
		inputs = append(inputs, w)
		defer w.Close()
		w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte{byte('a' + i)})})
		if !worker.Dispatch(ctx, &transport.Link{Reader: r, Writer: buf.Discard}) {
			t.Fatal("child rejected")
		}
		if i == 0 {
			select {
			case <-carrier.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("first frame never reached writer")
			}
		}
	}
	select {
	case <-carrier.entered:
		t.Fatal("second child bypassed first Vision frame commit")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case <-carrier.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second frame did not resume")
	}
	for _, w := range inputs {
		w.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for worker.ActiveConnections() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if worker.ActiveConnections() != 0 {
		t.Fatal("children did not finish")
	}
	carrier.mu.Lock()
	encoded := append([]byte(nil), carrier.wire.Bytes()...)
	carrier.mu.Unlock()
	decoded := proxy.NewVisionReader(buf.NewReader(bytes.NewReader(encoded)), proxy.NewTrafficState(uuid), true, context.Background(), nil, nil, nil, nil)
	var plain bytes.Buffer
	if err := buf.Copy(decoded, &buf.SequentialWriter{Writer: &plain}); err != nil {
		t.Fatal(err)
	}
	frames := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(plain.Bytes()))}
	seen := map[uint16]string{}
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
			seen[meta.SessionID] += mb.String()
			buf.ReleaseMulti(mb)
		}
	}
	if seen[1] != "a" || seen[2] != "b" {
		t.Fatalf("Vision stream lost child frame order/content: %+v", seen)
	}
}
