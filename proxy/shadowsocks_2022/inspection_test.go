package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func inspectionFlow(t *testing.T, close func() error) (fs.Exchange, fs.FlowInspection) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().Begin(cnet.Network_TCP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, close)
	flow.Route(fs.OutboundRef{Tag: "direct", Serial: 1})
	flow.BindRoute()
	return flow, view
}

func inspectionLive(t *testing.T, view fs.FlowInspection) fs.FlowRecord {
	t.Helper()
	live, err := view.ReadLive()
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live: %+v %v", live, err)
	}
	return live.Rows[0]
}

type inspectionWriteFunc func([]byte) (int, error)

func (f inspectionWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestInspectionSS2022NativeCodecResults(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, err := GetCipherMethod(name)
			if err != nil {
				t.Fatal(err)
			}
			key := make([]byte, method.KeySaltLength)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			aead, err := method.NewAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			flow, view := inspectionFlow(t, nil)
			writer := buf.AttachWriterReceipt(NewStreamWriter(&wire, aead), flow)
			payload := []byte("native decoded payload")
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
				t.Fatal(err)
			}
			reader := NewStreamReader(&wire, aead)
			decoded, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if got := decoded.String(); got != string(payload) {
				t.Fatalf("decoded: %q", got)
			}
			buf.ReleaseMulti(decoded)
			if got := inspectionLive(t, view).Downlink; got != uint64(len(payload)) {
				t.Fatalf("receipt: %d", got)
			}
		})
	}
}

func TestInspectionSS2022FrameWriteFailures(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	for _, tc := range []struct {
		name  string
		write inspectionWriteFunc
	}{
		{"zero-error", func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }},
		{"partial-error", func([]byte) (int, error) { return 1, io.ErrUnexpectedEOF }},
		{"complete-error", func(p []byte) (int, error) { return len(p), io.ErrUnexpectedEOF }},
		{"short-nil", func([]byte) (int, error) { return 1, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow, view := inspectionFlow(t, nil)
			aead, err := method.NewAEAD(make([]byte, method.KeySaltLength))
			if err != nil {
				t.Fatal(err)
			}
			writer := buf.AttachWriterReceipt(NewStreamWriter(tc.write, aead), flow)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err == nil {
				t.Fatal("missing native write error")
			}
			if got := inspectionLive(t, view).Downlink; got != 0 {
				t.Fatalf("unaccepted frame credited: %d", got)
			}
		})
	}
}

func TestInspectionSS2022PendingWrite(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	flow, view := inspectionFlow(t, func() error { return nil })
	method, _ := GetCipherMethod(MethodAES128GCM)
	aead, _ := method.NewAEAD(make([]byte, method.KeySaltLength))
	writer := buf.AttachWriterReceipt(NewStreamWriter(inspectionWriteFunc(func(p []byte) (int, error) { close(started); <-release; return len(p), nil }), aead), flow)
	done := make(chan error, 1)
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("late"))}) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	result, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
	if err != nil || len(result) != 1 || result[0].Err != nil {
		t.Fatalf("stop: %+v %v", result, err)
	}
	flow.Finish()
	page, _ := view.ReadTerminals()
	if len(page.Rows) != 1 || page.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("owner-end snapshot: %+v", page)
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write stuck")
	}
	page, _ = view.ReadTerminals()
	if page.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("late snapshot: %+v", page)
	}
	totals, _ := view.ReadTotals()
	var known uint64
	for _, total := range totals.Rows {
		known += total.Downlink
	}
	if known != 4 {
		t.Fatalf("late totals: %+v", totals)
	}
}
