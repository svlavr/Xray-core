package shadowsocks_2022

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

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
			writer := NewStreamWriter(&wire, aead)
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
			aead, err := method.NewAEAD(make([]byte, method.KeySaltLength))
			if err != nil {
				t.Fatal(err)
			}
			writer := NewStreamWriter(tc.write, aead)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err == nil {
				t.Fatal("missing native write error")
			}
		})
	}
}

func TestInspectionSS2022PendingWrite(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	method, _ := GetCipherMethod(MethodAES128GCM)
	aead, _ := method.NewAEAD(make([]byte, method.KeySaltLength))
	writer := NewStreamWriter(inspectionWriteFunc(func(p []byte) (int, error) { close(started); <-release; return len(p), nil }), aead)
	mb := buf.MultiBuffer{buf.FromBytes([]byte("late"))}
	done := make(chan error, 1)
	go func() { done <- writer.WriteMultiBuffer(mb) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
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
	for _, b := range mb {
		if !b.IsEmpty() {
			t.Fatal("native input buffer not released")
		}
	}
}
