package measurement

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"
)

type partialPayloadWriter struct {
	n    int
	err  error
	data []byte
}

func (w *partialPayloadWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p[:w.n]...)
	return w.n, w.err
}

func testUploadBody(t *testing.T, size int64) *uploadBody {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	return &uploadBody{ctx: ctx, cancel: cancel, bytes: size, timeout: time.Second, accepted: sha256.New()}
}

func TestUploadPartialWriterFacts(t *testing.T) {
	nativeErr := errors.New("native partial write")
	for _, writeErr := range []error{nativeErr, nil} {
		b := testUploadBody(t, transferChunk+9)
		w := &partialPayloadWriter{n: 17, err: writeErr}
		n, err := b.WriteTo(w)
		wantErr := writeErr
		if wantErr == nil {
			wantErr = io.ErrShortWrite
		}
		if n != 17 || !errors.Is(err, wantErr) || b.produced != transferChunk || b.written != 17 {
			t.Fatalf("partial counts generated=%d accepted=%d n=%d err=%v", b.produced, b.written, n, err)
		}
		if [sha256.Size]byte(b.accepted.Sum(nil)) != sha256.Sum256(w.data) {
			t.Fatal("partial digest is not writer accepted prefix")
		}
	}
}

type blockedPayloadWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (w *blockedPayloadWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return 0, io.ErrClosedPipe
}

func TestUploadBodyCloseDuringWriteAndBeforeStart(t *testing.T) {
	b := testUploadBody(t, transferChunk)
	w := &blockedPayloadWriter{entered: make(chan struct{}), release: make(chan struct{})}
	finished := make(chan error, 1)
	go func() { _, err := b.WriteTo(w); finished <- err }()
	<-w.entered
	// Close must not hold/wait for a blocked destination Write.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	close(w.release)
	if err := <-finished; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if b.written != 0 || b.produced != transferChunk {
		t.Fatal("blocked write was certified")
	}
	closed := testUploadBody(t, 1)
	closed.Close()
	if n, err := closed.WriteTo(io.Discard); n != 0 || !errors.Is(err, ErrUploadIncomplete) || !closed.began.IsZero() {
		t.Fatalf("late start n=%d err=%v", n, err)
	}
	if _, err := closed.Read(make([]byte, 1)); !errors.Is(err, ErrUnsupported) {
		t.Fatal("fallback production changed accounting")
	}
}
