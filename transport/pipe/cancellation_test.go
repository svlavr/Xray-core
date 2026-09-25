package pipe

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

func cancellationResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("pipe operation did not return")
		return nil
	}
}

func TestReadCancellationPreservesPipe(t *testing.T) {
	r, w := New()
	defer r.Interrupt()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { mb, err := r.ReadMultiBufferContext(ctx); buf.ReleaseMulti(mb); result <- err }()
	cancel()
	if err := cancellationResult(t, result); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("next"))})
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "next" {
		t.Fatalf("next read: %s %v", mb.String(), err)
	}
}

func TestCanceledReadDoesNotDequeue(t *testing.T) {
	r, w := New()
	defer r.Interrupt()
	w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("queued"))})
	ctx, cancel := context.WithCancel(context.Background())
	// Cancellation must be rechecked under the pipe lock, not only before it.
	r.pipe.Lock()
	result := make(chan error, 1)
	go func() { mb, err := r.ReadMultiBufferContext(ctx); buf.ReleaseMulti(mb); result <- err }()
	cancel()
	r.pipe.Unlock()
	if err := cancellationResult(t, result); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "queued" {
		t.Fatalf("queued custody: %s %v", mb.String(), err)
	}
}

func TestWriteCancellationPreservesQueuedCustody(t *testing.T) {
	r, w := New(WithSizeLimit(0))
	defer r.Interrupt()
	w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("queued"))})
	ctx, cancel := context.WithCancel(context.Background())
	b := buf.New()
	b.WriteString("canceled")
	result := make(chan error, 1)
	go func() { result <- w.WriteMultiBufferContext(ctx, buf.MultiBuffer{b}) }()
	cancel()
	if err := cancellationResult(t, result); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	if b.Len() != 0 {
		t.Fatal("canceled batch was not released")
	}
	mb, err := r.ReadMultiBuffer()
	if err != nil || mb.String() != "queued" {
		t.Fatalf("prior data changed: %s %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	if err := w.WriteMultiBufferContext(context.Background(), buf.MultiBuffer{buf.FromBytes([]byte("fresh"))}); err != nil {
		t.Fatal(err)
	}
	mb, err = r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "fresh" {
		t.Fatalf("pipe unusable: %s %v", mb.String(), err)
	}
}

func TestAcceptedWriteSurvivesCancellation(t *testing.T) {
	r, w := New()
	defer r.Interrupt()
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.WriteMultiBufferContext(ctx, buf.MultiBuffer{buf.FromBytes([]byte("accepted"))}); err != nil {
		t.Fatal(err)
	}
	cancel()
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "accepted" {
		t.Fatalf("accepted custody lost: %s %v", mb.String(), err)
	}
}

func TestCancellationRacingPacketHasOneOwner(t *testing.T) {
	for range 100 {
		r, w := New()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan buf.MultiBuffer, 1)
		go func() { mb, _ := r.ReadMultiBufferContext(ctx); result <- mb }()
		w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("packet"))})
		cancel()
		var mb buf.MultiBuffer
		select {
		case mb = <-result:
		case <-time.After(3 * time.Second):
			t.Fatal("canceled packet read blocked")
		}
		if mb.IsEmpty() {
			var err error
			mb, err = r.ReadMultiBufferTimeout(3 * time.Second)
			if err != nil {
				t.Fatal(err)
			}
		}
		if mb.String() != "packet" {
			t.Fatalf("packet lost: %q", mb.String())
		}
		buf.ReleaseMulti(mb)
		r.pipe.Lock()
		pending := r.pipe.data.Len()
		r.pipe.Unlock()
		if pending != 0 {
			t.Fatal("packet replayed into new binding")
		}
		r.Interrupt()
	}
}
