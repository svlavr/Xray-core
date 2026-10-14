package pipe

import (
	"io"
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

func TestStoppedWriteDoesNotEnqueue(t *testing.T) {
	r, w := New()
	defer r.Interrupt()
	stop := make(chan struct{})
	b := buf.New()
	b.WriteString("stopped")
	batch := buf.MultiBuffer{b}
	// Recheck revocation under the native enqueue lock.
	r.pipe.Lock()
	result := make(chan error, 1)
	go func() { result <- w.WriteMultiBufferStop(batch, stop) }()
	close(stop)
	r.pipe.Unlock()
	if err := cancellationResult(t, result); err != io.EOF {
		t.Fatalf("stopped enqueue: %v", err)
	}
	if b.Len() != 0 || batch[0] != nil {
		t.Fatal("stopped managed batch was not released or cleared")
	}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("next"))}); err != nil {
		t.Fatal(err)
	}
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "next" {
		t.Fatalf("stopped write changed queue: %q %v", mb.String(), err)
	}
}

func TestWriteCancellationPreservesQueuedCustody(t *testing.T) {
	r, w := New(WithSizeLimit(0))
	defer r.Interrupt()
	w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("queued"))})
	stop := make(chan struct{})
	b := buf.New()
	b.WriteString("canceled")
	batch := buf.MultiBuffer{b}
	result := make(chan error, 1)
	go func() { result <- w.WriteMultiBufferStop(batch, stop) }()
	close(stop)
	if err := cancellationResult(t, result); err != io.EOF {
		t.Fatalf("stop: %v", err)
	}
	if b.Len() != 0 || batch[0] != nil {
		t.Fatal("canceled managed batch was not released or cleared")
	}
	mb, err := r.ReadMultiBuffer()
	if err != nil || mb.String() != "queued" {
		t.Fatalf("prior data changed: %s %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	if err := w.WriteMultiBufferStop(buf.MultiBuffer{buf.FromBytes([]byte("fresh"))}, nil); err != nil {
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
	stop := make(chan struct{})
	if err := w.WriteMultiBufferStop(buf.MultiBuffer{buf.FromBytes([]byte("accepted"))}, stop); err != nil {
		t.Fatal(err)
	}
	close(stop)
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "accepted" {
		t.Fatalf("accepted custody lost: %s %v", mb.String(), err)
	}
}

func TestStopRacingPacketWriteHasOneOwner(t *testing.T) {
	for range 100 {
		r, w := New()
		stop := make(chan struct{})
		b := buf.New()
		b.WriteString("packet")
		batch := buf.MultiBuffer{b}
		result := make(chan error, 1)
		go func() { result <- w.WriteMultiBufferStop(batch, stop) }()
		close(stop)
		err := cancellationResult(t, result)
		switch err {
		case nil:
			mb, readErr := r.ReadMultiBufferTimeout(time.Second)
			if readErr != nil || mb.String() != "packet" {
				buf.ReleaseMulti(mb)
				t.Fatalf("accepted packet lost: %v", readErr)
			}
			buf.ReleaseMulti(mb)
		case io.EOF:
			if b.Len() != 0 || batch[0] != nil {
				t.Fatal("rejected managed packet retained custody")
			}
		default:
			t.Fatalf("stop result: %v", err)
		}
		r.pipe.Lock()
		pending := r.pipe.data.Len()
		r.pipe.Unlock()
		if pending != 0 {
			t.Fatal("packet replayed into next session")
		}
		r.Interrupt()
	}
}
