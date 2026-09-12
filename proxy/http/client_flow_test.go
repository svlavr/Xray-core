package http

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/task"
)

type h2WriteTracker struct {
	acquired atomic.Int32
	released atomic.Int32
	errors   atomic.Int32
}

func (t *h2WriteTracker) AcquireParticipant() task.ParticipantLease {
	t.acquired.Add(1)
	return &h2WriteLease{tracker: t}
}

type h2WriteLease struct {
	tracker *h2WriteTracker
}

func (l *h2WriteLease) AcquireParticipant() task.ParticipantLease {
	return l.tracker.AcquireParticipant()
}

func (l *h2WriteLease) Release(err error) {
	if err != nil {
		l.tracker.errors.Add(1)
	}
	l.tracker.released.Add(1)
}

func TestH2PayloadWriteParticipantSurvivesEarlyCallerReturn(t *testing.T) {
	tracker := new(h2WriteTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	reader, writer := io.Pipe()
	write := startH2PayloadWrite(ctx, true, writer, []byte("payload"))

	if tracker.acquired.Load() != 1 || tracker.released.Load() != 0 {
		t.Fatalf("got acquired=%d released=%d before write return, want 1/0", tracker.acquired.Load(), tracker.released.Load())
	}
	if err := reader.CloseWithError(io.ErrClosedPipe); err != nil {
		t.Fatal(err)
	}
	if err := write.Wait(); err == nil {
		t.Fatal("blocked payload write unexpectedly succeeded")
	}
	if tracker.released.Load() != 1 || tracker.errors.Load() != 1 {
		t.Fatalf("got released=%d errors=%d after write return, want 1/1", tracker.released.Load(), tracker.errors.Load())
	}
}

func TestH2PayloadWriteOwnsPayloadAfterCallerReturn(t *testing.T) {
	reader, writer := io.Pipe()
	payload := []byte("payload")
	write := startH2PayloadWrite(context.Background(), false, writer, payload)
	copy(payload, "changed")

	got := make([]byte, len("payload"))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if err := write.Wait(); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if string(got) != "payload" {
		t.Fatalf("late writer observed caller buffer reuse: got %q", got)
	}
}

func TestH2PayloadWriteTimeoutOnlyPathDoesNotAcquireF1Participant(t *testing.T) {
	tracker := new(h2WriteTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	reader, writer := io.Pipe()
	write := startH2PayloadWrite(ctx, false, writer, []byte("payload"))
	payload := make([]byte, len("payload"))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if err := write.Wait(); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if tracker.acquired.Load() != 0 || tracker.released.Load() != 0 {
		t.Fatalf("excluded path changed F1 participants: acquired=%d released=%d", tracker.acquired.Load(), tracker.released.Load())
	}
}
