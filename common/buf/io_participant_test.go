package buf

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/task"
)

type blockingParticipantReader struct {
	started chan struct{}
	release chan struct{}
	err     error
	mb      MultiBuffer
}

func (r *blockingParticipantReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.started != nil {
		close(r.started)
	}
	<-r.release
	return r.mb, r.err
}

type testReadLifecycle struct {
	begun     atomic.Int32
	completed atomic.Int32
	bytes     atomic.Uint64
	errSeen   atomic.Bool
}

func (l *testReadLifecycle) BeginRead() bool {
	l.begun.Add(1)
	return true
}

func (l *testReadLifecycle) CompleteRead(reserved bool, bytes uint64, err error) {
	if !reserved {
		return
	}
	l.bytes.Add(bytes)
	if err != nil {
		l.errSeen.Store(true)
	}
	l.completed.Add(1)
}

type timeoutParticipantTracker struct {
	acquired atomic.Int32
	released atomic.Int32
	errSeen  atomic.Bool
}

func (t *timeoutParticipantTracker) AcquireParticipant() task.ParticipantLease {
	t.acquired.Add(1)
	return &timeoutParticipantLease{tracker: t}
}

type timeoutParticipantLease struct {
	tracker *timeoutParticipantTracker
}

func (l *timeoutParticipantLease) AcquireParticipant() task.ParticipantLease {
	return l.tracker.AcquireParticipant()
}

func (l *timeoutParticipantLease) Release(err error) {
	if err != nil {
		l.tracker.errSeen.Store(true)
	}
	l.tracker.released.Add(1)
}

func TestTimeoutWrapperReaderHoldsParticipantUntilBackgroundReadReturns(t *testing.T) {
	wantErr := errors.New("read failed")
	reader := &blockingParticipantReader{release: make(chan struct{}), err: wantErr}
	tracker := new(timeoutParticipantTracker)
	wrapper := &TimeoutWrapperReader{Reader: reader, ParticipantTracker: tracker}

	multiBuffer, err := wrapper.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || !multiBuffer.IsEmpty() {
		t.Fatalf("timeout returned bytes=%d err=%v", multiBuffer.Len(), err)
	}
	if tracker.acquired.Load() != 1 || tracker.released.Load() != 0 {
		t.Fatalf("participant state at timeout: acquired=%d released=%d", tracker.acquired.Load(), tracker.released.Load())
	}

	close(reader.release)
	deadline := time.After(time.Second)
	for tracker.released.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("participant was not released after the underlying read returned")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !tracker.errSeen.Load() {
		t.Fatal("background read outcome was not published before release")
	}

	_, err = wrapper.ReadMultiBuffer()
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestTimeoutWrapperReaderReservesReadLifecycleBeforeBackgroundReturn(t *testing.T) {
	wantErr := errors.New("read failed")
	reader := &blockingParticipantReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
		err:     wantErr,
		mb:      MultiBuffer{FromBytes([]byte("late"))},
	}
	lifecycle := new(testReadLifecycle)
	wrapper := &TimeoutWrapperReader{Reader: reader, ReadLifecycle: lifecycle}

	multiBuffer, err := wrapper.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || !multiBuffer.IsEmpty() {
		t.Fatalf("timeout returned bytes=%d err=%v", multiBuffer.Len(), err)
	}
	<-reader.started
	if lifecycle.begun.Load() != 1 || lifecycle.completed.Load() != 0 {
		t.Fatalf("read lifecycle at timeout: begun=%d completed=%d", lifecycle.begun.Load(), lifecycle.completed.Load())
	}

	close(reader.release)
	deadline := time.After(time.Second)
	for lifecycle.completed.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("read lifecycle was not completed after the underlying read returned")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if lifecycle.bytes.Load() != uint64(len("late")) || !lifecycle.errSeen.Load() {
		t.Fatalf("read outcome was not recorded: bytes=%d err=%t", lifecycle.bytes.Load(), lifecycle.errSeen.Load())
	}

	multiBuffer, err = wrapper.ReadMultiBuffer()
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
	ReleaseMulti(multiBuffer)
	if lifecycle.begun.Load() != 1 || lifecycle.completed.Load() != 1 {
		t.Fatalf("cached read was counted twice: begun=%d completed=%d", lifecycle.begun.Load(), lifecycle.completed.Load())
	}
}

func TestTimeoutWrapperReaderDirectReadLifecycle(t *testing.T) {
	reader := &blockingParticipantReader{
		release: make(chan struct{}),
		mb:      MultiBuffer{FromBytes([]byte("direct"))},
	}
	close(reader.release)
	lifecycle := new(testReadLifecycle)
	wrapper := &TimeoutWrapperReader{Reader: reader, ReadLifecycle: lifecycle}

	multiBuffer, err := wrapper.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	ReleaseMulti(multiBuffer)
	if lifecycle.begun.Load() != 1 || lifecycle.completed.Load() != 1 || lifecycle.bytes.Load() != uint64(len("direct")) {
		t.Fatalf("unexpected direct read lifecycle: begun=%d completed=%d bytes=%d", lifecycle.begun.Load(), lifecycle.completed.Load(), lifecycle.bytes.Load())
	}
}
