package task

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingTracker struct {
	acquired atomic.Int32
	released atomic.Int32
	started  atomic.Int32
	errors   atomic.Int32
}

func (t *recordingTracker) AcquireParticipant() ParticipantLease {
	t.acquired.Add(1)
	return &recordingLease{tracker: t}
}

type recordingLease struct {
	tracker *recordingTracker
}

func (l *recordingLease) AcquireParticipant() ParticipantLease {
	return l.tracker.AcquireParticipant()
}

func (l *recordingLease) Release(err error) {
	if err != nil {
		l.tracker.errors.Add(1)
	}
	l.tracker.released.Add(1)
}

type rejectingTracker struct{}

func (rejectingTracker) AcquireParticipant() ParticipantLease { return nil }

func TestRunAcquiresBeforeStartAndReleasesAfterReturn(t *testing.T) {
	tracker := new(recordingTracker)
	ctx := ContextWithParticipantTracker(context.Background(), tracker)
	release := make(chan struct{})
	started := make(chan struct{})

	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, func() error {
			if tracker.acquired.Load() != 1 {
				t.Errorf("task started before participant acquisition")
			}
			tracker.started.Add(1)
			close(started)
			<-release
			return nil
		})
	}()

	<-started
	if tracker.released.Load() != 0 {
		t.Fatal("participant released before task return")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	releaseDeadline := time.Now().Add(time.Second)
	for tracker.released.Load() == 0 && time.Now().Before(releaseDeadline) {
		time.Sleep(time.Millisecond)
	}
	if tracker.released.Load() != 1 {
		t.Fatalf("got %d releases, want 1", tracker.released.Load())
	}
}

func TestRunFirstErrorDoesNotReleaseLateSiblingEarly(t *testing.T) {
	tracker := new(recordingTracker)
	ctx := ContextWithParticipantTracker(context.Background(), tracker)
	lateStarted := make(chan struct{})
	releaseLate := make(chan struct{})
	wantErr := errors.New("first")

	err := Run(ctx,
		func() error {
			<-lateStarted
			return wantErr
		},
		func() error {
			close(lateStarted)
			<-releaseLate
			return nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
	firstReleaseDeadline := time.Now().Add(time.Second)
	for tracker.released.Load() == 0 && time.Now().Before(firstReleaseDeadline) {
		time.Sleep(time.Millisecond)
	}
	if tracker.released.Load() != 1 {
		t.Fatalf("got %d releases after first task exit, want 1", tracker.released.Load())
	}
	close(releaseLate)
	deadline := time.After(time.Second)
	for tracker.released.Load() != 2 {
		select {
		case <-deadline:
			t.Fatal("late sibling participant was not released after its real return")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if tracker.errors.Load() != 1 {
		t.Fatalf("got %d error outcomes, want 1", tracker.errors.Load())
	}
}

func TestRunWithContextAllowsLinearNestedParticipant(t *testing.T) {
	tracker := new(recordingTracker)
	ctx := ContextWithParticipantTracker(context.Background(), tracker)
	childStarted := make(chan struct{})
	releaseChild := make(chan struct{})

	if err := RunWithContext(ctx, func(taskCtx context.Context) error {
		if ParticipantTrackerFromContext(taskCtx) == tracker {
			t.Fatal("task context retained the root tracker instead of its lease")
		}
		child := AcquireParticipant(taskCtx)
		if child == nil {
			t.Fatal("nested participant acquisition failed")
		}
		go func() {
			close(childStarted)
			<-releaseChild
			child.Release(nil)
		}()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	<-childStarted
	parentReleaseDeadline := time.Now().Add(time.Second)
	for tracker.released.Load() == 0 && time.Now().Before(parentReleaseDeadline) {
		time.Sleep(time.Millisecond)
	}
	if tracker.acquired.Load() != 2 || tracker.released.Load() != 1 {
		t.Fatalf("got acquired=%d released=%d, want 2/1 before child exit", tracker.acquired.Load(), tracker.released.Load())
	}
	close(releaseChild)
	deadline := time.After(time.Second)
	for tracker.released.Load() != 2 {
		select {
		case <-deadline:
			t.Fatal("nested participant was not released after its real return")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestRunWithContextMasksRejectedInheritedTracker(t *testing.T) {
	ctx := ContextWithParticipantTracker(context.Background(), rejectingTracker{})
	ran := false
	if err := RunWithContext(ctx, func(taskCtx context.Context) error {
		ran = true
		if AcquireParticipant(taskCtx) != nil {
			t.Fatal("task reacquired from a tracker that rejected its own lease")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("rejected telemetry lease suppressed task execution")
	}
}

func TestRunWithoutTrackerPreservesConcurrency(t *testing.T) {
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	tasks := []func() error{
		func() error { started <- struct{}{}; <-release; waitGroup.Done(); return nil },
		func() error { started <- struct{}{}; <-release; waitGroup.Done(); return nil },
	}
	result := make(chan error, 1)
	go func() { result <- Run(context.Background(), tasks...) }()
	<-started
	<-started
	close(release)
	waitGroup.Wait()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestContextWithoutParticipantTrackerPreservesParentContext(t *testing.T) {
	type key struct{}
	tracker := new(recordingTracker)
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "kept"))
	masked := ContextWithoutParticipantTracker(ContextWithParticipantTracker(parent, tracker))
	if masked.Value(key{}) != "kept" || AcquireParticipant(masked) != nil {
		t.Fatal("participant mask destroyed parent value or retained tracker")
	}
	cancel()
	if masked.Err() != context.Canceled {
		t.Fatalf("participant mask lost cancellation: %v", masked.Err())
	}
}
