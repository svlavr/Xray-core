package freedom

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
)

type timerTracker struct {
	acquired atomic.Int32
	released atomic.Int32
}

func (t *timerTracker) AcquireParticipant() task.ParticipantLease {
	t.acquired.Add(1)
	return &timerLease{tracker: t}
}

type timerLease struct {
	tracker *timerTracker
}

func (l *timerLease) AcquireParticipant() task.ParticipantLease {
	return l.tracker.AcquireParticipant()
}

func (l *timerLease) Release(error) {
	l.tracker.released.Add(1)
}

func TestParticipantTimerStopReleasesPreventedCallback(t *testing.T) {
	tracker := new(timerTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	timer := afterFuncWithParticipant(ctx, true, time.Hour, func() { t.Fatal("stopped callback ran") })
	if !timer.Stop() {
		t.Fatal("timer fired before stop")
	}
	timer.Stop()
	if tracker.acquired.Load() != 1 || tracker.released.Load() != 1 {
		t.Fatalf("got acquired=%d released=%d, want exactly 1/1", tracker.acquired.Load(), tracker.released.Load())
	}
}

func TestParticipantTimerFireReleasesAfterCallbackReturn(t *testing.T) {
	tracker := new(timerTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	started := make(chan struct{})
	finish := make(chan struct{})
	timer := afterFuncWithParticipant(ctx, true, 0, func() {
		close(started)
		<-finish
	})
	<-started
	if timer.Stop() {
		t.Fatal("running callback was reported stopped")
	}
	if tracker.released.Load() != 0 {
		t.Fatal("participant released before callback return")
	}
	close(finish)
	deadline := time.After(time.Second)
	for tracker.released.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("participant was not released after callback return")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestParticipantTimerExcludedPathDoesNotAcquire(t *testing.T) {
	tracker := new(timerTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	timer := afterFuncWithParticipant(ctx, false, time.Hour, func() {})
	timer.Stop()
	if tracker.acquired.Load() != 0 || tracker.released.Load() != 0 {
		t.Fatalf("excluded path changed F1 participants: acquired=%d released=%d", tracker.acquired.Load(), tracker.released.Load())
	}
}

func TestParticipantTimerUDPPathDoesNotAcquire(t *testing.T) {
	tracker := new(timerTracker)
	ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
	udpDestination := net.UDPDestination(net.LocalHostIP, 53)
	if shouldTrackBlockedTimer(ctx, udpDestination) {
		t.Fatal("UDP destination entered PR-F1 timer tracking")
	}
	timer := afterFuncWithParticipant(ctx, shouldTrackBlockedTimer(ctx, udpDestination), time.Hour, func() {})
	timer.Stop()
	if tracker.acquired.Load() != 0 || tracker.released.Load() != 0 {
		t.Fatalf("UDP path changed F1 participants: acquired=%d released=%d", tracker.acquired.Load(), tracker.released.Load())
	}
}

func TestParticipantTimerStopFireRaceReleasesExactlyOnce(t *testing.T) {
	const iterations = 1000
	for iteration := range iterations {
		tracker := new(timerTracker)
		ctx := task.ContextWithParticipantTracker(context.Background(), tracker)
		timer := afterFuncWithParticipant(ctx, true, 0, func() {})
		stopDone := make(chan struct{})
		go func() {
			timer.Stop()
			close(stopDone)
		}()
		<-stopDone
		deadline := time.Now().Add(time.Second)
		for tracker.released.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if tracker.acquired.Load() != 1 || tracker.released.Load() != 1 {
			t.Fatalf("iteration %d: got acquired=%d released=%d, want 1/1", iteration, tracker.acquired.Load(), tracker.released.Load())
		}
	}
}
