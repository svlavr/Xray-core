package signal

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/task"
)

func TestActivityTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := CancelAfterInactivity(ctx, cancel, time.Second*4)
	time.Sleep(time.Second * 6)
	if ctx.Err() == nil {
		t.Error("expected some error, but got nil")
	}
	runtime.KeepAlive(timer)
}

func TestActivityTimerUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := CancelAfterInactivity(ctx, cancel, time.Second*10)
	time.Sleep(time.Second * 3)
	if ctx.Err() != nil {
		t.Error("expected nil, but got ", ctx.Err().Error())
	}
	timer.SetTimeout(time.Second * 1)
	time.Sleep(time.Second * 2)
	if ctx.Err() == nil {
		t.Error("expected some error, but got nil")
	}
	runtime.KeepAlive(timer)
}

func TestActivityTimerNonBlocking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := CancelAfterInactivity(ctx, cancel, 0)
	time.Sleep(time.Second * 1)
	select {
	case <-ctx.Done():
	default:
		t.Error("context not done")
	}
	timer.SetTimeout(0)
	timer.SetTimeout(1)
	timer.SetTimeout(2)
}

func TestActivityTimerZeroTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := CancelAfterInactivity(ctx, cancel, 0)
	select {
	case <-ctx.Done():
	default:
		t.Error("context not done")
	}
	runtime.KeepAlive(timer)
}

func TestActivityTimerOwnerCancellationAndCloseReceipt(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	var calls atomic.Int32
	timer := CancelAfterInactivity(owner, func() {
		calls.Add(1)
		close(callbackEntered)
		<-releaseCallback
	}, time.Hour)
	cancelOwner()
	<-callbackEntered
	closeDone := make(chan error, 1)
	go func() { closeDone <- timer.CloseAndWait() }()
	select {
	case err := <-closeDone:
		t.Fatalf("CloseAndWait returned before callback receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCallback)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseAndWait did not join timer callback")
	}
	if calls.Load() != 1 {
		t.Fatalf("timer callback calls = %d, want 1", calls.Load())
	}
	if err := timer.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestActivityTimerCloseWaitsLosingOwnerCallback(t *testing.T) {
	ownerDone := make(chan struct{})
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: func() {},
		stopOwner: func() bool { return false },
		ownerDone: ownerDone,
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- timer.CloseAndWait() }()
	select {
	case err := <-closeDone:
		t.Fatalf("CloseAndWait returned before owner callback receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(ownerDone)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseAndWait did not observe owner callback receipt")
	}
}

func TestActivityTimerReplacementJoinsActiveOldCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: cancel,
	}
	oldEntered := make(chan struct{})
	releaseOld := make(chan struct{})
	oldTask := &task.Periodic{
		Interval: time.Hour,
		Execute: func() error {
			close(oldEntered)
			<-releaseOld
			return timer.check()
		},
	}
	timer.checkTask = oldTask
	timer.Update()
	oldStartDone := make(chan error, 1)
	go func() { oldStartDone <- oldTask.Start() }()
	<-oldEntered
	replaceDone := make(chan struct{})
	go func() {
		timer.SetTimeout(time.Hour)
		close(replaceDone)
	}()
	select {
	case <-replaceDone:
		t.Fatal("SetTimeout replaced an active old callback without joining it")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseOld)
	if err := <-oldStartDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-replaceDone:
	case <-time.After(time.Second):
		t.Fatal("SetTimeout did not complete after old callback receipt")
	}
	if ctx.Err() != nil {
		t.Fatalf("replacement consumed the new timer token: %v", ctx.Err())
	}
	if err := timer.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
