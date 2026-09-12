package signal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/task"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	mu        sync.RWMutex
	replaceMu sync.Mutex
	updated   chan struct{}
	checkTask *task.Periodic
	onTimeout func()
	stopOwner func() bool
	ownerDone <-chan struct{}
	consumed  atomic.Bool
	once      sync.Once
}

func (t *ActivityTimer) Update() {
	select {
	case t.updated <- struct{}{}:
	default:
	}
}

func (t *ActivityTimer) check() error {
	select {
	case <-t.updated:
	default:
		t.finish()
	}
	return nil
}

func (t *ActivityTimer) finish() {
	t.once.Do(func() {
		t.consumed.Store(true)
		t.mu.Lock()
		checkTask := t.checkTask
		stopOwner := t.stopOwner
		t.mu.Unlock()
		if stopOwner != nil {
			stopOwner()
		}
		common.CloseIfExists(checkTask)
		t.onTimeout()
	})
}

// CloseAndWait consumes the timer, runs its cancellation callback exactly
// once, and waits for an already-running periodic check to return.
func (t *ActivityTimer) CloseAndWait() error {
	if t == nil {
		return nil
	}
	t.replaceMu.Lock()
	defer t.replaceMu.Unlock()
	t.finish()
	t.mu.RLock()
	checkTask := t.checkTask
	t.mu.RUnlock()
	if checkTask != nil {
		if err := checkTask.CloseAndWait(); err != nil {
			return err
		}
	}
	t.mu.RLock()
	ownerDone := t.ownerDone
	t.mu.RUnlock()
	if ownerDone != nil {
		<-ownerDone
	}
	return nil
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if t.consumed.Load() {
		return
	}
	if timeout == 0 {
		t.finish()
		return
	}

	t.replaceMu.Lock()
	defer t.replaceMu.Unlock()
	if t.consumed.Load() {
		return
	}
	t.mu.Lock()
	oldCheckTask := t.checkTask
	t.checkTask = nil
	t.mu.Unlock()
	if oldCheckTask != nil {
		_ = oldCheckTask.CloseAndWait()
	}
	if t.consumed.Load() {
		return
	}
	newCheckTask := &task.Periodic{
		Interval: timeout,
		Execute:  t.check,
	}
	t.Update()
	common.Must(newCheckTask.Start())
	t.mu.Lock()
	if t.consumed.Load() {
		t.mu.Unlock()
		_ = newCheckTask.CloseAndWait()
		return
	}
	t.checkTask = newCheckTask
	t.mu.Unlock()
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	ownerDone := make(chan struct{})
	var ownerDoneOnce sync.Once
	completeOwner := func() {
		ownerDoneOnce.Do(func() { close(ownerDone) })
	}
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: cancel,
		ownerDone: ownerDone,
	}
	rawStopOwner := context.AfterFunc(ctx, func() {
		defer completeOwner()
		timer.finish()
	})
	stopOwner := func() bool {
		stopped := rawStopOwner()
		if stopped {
			completeOwner()
		}
		return stopped
	}
	timer.mu.Lock()
	timer.stopOwner = stopOwner
	consumed := timer.consumed.Load()
	timer.mu.Unlock()
	if consumed {
		stopOwner()
	}
	timer.SetTimeout(timeout)
	return timer
}
