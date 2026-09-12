package task

import (
	"errors"
	"sync"
	"time"
)

// Periodic is a task that runs periodically.
type Periodic struct {
	// Interval of the task being run
	Interval time.Duration
	// Execute is the task function
	Execute func() error

	access      sync.Mutex
	timer       *time.Timer
	running     bool
	waiters     int
	generation  uint64
	receipts    int
	receiptDone chan struct{}
}

func (t *Periodic) hasClosed() bool {
	t.access.Lock()
	defer t.access.Unlock()

	return !t.running
}

func (t *Periodic) reserveLocked() {
	if t.receipts == 0 {
		t.receiptDone = make(chan struct{})
	}
	t.receipts++
}

func (t *Periodic) releaseLocked() {
	t.receipts--
	if t.receipts == 0 {
		close(t.receiptDone)
		t.receiptDone = nil
	}
}

func (t *Periodic) stopTimerLocked() {
	if t.timer == nil {
		return
	}
	timer := t.timer
	t.timer = nil
	if timer.Stop() {
		t.releaseLocked()
	}
}

func (t *Periodic) checkedExecute(generation uint64) error {
	t.access.Lock()
	if !t.running || t.generation != generation {
		t.releaseLocked()
		t.access.Unlock()
		return nil
	}
	t.timer = nil
	t.access.Unlock()
	defer func() {
		t.access.Lock()
		t.releaseLocked()
		t.access.Unlock()
	}()

	if err := t.Execute(); err != nil {
		t.access.Lock()
		if t.generation == generation {
			t.running = false
		}
		t.access.Unlock()
		return err
	}

	t.access.Lock()
	defer t.access.Unlock()

	if !t.running || t.generation != generation {
		return nil
	}

	t.reserveLocked()
	t.timer = time.AfterFunc(t.Interval, func() {
		t.checkedExecute(generation)
	})

	return nil
}

// Start implements common.Runnable.
func (t *Periodic) Start() error {
	t.access.Lock()
	if t.waiters != 0 {
		t.access.Unlock()
		return errors.New("periodic task is closing")
	}
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.generation++
	generation := t.generation
	t.reserveLocked()
	t.access.Unlock()

	if err := t.checkedExecute(generation); err != nil {
		return err
	}

	return nil
}

// Close implements common.Closable.
func (t *Periodic) Close() error {
	t.access.Lock()
	defer t.access.Unlock()

	t.running = false
	t.stopTimerLocked()

	return nil
}

// CloseAndWait prevents future callbacks and waits for callbacks already
// executing. A callback must call Close (not CloseAndWait) on itself.
func (t *Periodic) CloseAndWait() error {
	t.access.Lock()
	t.waiters++
	t.running = false
	t.stopTimerLocked()
	done := t.receiptDone
	receipts := t.receipts
	t.access.Unlock()
	if receipts != 0 {
		<-done
	}
	t.access.Lock()
	t.waiters--
	t.access.Unlock()
	return nil
}
