package task

import "sync"

// Lifecycle is a small seal-and-receipt fence.  It deliberately does not
// assign a terminal meaning to Seal: owners still decide which receipts they
// can join.
type Lifecycle struct {
	mu     sync.Mutex
	sealed bool
	active int
	done   chan struct{}
	closed bool
}

func (l *Lifecycle) Acquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed {
		return false
	}
	l.active++
	return true
}

func (l *Lifecycle) Release() {
	l.mu.Lock()
	l.active--
	l.closeDoneLocked()
	l.mu.Unlock()
}

func (l *Lifecycle) Seal() {
	l.mu.Lock()
	l.sealed = true
	l.closeDoneLocked()
	l.mu.Unlock()
}

func (l *Lifecycle) Sealed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sealed
}

func (l *Lifecycle) Done() <-chan struct{} {
	l.mu.Lock()
	if l.done == nil {
		l.done = make(chan struct{})
	}
	done := l.done
	l.closeDoneLocked()
	l.mu.Unlock()
	return done
}

func (l *Lifecycle) Wait() { <-l.Done() }

func (l *Lifecycle) closeDoneLocked() {
	if !l.sealed || l.active != 0 || l.closed {
		return
	}
	if l.done == nil {
		l.done = make(chan struct{})
	}
	close(l.done)
	l.closed = true
}
