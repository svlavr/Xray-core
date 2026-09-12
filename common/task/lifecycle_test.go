package task

import (
	"sync"
	"testing"
	"time"
)

func TestLifecycleSealWaitsForWinningLease(t *testing.T) {
	var lifecycle Lifecycle
	if !lifecycle.Acquire() {
		t.Fatal("initial acquire was rejected")
	}
	lifecycle.Seal()
	if lifecycle.Acquire() {
		t.Fatal("acquire succeeded after seal")
	}
	done := make(chan struct{})
	go func() {
		lifecycle.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("wait completed before the winning lease released")
	case <-time.After(20 * time.Millisecond):
	}
	lifecycle.Release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wait did not complete after release")
	}
}

func TestLifecycleAcquireSealRaceLeavesNoLateLease(t *testing.T) {
	for range 1000 {
		var lifecycle Lifecycle
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if lifecycle.Acquire() {
				lifecycle.Release()
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			lifecycle.Seal()
		}()
		close(start)
		wg.Wait()
		lifecycle.Wait()
		if lifecycle.Acquire() {
			t.Fatal("late acquire succeeded")
		}
	}
}

func TestPeriodicCloseAndWaitRejectsConcurrentRestart(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &Periodic{Interval: time.Hour, Execute: func() error {
		close(started)
		<-release
		return nil
	}}
	startResult := make(chan error, 1)
	go func() { startResult <- p.Start() }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- p.CloseAndWait() }()
	for {
		p.access.Lock()
		waiting := p.waiters != 0
		p.access.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := p.Start(); err == nil {
		t.Fatal("concurrent Start succeeded while CloseAndWait owned the receipt")
	}
	close(release)
	if err := <-startResult; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestPeriodicMultipleCloseWaitersHoldRestartFence(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &Periodic{Interval: time.Hour, Execute: func() error {
		close(started)
		<-release
		return nil
	}}
	go p.Start()
	<-started
	closed := make(chan error, 2)
	go func() { closed <- p.CloseAndWait() }()
	go func() { closed <- p.CloseAndWait() }()
	for {
		p.access.Lock()
		waiters := p.waiters
		p.access.Unlock()
		if waiters == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := p.Start(); err == nil {
		t.Fatal("Start succeeded while multiple CloseAndWait callers owned the receipt")
	}
	close(release)
	for range 2 {
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPeriodicCloseAndWaitJoinsFiredScheduledWrapper(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &Periodic{Interval: time.Hour, Execute: func() error { return nil }}
	p.access.Lock()
	p.running = true
	p.generation = 1
	p.reserveLocked()
	p.timer = time.AfterFunc(0, func() {
		close(started)
		<-release
		_ = p.checkedExecute(1)
	})
	p.access.Unlock()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- p.CloseAndWait() }()
	select {
	case err := <-closed:
		t.Fatalf("CloseAndWait returned before fired callback wrapper: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseAndWait did not join fired callback wrapper")
	}
}
