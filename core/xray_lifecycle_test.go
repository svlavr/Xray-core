package core

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

type lifecycleStateFeature struct {
	instance *Instance
}

func (*lifecycleStateFeature) Type() interface{} { return (*lifecycleStateFeature)(nil) }
func (f *lifecycleStateFeature) Start() error {
	if !f.instance.IsRunning() {
		return fmt.Errorf("Start callback cannot observe running instance")
	}
	return nil
}

func (f *lifecycleStateFeature) Close() error {
	if f.instance.IsRunning() {
		return fmt.Errorf("Close callback observes running instance")
	}
	return nil
}

func TestInstanceLifecycleStateCallbacks(t *testing.T) {
	s := &Instance{ctx: context.Background()}
	if err := s.AddFeature(&lifecycleStateFeature{instance: s}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		if err := s.Start(); err != nil {
			done <- err
			return
		}
		done <- s.Close()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("feature callback deadlocked reading instance state")
	}
}

func TestInstanceLifecycleConcurrentState(t *testing.T) {
	s := &Instance{ctx: context.Background()}
	ready, stop, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		close(ready)
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.IsRunning()
				runtime.Gosched()
			}
		}
	}()
	<-ready
	defer func() { close(stop); <-joined }()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if !s.IsRunning() {
		t.Fatal("started instance is not running")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.IsRunning() {
		t.Fatal("closed instance is running")
	}
}

type runningAddedFeature struct {
	starts int
	fail   bool
}

func (*runningAddedFeature) Type() interface{} { return (*runningAddedFeature)(nil) }
func (f *runningAddedFeature) Start() error {
	f.starts++
	if f.fail {
		return fmt.Errorf("native feature start failure")
	}
	return nil
}
func (*runningAddedFeature) Close() error { return nil }

func TestInstanceAddFeatureNativeRunningBehavior(t *testing.T) {
	s := &Instance{ctx: context.Background()}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, fail := range []bool{false, true} {
		f := &runningAddedFeature{fail: fail}
		if err := s.AddFeature(f); err != nil || f.starts != 1 || s.GetFeature(f.Type()) != nil {
			t.Fatalf("running AddFeature changed native start/log/no-registration behavior: %d %v", f.starts, err)
		}
	}
}
