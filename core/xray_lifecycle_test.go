package core

import (
	"context"
	"fmt"
	"runtime"
	"testing"
)

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
