package observatory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/outbound"
)

type lifecycleSelector struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*lifecycleSelector) Type() interface{} { return outbound.ManagerType() }
func (*lifecycleSelector) Start() error      { return nil }
func (*lifecycleSelector) Close() error      { return nil }
func (*lifecycleSelector) GetHandler(string) outbound.Handler {
	return nil
}
func (*lifecycleSelector) GetDefaultHandler() outbound.Handler { return nil }
func (*lifecycleSelector) AddHandler(context.Context, outbound.Handler) error {
	return nil
}
func (*lifecycleSelector) RemoveHandler(context.Context, string) error { return nil }
func (*lifecycleSelector) ListHandlers(context.Context) []outbound.Handler {
	return nil
}

func (s *lifecycleSelector) Select([]string) []string {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return []string{"late"}
}

func TestObserverCloseWaitsForBackgroundReceipt(t *testing.T) {
	selector := &lifecycleSelector{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	o := &Observer{
		config: &Config{SubjectSelector: []string{"test"}},
		ctx:    context.Background(),
		ohm:    selector,
	}
	if err := o.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-selector.entered:
	case <-time.After(time.Second):
		t.Fatal("background selector did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- o.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the registered background task: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(selector.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the registered background task")
	}
	if len(o.status) != 0 {
		t.Fatal("selector result was published after Close sealed observation")
	}
}

func TestObserverConcurrentStartCloseIsTerminal(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		o := &Observer{
			config: &Config{SubjectSelector: []string{"test"}},
			ctx:    context.Background(),
			ohm:    &emptySelector{},
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-start; _ = o.Start() }()
		go func() { defer wg.Done(); <-start; _ = o.Start() }()
		go func() { defer wg.Done(); <-start; _ = o.Close() }()
		go func() { defer wg.Done(); <-start; _ = o.Close() }()
		close(start)
		wg.Wait()
		if !o.lifecycle.Sealed() {
			t.Fatalf("iteration %d: Close did not seal the lifecycle", iteration)
		}
		if err := o.Start(); err != nil {
			t.Fatalf("iteration %d: repeated Start returned %v", iteration, err)
		}
	}
}

func TestObserverObservationIsAnImmutableSnapshot(t *testing.T) {
	o := &Observer{status: []*OutboundStatus{{OutboundTag: "before", Delay: 7}}}
	message, err := o.GetObservation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := message.(*ObservationResult)
	if !o.updateStatusForResult("before", &ProbeResult{Alive: true, Delay: 42}) {
		t.Fatal("live status update was rejected before close")
	}
	if got := snapshot.Status[0].Delay; got != 7 {
		t.Fatalf("snapshot changed with live status: delay=%d", got)
	}
	snapshot.Status[0].OutboundTag = "caller-mutation"
	if got := o.status[0].OutboundTag; got != "before" {
		t.Fatalf("caller mutation escaped snapshot: outbound=%q", got)
	}
}

type emptySelector struct{}

func (*emptySelector) Type() interface{} { return outbound.ManagerType() }
func (*emptySelector) Start() error      { return nil }
func (*emptySelector) Close() error      { return nil }
func (*emptySelector) GetHandler(string) outbound.Handler {
	return nil
}
func (*emptySelector) GetDefaultHandler() outbound.Handler { return nil }
func (*emptySelector) AddHandler(context.Context, outbound.Handler) error {
	return nil
}
func (*emptySelector) RemoveHandler(context.Context, string) error { return nil }
func (*emptySelector) ListHandlers(context.Context) []outbound.Handler {
	return nil
}
func (*emptySelector) Select([]string) []string { return nil }
