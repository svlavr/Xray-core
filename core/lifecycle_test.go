package core

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type lifecycleFeature struct {
	name   string
	start  func() error
	close  func() error
	signal func()
}

type phasedLifecycleFeature struct {
	*lifecycleFeature
	phase    features.ShutdownPhase
	join     func() error
	finalize func() error
}

func (f *phasedLifecycleFeature) ShutdownPhase() features.ShutdownPhase { return f.phase }
func (f *phasedLifecycleFeature) AdoptObservationShutdown() (features.ObservationShutdown, error) {
	return f, nil
}

func (f *phasedLifecycleFeature) JoinShutdown() error {
	if f.join != nil {
		return f.join()
	}
	return f.Close()
}

func (f *phasedLifecycleFeature) FinalizeObservation() error {
	if f.finalize != nil {
		return f.finalize()
	}
	return nil
}

type panickingShutdownPhaseFeature struct{ *lifecycleFeature }

func (*panickingShutdownPhaseFeature) ShutdownPhase() features.ShutdownPhase {
	panic("phase panic")
}

type canonicalLifecycleDispatcher struct{ *lifecycleFeature }

func (*canonicalLifecycleDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*canonicalLifecycleDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (*canonicalLifecycleDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (*lifecycleFeature) Type() interface{} { return (*lifecycleFeature)(nil) }
func (f *lifecycleFeature) Start() error {
	if f.start != nil {
		return f.start()
	}
	return nil
}

func (f *lifecycleFeature) Close() error {
	if f.close != nil {
		return f.close()
	}
	return nil
}

func (f *lifecycleFeature) SignalStop() {
	if f.signal != nil {
		f.signal()
	}
}

func TestInstanceStartRollsBackEveryAdoptedFeature(t *testing.T) {
	var mu sync.Mutex
	var order []string
	appendOrder := func(value string) { mu.Lock(); order = append(order, value); mu.Unlock() }
	f1 := &lifecycleFeature{name: "one", start: func() error { appendOrder("start-one"); return nil }, close: func() error { appendOrder("close-one"); return nil }}
	f2 := &lifecycleFeature{name: "two", start: func() error { appendOrder("start-two"); return errors.New("start failure") }, close: func() error { appendOrder("close-two"); return nil }}
	f3 := &lifecycleFeature{name: "three", start: func() error { appendOrder("start-three"); return nil }, close: func() error { appendOrder("close-three"); return nil }}
	instance := &Instance{ctx: context.Background(), features: []features.Feature{f1, f2, f3}}
	if err := instance.Start(); err == nil {
		t.Fatal("Start succeeded")
	}
	if got, want := order, []string{"start-one", "start-two", "close-one", "close-two", "close-three"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("repeated Close = %v", err)
	}
}

func TestInstanceFailedStartStoresCombinedRunnerReceipt(t *testing.T) {
	startFailure := errors.New("start failure")
	closeFailure := errors.New("close failure")
	feature := &lifecycleFeature{
		start: func() error { return startFailure },
		close: func() error { return closeFailure },
	}
	instance := &Instance{ctx: context.Background(), features: []features.Feature{feature}}
	err := instance.Start()
	if err == nil || !strings.Contains(err.Error(), startFailure.Error()) || !strings.Contains(err.Error(), closeFailure.Error()) {
		t.Fatalf("Start error = %v, want combined start and rollback failures", err)
	}
	if instance.startResult == nil || instance.startResult.Error() != err.Error() {
		t.Fatalf("saved start receipt = %v, runner receipt = %v", instance.startResult, err)
	}
	if closeErr := instance.Close(); closeErr == nil || !strings.Contains(closeErr.Error(), closeFailure.Error()) {
		t.Fatalf("Close receipt = %v, want rollback close failure", closeErr)
	}
}

func TestInstanceCloseDuringStartSealsLaterFeatureAdmission(t *testing.T) {
	tests := []struct {
		name     string
		instance func() *Instance
	}{
		{name: "real lifecycle owners", instance: func() *Instance { return newInstance(context.Background()) }},
		{name: "no lifecycle owners", instance: func() *Instance { return &Instance{ctx: context.Background()} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var firstClosed atomic.Int32
			var secondStarted atomic.Bool
			var secondClosed atomic.Int32
			first := &lifecycleFeature{
				start: func() error { close(entered); <-release; return nil },
				close: func() error { firstClosed.Add(1); return nil },
			}
			second := &lifecycleFeature{
				start: func() error { secondStarted.Store(true); return nil },
				close: func() error { secondClosed.Add(1); return nil },
			}
			instance := test.instance()
			instance.features = []features.Feature{first, second}
			startDone := make(chan error, 1)
			go func() { startDone <- instance.Start() }()
			<-entered
			closeDone := make(chan error, 1)
			go func() { closeDone <- instance.Close() }()

			deadline := time.Now().Add(time.Second)
			for {
				instance.statusLock.Lock()
				sealed := instance.startupSealed
				instance.statusLock.Unlock()
				if sealed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Close did not seal startup")
				}
				runtime.Gosched()
			}
			select {
			case err := <-closeDone:
				t.Fatalf("Close returned while admitted Start runs: %v", err)
			default:
			}
			close(release)
			if err := <-startDone; err == nil || !strings.Contains(err.Error(), "instance closed while starting") {
				t.Fatalf("Start error = %v, want close-during-start rollback", err)
			}
			if err := <-closeDone; err != nil {
				t.Fatalf("Close = %v", err)
			}
			if secondStarted.Load() {
				t.Fatal("later feature started after Close sealed startup")
			}
			if got := firstClosed.Load(); got != 1 {
				t.Fatalf("first feature Close count = %d, want 1", got)
			}
			if got := secondClosed.Load(); got != 1 {
				t.Fatalf("unstarted adopted feature Close count = %d, want 1", got)
			}
			if instance.IsRunning() {
				t.Fatal("instance committed RUNNING after Close sealed startup")
			}
		})
	}
}

func TestInstanceNormalStartThenClose(t *testing.T) {
	var starts atomic.Int32
	var closes atomic.Int32
	feature := &lifecycleFeature{
		start: func() error { starts.Add(1); return nil },
		close: func() error { closes.Add(1); return nil },
	}
	instance := &Instance{ctx: context.Background(), features: []features.Feature{feature}}
	if err := instance.Start(); err != nil {
		t.Fatalf("Start = %v", err)
	}
	if !instance.IsRunning() {
		t.Fatal("instance is not RUNNING after Start")
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("Start count = %d, want 1", got)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("Close count = %d, want 1", got)
	}
}

func TestInstanceSignalsEveryFeatureBeforeFirstJoin(t *testing.T) {
	secondSignaled := make(chan struct{})
	var mu sync.Mutex
	var order []string
	appendOrder := func(value string) { mu.Lock(); order = append(order, value); mu.Unlock() }
	first := &lifecycleFeature{
		signal: func() { appendOrder("signal-first") },
		close: func() error {
			appendOrder("close-first")
			select {
			case <-secondSignaled:
				return nil
			case <-time.After(time.Second):
				return errors.New("second feature was not signaled")
			}
		},
	}
	second := &lifecycleFeature{
		signal: func() { appendOrder("signal-second"); close(secondSignaled) },
		close:  func() error { appendOrder("close-second"); return nil },
	}
	instance := &Instance{ctx: context.Background(), features: []features.Feature{first, second}}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := order, []string{"signal-first", "signal-second", "close-first", "close-second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestInstanceContinuesSignalingAfterSignalPanic(t *testing.T) {
	secondSignaled := make(chan struct{})
	first := &lifecycleFeature{signal: func() { panic("stop panic") }}
	second := &lifecycleFeature{signal: func() { close(secondSignaled) }}
	instance := &Instance{ctx: context.Background(), features: []features.Feature{first, second}}
	err := instance.Close()
	if err == nil || !strings.Contains(err.Error(), "stop panic") {
		t.Fatalf("Close error = %v, want recovered signal panic", err)
	}
	select {
	case <-secondSignaled:
	default:
		t.Fatal("later feature was not signaled after earlier panic")
	}
}

func TestInstanceShutdownUsesDependencyPhasesAndStagedObservation(t *testing.T) {
	var mu sync.Mutex
	var order []string
	appendOrder := func(value string) { mu.Lock(); order = append(order, value); mu.Unlock() }
	newPhased := func(name string, phase features.ShutdownPhase) *phasedLifecycleFeature {
		return &phasedLifecycleFeature{
			lifecycleFeature: &lifecycleFeature{
				name:   name,
				signal: func() { appendOrder("signal-" + name) },
				close:  func() error { appendOrder("close-" + name); return nil },
			},
			phase: phase,
		}
	}

	logger := newPhased("logger", features.ShutdownPhaseLogger)
	dependency := newPhased("dependency", features.ShutdownPhaseDependency)
	dispatcher := newPhased("dispatcher", features.ShutdownPhaseDispatcher)
	owner := newPhased("owner", features.ShutdownPhaseTrafficOwner)
	preOwner := newPhased("pre-owner", features.ShutdownPhasePreOwner)
	stats := newPhased("stats", features.ShutdownPhaseStats)
	dispatcher.join = func() error { appendOrder("join-dispatcher"); return nil }
	dispatcher.finalize = func() error { appendOrder("finalize-observation"); return nil }
	instance := &Instance{ctx: context.Background()}
	for _, feature := range []features.Feature{logger, dependency, dispatcher, owner, preOwner, stats} {
		if err := instance.AddFeature(feature); err != nil {
			t.Fatal(err)
		}
	}

	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"signal-logger", "signal-dependency", "signal-dispatcher", "signal-owner", "signal-pre-owner", "signal-stats",
		"close-pre-owner", "close-owner", "join-dispatcher", "close-dependency", "finalize-observation", "close-stats", "close-logger",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestInstanceObservationFinalizationWaitsForOwnerReceipt(t *testing.T) {
	ownerEntered := make(chan struct{})
	releaseOwner := make(chan struct{})
	receiptPublished := make(chan struct{})
	finalized := make(chan struct{})
	owner := &phasedLifecycleFeature{
		lifecycleFeature: &lifecycleFeature{close: func() error {
			close(ownerEntered)
			<-releaseOwner
			close(receiptPublished)
			return nil
		}},
		phase: features.ShutdownPhaseTrafficOwner,
	}
	dispatcher := &phasedLifecycleFeature{
		lifecycleFeature: &lifecycleFeature{},
		phase:            features.ShutdownPhaseDispatcher,
		join:             func() error { return nil },
		finalize: func() error {
			select {
			case <-receiptPublished:
				close(finalized)
				return nil
			default:
				return errors.New("observation finalized before owner receipt")
			}
		},
	}
	instance := &Instance{ctx: context.Background()}
	for _, feature := range []features.Feature{dispatcher, owner} {
		if err := instance.AddFeature(feature); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- instance.Close() }()
	<-ownerEntered
	select {
	case <-finalized:
		t.Fatal("observation finalized while traffic owner was still running")
	default:
	}
	close(releaseOwner)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finalized:
	default:
		t.Fatal("observation was not finalized after owner receipt")
	}
}

func TestAddFeatureRejectsInvalidOrPanickingShutdownPhase(t *testing.T) {
	invalidClosed := false
	invalid := &phasedLifecycleFeature{lifecycleFeature: &lifecycleFeature{close: func() error { invalidClosed = true; return nil }}, phase: features.ShutdownPhase(255)}
	instance := &Instance{ctx: context.Background()}
	if err := instance.AddFeature(invalid); err == nil || !strings.Contains(err.Error(), "invalid feature shutdown phase") {
		t.Fatalf("invalid phase error = %v", err)
	}
	panicking := &panickingShutdownPhaseFeature{lifecycleFeature: &lifecycleFeature{}}
	if err := instance.AddFeature(panicking); err == nil || !strings.Contains(err.Error(), "phase panic") {
		t.Fatalf("panicking phase error = %v", err)
	}
	if len(instance.features) != 0 {
		t.Fatalf("invalid features were registered: %d", len(instance.features))
	}
	if !invalidClosed {
		t.Fatal("invalid unadopted feature was not closed")
	}
}

func TestCanonicalDispatcherUsesDispatcherShutdownPhaseWithoutMarker(t *testing.T) {
	phase, err := featureShutdownPhase(&canonicalLifecycleDispatcher{lifecycleFeature: &lifecycleFeature{}})
	if err != nil {
		t.Fatal(err)
	}
	if phase != features.ShutdownPhaseDispatcher {
		t.Fatalf("canonical dispatcher phase = %d, want %d", phase, features.ShutdownPhaseDispatcher)
	}
}

func TestShutdownErrorDoesNotSkipObservationStatsOrLogger(t *testing.T) {
	var order []string
	owner := &phasedLifecycleFeature{
		lifecycleFeature: &lifecycleFeature{close: func() error { panic("owner close panic") }},
		phase:            features.ShutdownPhaseTrafficOwner,
	}
	dispatcher := &phasedLifecycleFeature{
		lifecycleFeature: &lifecycleFeature{},
		phase:            features.ShutdownPhaseDispatcher,
		join:             func() error { order = append(order, "join"); return nil },
		finalize:         func() error { order = append(order, "finalize"); return nil },
	}
	stats := &phasedLifecycleFeature{
		lifecycleFeature: &lifecycleFeature{close: func() error { order = append(order, "stats"); return nil }},
		phase:            features.ShutdownPhaseStats,
	}
	logger := &phasedLifecycleFeature{
		lifecycleFeature: &lifecycleFeature{close: func() error { order = append(order, "logger"); return nil }},
		phase:            features.ShutdownPhaseLogger,
	}
	instance := &Instance{ctx: context.Background()}
	for _, feature := range []features.Feature{logger, dispatcher, owner, stats} {
		if addErr := instance.AddFeature(feature); addErr != nil {
			t.Fatal(addErr)
		}
	}
	err := instance.Close()
	if err == nil || !strings.Contains(err.Error(), "owner close panic") {
		t.Fatalf("Close error = %v, want recovered owner panic", err)
	}
	if want := []string{"join", "finalize", "stats", "logger"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order after owner panic = %v, want %v", order, want)
	}
}

func TestShutdownFailureDoesNotCrossObservationBarriers(t *testing.T) {
	tests := []struct {
		name          string
		joinErr       error
		finalizeErr   error
		wantOrder     []string
		wantErrorText string
	}{
		{name: "join", joinErr: errors.New("join failed"), wantOrder: []string{"join"}, wantErrorText: "join failed"},
		{name: "finalize", finalizeErr: errors.New("finalize failed"), wantOrder: []string{"join", "dependency", "finalize"}, wantErrorText: "finalize failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var order []string
			dispatcher := &phasedLifecycleFeature{
				lifecycleFeature: &lifecycleFeature{},
				phase:            features.ShutdownPhaseDispatcher,
				join: func() error {
					order = append(order, "join")
					return test.joinErr
				},
				finalize: func() error {
					order = append(order, "finalize")
					return test.finalizeErr
				},
			}
			dependency := &phasedLifecycleFeature{
				lifecycleFeature: &lifecycleFeature{close: func() error { order = append(order, "dependency"); return nil }},
				phase:            features.ShutdownPhaseDependency,
			}
			stats := &phasedLifecycleFeature{
				lifecycleFeature: &lifecycleFeature{close: func() error { order = append(order, "stats"); return nil }},
				phase:            features.ShutdownPhaseStats,
			}
			logger := &phasedLifecycleFeature{
				lifecycleFeature: &lifecycleFeature{close: func() error { order = append(order, "logger"); return nil }},
				phase:            features.ShutdownPhaseLogger,
			}
			instance := &Instance{ctx: context.Background()}
			for _, feature := range []features.Feature{logger, dependency, dispatcher, stats} {
				if err := instance.AddFeature(feature); err != nil {
					t.Fatal(err)
				}
			}
			err := instance.Close()
			if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Fatalf("Close error = %v, want %q", err, test.wantErrorText)
			}
			if !reflect.DeepEqual(order, test.wantOrder) {
				t.Fatalf("order = %v, want %v", order, test.wantOrder)
			}
		})
	}
}
