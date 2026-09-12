package flow

import (
	"reflect"
	"sync"
	"sync/atomic"

	feature_outbound "github.com/xtls/xray-core/features/outbound"
)

type carrierObservationBinding struct {
	observation CarrierObservation
	references  int
	conflicted  bool
}

type carrierObservationSnapshot struct {
	bindings map[feature_outbound.Handler]carrierObservationBinding
}

var (
	carrierObservationBindingAccess sync.Mutex
	carrierObservationBindings      atomic.Pointer[carrierObservationSnapshot]
)

// BindHandlerCarrierObservation associates an immutable descriptor with the
// exact handler instance. Binding and release happen only on handler-manager
// configuration paths; traffic paths use HandlerCarrierObservation's
// lock-free lookup and never invoke handler code.
func BindHandlerCarrierObservation(handler feature_outbound.Handler, observation CarrierObservation) func() {
	if handler == nil || !reflect.ValueOf(handler).Comparable() {
		return func() {}
	}

	carrierObservationBindingAccess.Lock()
	snapshot := cloneCarrierObservationSnapshot()
	binding, loaded := snapshot.bindings[handler]
	if !loaded {
		binding.observation = observation
	} else if binding.observation != observation {
		binding.conflicted = true
	}
	binding.references++
	snapshot.bindings[handler] = binding
	carrierObservationBindings.Store(snapshot)
	carrierObservationBindingAccess.Unlock()

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			carrierObservationBindingAccess.Lock()
			defer carrierObservationBindingAccess.Unlock()
			snapshot := cloneCarrierObservationSnapshot()
			binding, ok := snapshot.bindings[handler]
			if !ok {
				return
			}
			binding.references--
			if binding.references == 0 {
				delete(snapshot.bindings, handler)
			} else {
				snapshot.bindings[handler] = binding
			}
			carrierObservationBindings.Store(snapshot)
		})
	}
}

// HandlerCarrierObservation returns the immutable descriptor registered for
// the exact handler. Unknown, custom, released, incomparable, or conflicting
// handler bindings fail proof closed without invoking handler methods.
func HandlerCarrierObservation(handler feature_outbound.Handler) (CarrierObservation, bool) {
	if handler == nil || !reflect.ValueOf(handler).Comparable() {
		return CarrierObservation{}, false
	}
	snapshot := carrierObservationBindings.Load()
	if snapshot == nil {
		return CarrierObservation{}, false
	}
	binding, ok := snapshot.bindings[handler]
	if !ok {
		return CarrierObservation{}, false
	}
	if binding.conflicted {
		return CarrierObservation{}, false
	}
	return binding.observation, true
}

func cloneCarrierObservationSnapshot() *carrierObservationSnapshot {
	bindings := make(map[feature_outbound.Handler]carrierObservationBinding)
	if current := carrierObservationBindings.Load(); current != nil {
		for handler, binding := range current.bindings {
			bindings[handler] = binding
		}
	}
	return &carrierObservationSnapshot{bindings: bindings}
}
