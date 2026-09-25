package stats

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"sync/atomic"

	featurestats "github.com/xtls/xray-core/features/stats"
)

var defaultObservationOptions = featurestats.ObservationOptions{
	MaxLive:         256,
	MaxTerminals:    1024,
	MaxBuckets:      1024,
	MaxClose:        64,
	MaxRouteSteps:   4,
	MaxDestinations: 8,
}

func normalizeObservationOptions(options featurestats.ObservationOptions) (featurestats.ObservationOptions, error) {
	values := []*uint32{
		&options.MaxLive,
		&options.MaxTerminals,
		&options.MaxBuckets,
		&options.MaxClose,
		&options.MaxRouteSteps,
		&options.MaxDestinations,
	}
	maxima := []uint32{
		defaultObservationOptions.MaxLive,
		defaultObservationOptions.MaxTerminals,
		defaultObservationOptions.MaxBuckets,
		defaultObservationOptions.MaxClose,
		defaultObservationOptions.MaxRouteSteps,
		defaultObservationOptions.MaxDestinations,
	}
	for i, value := range values {
		if *value == 0 {
			*value = maxima[i]
			continue
		}
		if *value > maxima[i] {
			return featurestats.ObservationOptions{}, fmt.Errorf("%w: option exceeds reviewed maximum", featurestats.ErrInspectionLimit)
		}
	}
	return options, nil
}

func newRuntimeID(reader io.Reader) (featurestats.RuntimeID, error) {
	var runtime featurestats.RuntimeID
	if _, err := io.ReadFull(reader, runtime[:]); err != nil {
		return featurestats.RuntimeID{}, fmt.Errorf("%w: %v", featurestats.ErrInspectionEntropy, err)
	}
	if runtime == (featurestats.RuntimeID{}) {
		return featurestats.RuntimeID{}, fmt.Errorf("%w: runtime ID is zero", featurestats.ErrInspectionEntropy)
	}
	return runtime, nil
}

// EnableInspection enables the optional observation store. It must be called
// before Manager.Start and may succeed only once.
func (m *Manager) EnableInspection(options featurestats.ObservationOptions) (featurestats.FlowInspection, error) {
	limits, err := normalizeObservationOptions(options)
	if err != nil {
		return nil, err
	}
	runtime, err := newRuntimeID(rand.Reader)
	if err != nil {
		return nil, err
	}

	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		return nil, featurestats.ErrInspectionTooLate
	}
	if m.inspection != nil {
		return nil, featurestats.ErrInspectionAlreadyEnabled
	}
	m.inspection = newInspectionStore(runtime, limits)
	return m.inspection, nil
}

// Observation returns the admission store only while enabled and open.
func (m *Manager) Observation() featurestats.AdmissionStore {
	m.access.RLock()
	store := m.inspection
	m.access.RUnlock()
	if store == nil || store.isClosed() {
		return nil
	}
	return store
}

type saturatingUint64 struct {
	value     atomic.Uint64
	saturated atomic.Bool
}

func (v *saturatingUint64) add(delta uint64) bool {
	if delta == 0 {
		return false
	}
	for {
		old := v.value.Load()
		if old == math.MaxUint64 {
			v.saturated.Store(true)
			return true
		}
		if delta > math.MaxUint64-old {
			if v.value.CompareAndSwap(old, math.MaxUint64) {
				v.saturated.Store(true)
				return true
			}
			continue
		}
		if v.value.CompareAndSwap(old, old+delta) {
			return false
		}
	}
}

func (v *saturatingUint64) load() uint64 {
	return v.value.Load()
}
