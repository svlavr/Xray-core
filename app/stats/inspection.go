package stats

import (
	"fmt"

	"github.com/xtls/xray-core/common/uuid"
	featurestats "github.com/xtls/xray-core/features/stats"
)

var defaultObservationOptions = featurestats.ObservationOptions{
	MaxLive:      256,
	MaxTerminals: 1024,
	MaxBuckets:   1024,
}

func normalizeObservationOptions(options featurestats.ObservationOptions) featurestats.ObservationOptions {
	if options.MaxLive == 0 {
		options.MaxLive = defaultObservationOptions.MaxLive
	}
	if options.MaxTerminals == 0 {
		options.MaxTerminals = defaultObservationOptions.MaxTerminals
	}
	if options.MaxBuckets == 0 {
		options.MaxBuckets = defaultObservationOptions.MaxBuckets
	}
	return options
}

// EnableInspection enables the optional observation store before Manager.Start.
func (m *Manager) EnableInspection(options featurestats.ObservationOptions) (featurestats.FlowInspection, error) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.running {
		return nil, fmt.Errorf("inspection enablement is too late")
	}
	if m.inspection != nil {
		return nil, fmt.Errorf("inspection already enabled")
	}
	m.inspection = newInspectionStore(featurestats.RuntimeID(uuid.New()), normalizeObservationOptions(options))
	return m.inspection, nil
}

// Observation returns the admission store only while enabled and open.
func (m *Manager) Observation() featurestats.AdmissionStore {
	m.access.RLock()
	store := m.inspection
	m.access.RUnlock()
	if store == nil || store.closed.Load() {
		return nil
	}
	return store
}
