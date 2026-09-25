package core

import (
	"fmt"

	"github.com/xtls/xray-core/features/stats"
)

// EnableFlowInspection enables the optional in-process observation capability.
// Enablement is intentionally limited to the interval before Instance.Start.
func EnableFlowInspection(instance *Instance, options stats.ObservationOptions) (stats.FlowInspection, error) {
	if instance == nil {
		return nil, fmt.Errorf("%w: nil instance", stats.ErrInspectionUnavailable)
	}
	instance.statusLock.Lock()
	defer instance.statusLock.Unlock()
	if instance.started || instance.running {
		return nil, stats.ErrInspectionTooLate
	}
	feature := instance.GetFeature(stats.ManagerType())
	provider, ok := feature.(stats.ObservationProvider)
	if !ok {
		return nil, stats.ErrInspectionUnavailable
	}
	return provider.EnableInspection(options)
}
