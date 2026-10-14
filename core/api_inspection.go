package core

import (
	go_errors "errors"
	"fmt"

	"github.com/xtls/xray-core/features/stats"
)

// EnableFlowInspection enables the optional native endpoint observation capability.
// Enablement is intentionally limited to the interval before Instance.Start.
func EnableFlowInspection(instance *Instance, options stats.ObservationOptions) (stats.FlowInspection, error) {
	instance.statusLock.Lock()
	defer instance.statusLock.Unlock()
	if instance.running {
		return nil, fmt.Errorf("inspection enablement is too late")
	}
	feature := instance.GetFeature(stats.ManagerType())
	provider, ok := feature.(stats.ObservationProvider)
	if !ok {
		return nil, go_errors.ErrUnsupported
	}
	return provider.EnableInspection(options)
}
