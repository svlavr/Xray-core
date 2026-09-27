package core

import (
	"github.com/xtls/xray-core/features/stats"
)

// OutboundStatsDirection describes one outbound traffic counter observation.
type OutboundStatsDirection struct {
	// CounterPresent distinguishes an observed zero from a missing counter.
	CounterPresent bool
	// Bytes is the raw signed stock counter value. It is meaningful only when
	// CounterPresent is true.
	Bytes int64
}

// OutboundStats describes the independently observed facts for an outbound tag.
type OutboundStats struct {
	Uplink   OutboundStatsDirection
	Downlink OutboundStatsDirection
}

// ReadOutboundStats reads the current stock outbound statistics facts for tag.
// The uplink and downlink values are sequential observations, not one coherent
// snapshot. An empty tag never resolves a counter name. A missing counter
// remains distinct from an observed zero. The instance must be non-nil.
//
// xray:api:beta
func ReadOutboundStats(instance *Instance, tag string) OutboundStats {
	var result OutboundStats

	if statsManager, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager); ok {
		if tag != "" {
			if counter := statsManager.GetCounter("outbound>>>" + tag + ">>>traffic>>>uplink"); counter != nil {
				result.Uplink.CounterPresent = true
				result.Uplink.Bytes = counter.Value()
			}
			if counter := statsManager.GetCounter("outbound>>>" + tag + ">>>traffic>>>downlink"); counter != nil {
				result.Downlink.CounterPresent = true
				result.Downlink.Bytes = counter.Value()
			}
		}
	}

	return result
}
