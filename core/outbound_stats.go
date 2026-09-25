package core

import (
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
)

// OutboundStatsDirection describes one outbound traffic counter observation.
type OutboundStatsDirection struct {
	// PolicyEnabled reports the current system policy flag for this direction.
	PolicyEnabled bool
	// CounterPresent distinguishes an observed zero from a missing counter.
	CounterPresent bool
	// Bytes is the raw signed stock counter value. It is meaningful only when
	// CounterPresent is true.
	Bytes int64
}

// OutboundStats describes the independently observed facts for an outbound tag.
type OutboundStats struct {
	OutboundManagerAvailable bool
	PolicyManagerAvailable   bool
	StatsManagerAvailable    bool
	HandlerPresent           bool
	Uplink                   OutboundStatsDirection
	Downlink                 OutboundStatsDirection
}

// ReadOutboundStats reads the current stock outbound statistics facts for tag.
// The uplink and downlink values are sequential observations, not one coherent
// snapshot. An empty tag reports policy only and is never resolved as a handler
// or counter name. The instance must be non-nil.
//
// xray:api:beta
func ReadOutboundStats(instance *Instance, tag string) OutboundStats {
	var result OutboundStats

	if policyManager, ok := instance.GetFeature(policy.ManagerType()).(policy.Manager); ok {
		result.PolicyManagerAvailable = true
		systemStats := policyManager.ForSystem().Stats
		result.Uplink.PolicyEnabled = systemStats.OutboundUplink
		result.Downlink.PolicyEnabled = systemStats.OutboundDownlink
	}
	if outboundManager, ok := instance.GetFeature(outbound.ManagerType()).(outbound.Manager); ok {
		result.OutboundManagerAvailable = true
		if tag != "" {
			result.HandlerPresent = outboundManager.GetHandler(tag) != nil
		}
	}
	if statsManager, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager); ok {
		switch statsManager.(type) {
		case stats.NoopManager, *stats.NoopManager:
		default:
			result.StatsManagerAvailable = true
		}
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
