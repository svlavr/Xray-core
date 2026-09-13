package dispatcher

import (
	"math"
	"time"
)

const outboundRateSampleInterval = time.Second

type outboundRateEndpoint struct {
	bytes      int64
	continuity uint64
	valid      bool
}

type outboundRateState struct {
	hasBaseline bool
	baselineAt  time.Time
	uplink      outboundRateEndpoint
	downlink    outboundRateEndpoint

	windowStart       time.Time
	windowEnd         time.Time
	uplinkPerSecond   float64
	downlinkPerSecond float64
	uplinkRateValid   bool
	downlinkRateValid bool
}

func rateEndpoint(bytes int64, coverage ByteCoverage, before, after uint64) outboundRateEndpoint {
	return outboundRateEndpoint{
		bytes:      bytes,
		continuity: after,
		valid:      coverage == BytesExact && before == after && after != math.MaxUint64,
	}
}

func sampledRate(previous, current outboundRateEndpoint, elapsed time.Duration) (float64, bool) {
	if !previous.valid || !current.valid || previous.continuity != current.continuity || current.bytes < previous.bytes || elapsed <= 0 {
		return 0, false
	}
	return float64(current.bytes-previous.bytes) / elapsed.Seconds(), true
}

// snapshot samples both directions around one timestamp. Rate state is used
// only while the tracker mutex is held; cumulative totals remain atomic.
func (t *outboundTotal) snapshot(tag string, sampleTime func() time.Time) UserOutboundTotal {
	uplinkBefore := t.uplink.continuity.Load()
	downlinkBefore := t.downlink.continuity.Load()
	uplinkBytes, uplinkCoverage := t.uplink.sample()
	downlinkBytes, downlinkCoverage := t.downlink.sample()
	at := sampleTime()
	uplinkAfter := t.uplink.continuity.Load()
	downlinkAfter := t.downlink.continuity.Load()

	uplink := rateEndpoint(uplinkBytes, uplinkCoverage, uplinkBefore, uplinkAfter)
	downlink := rateEndpoint(downlinkBytes, downlinkCoverage, downlinkBefore, downlinkAfter)
	state := &t.rate
	if !state.hasBaseline {
		state.hasBaseline = true
		state.baselineAt = at
		state.uplink = uplink
		state.downlink = downlink
	} else if elapsed := at.Sub(state.baselineAt); elapsed >= outboundRateSampleInterval {
		state.windowStart = state.baselineAt
		state.windowEnd = at
		state.uplinkPerSecond, state.uplinkRateValid = sampledRate(state.uplink, uplink, elapsed)
		state.downlinkPerSecond, state.downlinkRateValid = sampledRate(state.downlink, downlink, elapsed)
		// Even an invalid interval advances the baseline. A torn endpoint stays
		// invalid, preventing it from seeding false validity on the next read.
		state.baselineAt = at
		state.uplink = uplink
		state.downlink = downlink
	}

	return UserOutboundTotal{
		OutboundTag:            tag,
		UplinkReadBytes:        uplinkBytes,
		DownlinkWrittenBytes:   downlinkBytes,
		UplinkCoverage:         uplinkCoverage,
		DownlinkCoverage:       downlinkCoverage,
		RateWindowStart:        state.windowStart,
		RateWindowEnd:          state.windowEnd,
		UplinkBytesPerSecond:   state.uplinkPerSecond,
		DownlinkBytesPerSecond: state.downlinkPerSecond,
		UplinkRateValid:        state.uplinkRateValid,
		DownlinkRateValid:      state.downlinkRateValid,
	}
}
