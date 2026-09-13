package dispatcher

import (
	"math"
	"sync/atomic"
	"time"
)

// UserOutboundTotal accumulates observed USER TCP bytes for one selected tag
// since tracking was enabled, independently of live-row retention. Tag reuse
// shares a bucket; handler removal does not erase it. Dispatcher Close clears
// totals. Coverage describes the observed boundary, not all instance traffic.
type UserOutboundTotal struct {
	OutboundTag          string
	UplinkReadBytes      int64
	DownlinkWrittenBytes int64
	UplinkCoverage       ByteCoverage
	DownlinkCoverage     ByteCoverage
	// Rate fields describe the cached historical window, while byte totals and
	// coverage above describe this snapshot. Invalid zero is not zero traffic.
	// Snapshot reads establish the first baseline (zero window, invalid rates)
	// and refresh after at least one second. Rates divide compatible byte deltas
	// by the actual elapsed time; there is no background sampler. Multiple
	// readers share the same window, and infrequent reads produce longer windows.
	// Raw-copy transitions and pre-selection transfers invalidate an interval;
	// later compatible samples can recover. Directions are sampled independently.
	RateWindowStart        time.Time
	RateWindowEnd          time.Time
	UplinkBytesPerSecond   float64
	DownlinkBytesPerSecond float64
	UplinkRateValid        bool
	DownlinkRateValid      bool
}

// Binding uses the tracker mutex; bound I/O updates use only atomics.
// Buckets retain no request, counter, link, handler or context references.
type outboundTotal struct {
	uplink, downlink outboundByteTotal
	rate             outboundRateState
}

type outboundByteTotal struct {
	bytes       atomic.Int64
	deferred    atomic.Int64
	unavailable atomic.Bool
	overflow    atomic.Bool
	continuity  atomic.Uint64
}

func (b *outboundByteTotal) markDiscontinuity() {
	for {
		old := b.continuity.Load()
		if old == math.MaxUint64 || b.continuity.CompareAndSwap(old, old+1) {
			return
		}
	}
}

func (b *outboundByteTotal) add(n int64) {
	for {
		old := b.bytes.Load()
		next := int64(math.MaxInt64)
		if n < 0 || n > math.MaxInt64-old {
			b.overflow.Store(true)
		} else {
			next = old + n
		}
		if b.bytes.CompareAndSwap(old, next) {
			return
		}
	}
}

func (b *outboundByteTotal) sample() (int64, ByteCoverage) {
	// Read deferred before bytes: a concurrently finishing raw copy must not
	// turn a sampled pre-completion value into an exact completed count.
	deferred := b.deferred.Load()
	value := b.bytes.Load()
	if b.overflow.Load() {
		return value, BytesOverflow
	}
	if b.unavailable.Load() {
		return value, BytesUnavailable
	}
	if deferred != 0 {
		return value, BytesDeferredRawCopy
	}
	return value, BytesExact
}

func (b *outboundByteTotal) bind(c *flowByteCounter) {
	if c == nil {
		b.unavailable.Store(true)
		return
	}
	value, coverage := c.sample()
	deferred := c.deferred.Load()
	if value != 0 || deferred {
		// Binding holds the tracker lock. Invalidate an existing sampling
		// interval before publishing pre-selection bytes or deferred state.
		b.markDiscontinuity()
	}
	b.add(value)
	if coverage == BytesOverflow {
		b.overflow.Store(true)
	}
	if deferred {
		b.deferred.Add(1)
	}
	// Publish only after the pre-selection value/state has transferred. An
	// unbound update takes tracker, rechecks this pointer, then adds once.
	c.total.Store(b)
	c.totalBindingResolved.Store(true)
}

func (t *connectionTracker) bindTotals(row *connectionEntry, tag string) {
	total := t.totals[tag]
	if total == nil {
		if len(t.totals) >= t.limit {
			if t.totalsDropped != math.MaxUint64 {
				t.totalsDropped++
			}
			for _, c := range []*flowByteCounter{row.uplink, row.downlink} {
				if c != nil {
					c.totalBindingResolved.Store(true)
				}
			}
			return
		}
		total = new(outboundTotal)
		t.totals[tag] = total
	}
	total.uplink.bind(row.uplink)
	total.downlink.bind(row.downlink)
}

func (c *flowByteCounter) setDeferred(deferred bool) {
	if c.tracker != nil && !c.totalBindingResolved.Load() {
		c.tracker.Lock()
		defer c.tracker.Unlock()
		if c.tracker.closed {
			c.totalBindingResolved.Store(true)
		}
	}
	previous := c.deferred.Swap(deferred)
	total := c.total.Load()
	if previous == deferred || total == nil {
		return
	}
	total.markDiscontinuity()
	if deferred {
		total.deferred.Add(1)
	} else {
		total.deferred.Add(-1)
	}
}
