package kcp

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
)

// Real workers without periodic scheduling let Input run after the flush sample.
func idleOrderConnection(t *testing.T) *Connection {
	config := &Config{Mtu: 1350, Tti: 50, UplinkCapacity: 5, DownlinkCapacity: 20, CwndMultiplier: 20, MaxSendingWindow: 2 * 1024 * 1024}
	c := &Connection{meta: ConnMetadata{Conversation: 1729}, closer: io.NopCloser(strings.NewReader("")), since: nowMillisec(), dataInput: signal.NewNotifier(), dataOutput: signal.NewNotifier(), Config: config, output: NewRetryableWriter(NewSegmentWriter(buf.DiscardBytes)), mss: config.Mtu - DataSegmentOverhead, roundTrip: &RoundTripInfo{rto: 100, minRtt: config.Tti}}
	c.receivingWorker = NewReceivingWorker(c)
	c.sendingWorker = NewSendingWorker(c)
	c.dataUpdater = NewUpdater(50, func() bool { return false }, func() bool { return true }, func() {})
	c.pingUpdater = NewUpdater(5000, func() bool { return false }, func() bool { return true }, func() {})
	t.Cleanup(func() { c.receivingWorker.Release(); c.sendingWorker.Release() })
	return c
}

func TestKCPFreshInputAfterFlushSample(t *testing.T) {
	c := idleOrderConnection(t)
	sampled := c.Elapsed()
	c.since -= 100
	ping := NewCmdOnlySegment()
	ping.Conv = c.meta.Conversation
	ping.Cmd = CommandPing
	c.Input([]Segment{ping})
	if atomic.LoadUint32(&c.lastIncomingTime) <= sampled {
		t.Fatal("input did not advance clock")
	}
	c.flushAt(sampled)
	if c.State() != StateActive {
		t.Fatalf("fresh input closed connection: %v", c.State())
	}
}

func TestKCPIdleClockWrapAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name      string
		now, last uint32
		active    bool
	}{
		{"newer input", 100, 101, true},
		{"recent", 30000, 29999, true},
		{"wrap", 100, ^uint32(0) - 100, true},
		{"idle", 30001, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := idleOrderConnection(t)
			c.since -= int64(tc.now)
			c.lastIncomingTime = tc.last
			c.lastPingTime = tc.now
			c.flushAt(tc.now)
			if (c.State() == StateActive) != tc.active {
				t.Fatalf("state=%v", c.State())
			}
		})
	}
}
