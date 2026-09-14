package dispatcher

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

func rateSnapshotAt(d *DefaultDispatcher, at time.Time) ConnectionSnapshot {
	return d.connectionSnapshot(func() time.Time { return at })
}

func rateTotalAt(t *testing.T, d *DefaultDispatcher, tag string, at time.Time) UserOutboundTotal {
	t.Helper()
	for _, total := range rateSnapshotAt(d, at).OutboundTotals {
		if total.OutboundTag == tag {
			return total
		}
	}
	t.Fatalf("missing rate total for %q", tag)
	return UserOutboundTotal{}
}

func selectRateRequest(t *testing.T, d *DefaultDispatcher, tag string) (*connectionEntry, *transport.Link) {
	t.Helper()
	row, link := totalsRequest(t, d)
	d.connections.selected(row, tag, "", net.TCPDestination(net.LocalHostIP, 80))
	return row, link
}

func TestOutboundRatesFirstReadCacheElapsedAndDirections(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(4); err != nil {
		t.Fatal(err)
	}
	a, aLink := selectRateRequest(t, d, "A")
	b, _ := selectRateRequest(t, d, "B")
	start := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	first := rateTotalAt(t, d, "A", start)
	if first.UplinkRateValid || first.DownlinkRateValid || !first.RateWindowStart.IsZero() || !first.RateWindowEnd.IsZero() {
		t.Fatalf("first read exposed a rate: %+v", first)
	}
	a.uplink.Add(120)
	a.downlink.Add(60)
	b.uplink.Add(30)
	early := rateTotalAt(t, d, "A", start.Add(750*time.Millisecond))
	if early.UplinkReadBytes != 120 || early.DownlinkWrittenBytes != 60 || early.UplinkRateValid || !early.RateWindowEnd.IsZero() {
		t.Fatalf("early reader changed cache or missed totals: %+v", early)
	}
	windowEnd := start.Add(2500 * time.Millisecond)
	got := rateTotalAt(t, d, "A", windowEnd)
	if !got.UplinkRateValid || !got.DownlinkRateValid || got.UplinkBytesPerSecond != 48 || got.DownlinkBytesPerSecond != 24 || !got.RateWindowStart.Equal(start) || !got.RateWindowEnd.Equal(windowEnd) {
		t.Fatalf("actual elapsed rate: %+v", got)
	}
	other := rateTotalAt(t, d, "B", windowEnd)
	if !other.UplinkRateValid || !other.DownlinkRateValid || other.UplinkBytesPerSecond != 12 || other.DownlinkBytesPerSecond != 0 {
		t.Fatalf("directions/tags not independent: %+v", other)
	}
	a.uplink.Add(25)
	finish := buf.BeginRawCopy(aLink.Writer)
	cached := rateTotalAt(t, d, "A", start.Add(3*time.Second))
	if cached.UplinkReadBytes != 145 || cached.DownlinkCoverage != BytesDeferredRawCopy || !cached.UplinkRateValid || !cached.DownlinkRateValid || cached.UplinkBytesPerSecond != 48 || !cached.RateWindowEnd.Equal(windowEnd) {
		t.Fatalf("current totals altered historical cache: %+v", cached)
	}
	finish(10)
	idle := rateTotalAt(t, d, "B", start.Add(5*time.Second))
	if !idle.UplinkRateValid || !idle.DownlinkRateValid || idle.UplinkBytesPerSecond != 0 || idle.DownlinkBytesPerSecond != 0 {
		t.Fatalf("idle interval is not exact zero: %+v", idle)
	}
}

func TestOutboundRatesRawTransitionsAndRecovery(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(3); err != nil {
		t.Fatal(err)
	}
	_, link := selectRateRequest(t, d, "A")
	start := time.Date(2026, 9, 13, 13, 0, 0, 0, time.UTC)
	_ = rateTotalAt(t, d, "A", start)
	finish := buf.BeginRawCopy(link.Writer)
	finish(40)
	invalid := rateTotalAt(t, d, "A", start.Add(time.Second))
	if invalid.DownlinkRateValid || invalid.DownlinkWrittenBytes != 40 || invalid.DownlinkCoverage != BytesExact || !invalid.UplinkRateValid {
		t.Fatalf("completed inter-sample raw copy falsely exact: %+v", invalid)
	}
	recovered := rateTotalAt(t, d, "A", start.Add(2*time.Second))
	if !recovered.DownlinkRateValid || recovered.DownlinkBytesPerSecond != 0 {
		t.Fatalf("clean interval did not recover: %+v", recovered)
	}

	row, activeLink := totalsRequest(t, d)
	finish = buf.BeginRawCopy(activeLink.Writer)
	d.connections.selected(row, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	d.connections.end(row)
	active := rateTotalAt(t, d, "A", start.Add(3*time.Second))
	if active.DownlinkCoverage != BytesDeferredRawCopy || active.DownlinkRateValid {
		t.Fatalf("pre-binding active raw copy falsely exact: %+v", active)
	}
	finish(7)
	late := rateTotalAt(t, d, "A", start.Add(4*time.Second))
	if late.DownlinkWrittenBytes != 47 || late.DownlinkCoverage != BytesExact || late.DownlinkRateValid {
		t.Fatalf("late completion falsely attributed: %+v", late)
	}
	if got := rateTotalAt(t, d, "A", start.Add(5*time.Second)); !got.DownlinkRateValid || got.DownlinkBytesPerSecond != 0 {
		t.Fatalf("late completion did not recover: %+v", got)
	}
}

func TestOutboundRatesPreselectionTransferAndTornEndpoint(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(3); err != nil {
		t.Fatal(err)
	}
	_, _ = selectRateRequest(t, d, "A")
	start := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	_ = rateTotalAt(t, d, "A", start)
	row, _ := totalsRequest(t, d)
	row.uplink.Add(30)
	d.connections.selected(row, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	transferred := rateTotalAt(t, d, "A", start.Add(time.Second))
	if transferred.UplinkReadBytes != 30 || transferred.UplinkRateValid || !transferred.DownlinkRateValid {
		t.Fatalf("preselection bytes falsely attributed: %+v", transferred)
	}
	if got := rateTotalAt(t, d, "A", start.Add(2*time.Second)); !got.UplinkRateValid || got.UplinkBytesPerSecond != 0 {
		t.Fatalf("transfer interval did not recover: %+v", got)
	}

	total := d.connections.totals["A"]
	tornAt := start.Add(3 * time.Second)
	s := d.connectionSnapshot(func() time.Time {
		total.uplink.markDiscontinuity()
		return tornAt
	})
	if s.OutboundTotals[0].UplinkRateValid {
		t.Fatalf("torn endpoint falsely exact: %+v", s.OutboundTotals[0])
	}
	if got := rateTotalAt(t, d, "A", start.Add(4*time.Second)); got.UplinkRateValid {
		t.Fatalf("torn endpoint seeded false validity: %+v", got)
	}
	if got := rateTotalAt(t, d, "A", start.Add(5*time.Second)); !got.UplinkRateValid {
		t.Fatalf("clean endpoint pair did not recover: %+v", got)
	}
}

func TestOutboundRatesUnavailableOverflowAndSaturation(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(2); err != nil {
		t.Fatal(err)
	}
	row := d.connections.begin(context.Background(), net.TCPDestination(net.LocalHostIP, 80))
	row.uplink = &flowByteCounter{tracker: &d.connections}
	d.connections.selected(row, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	start := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	_ = rateTotalAt(t, d, "A", start)
	row.uplink.Add(math.MaxInt64)
	row.uplink.Add(1)
	invalid := rateTotalAt(t, d, "A", start.Add(time.Second))
	if invalid.UplinkCoverage != BytesOverflow || invalid.UplinkRateValid || invalid.DownlinkCoverage != BytesUnavailable || invalid.DownlinkRateValid {
		t.Fatalf("partial/overflow rate exposed: %+v", invalid)
	}

	other := new(DefaultDispatcher)
	if err := other.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	row, _ = selectRateRequest(t, other, "A")
	_ = rateTotalAt(t, other, "A", start)
	bucket := other.connections.totals["A"]
	bucket.uplink.continuity.Store(math.MaxUint64)
	bucket.uplink.markDiscontinuity()
	row.uplink.Add(10)
	got := rateTotalAt(t, other, "A", start.Add(time.Second))
	if bucket.uplink.continuity.Load() != math.MaxUint64 || got.UplinkRateValid {
		t.Fatalf("saturated marker wrapped or became valid: %+v", got)
	}
}

func TestOutboundRatesBoundsIsolationCloseAndConcurrency(t *testing.T) {
	d, other := new(DefaultDispatcher), new(DefaultDispatcher)
	for _, instance := range []*DefaultDispatcher{d, other} {
		if err := instance.EnableConnectionTracking(1); err != nil {
			t.Fatal(err)
		}
	}
	row, link := selectRateRequest(t, d, "A")
	otherRow, _ := selectRateRequest(t, other, "A")
	start := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	_ = rateTotalAt(t, d, "A", start)
	_ = rateTotalAt(t, other, "A", start)
	d.connections.end(row)
	reused, _ := totalsRequest(t, d)
	reused.uplink.Add(5)
	d.connections.selected(reused, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	omitted, _ := totalsRequest(t, d)
	d.connections.selected(omitted, "B", "", net.TCPDestination(net.LocalHostIP, 80))
	if s := rateSnapshotAt(d, start.Add(time.Second)); len(s.OutboundTotals) != 1 || s.OutboundTotals[0].OutboundTag != "A" || s.OutboundTotals[0].UplinkRateValid || s.TotalsDropped != 1 {
		t.Fatalf("retirement/tag reuse bounds: %+v", s)
	}
	otherRow.uplink.Add(9)
	if got := rateTotalAt(t, other, "A", start.Add(time.Second)); !got.UplinkRateValid || got.UplinkBytesPerSecond != 9 {
		t.Fatalf("cross-instance rate mutation: %+v", got)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			reused.uplink.Add(1)
			reused.downlink.Add(1)
		}
	})
	wg.Go(func() {
		for range 500 {
			finish := buf.BeginRawCopy(link.Writer)
			finish(1)
		}
	})
	wg.Go(func() {
		for range 1000 {
			_ = d.ConnectionSnapshot()
		}
	})
	wg.Go(func() { _ = d.Close() })
	wg.Wait()
	if s := d.ConnectionSnapshot(); !s.Closed || len(s.Connections) != 0 || len(s.OutboundTotals) != 0 {
		t.Fatalf("close republished rate state: %+v", s)
	}
	if got := rateTotalAt(t, other, "A", start.Add(2*time.Second)); !got.UplinkRateValid {
		t.Fatalf("other instance damaged by close: %+v", got)
	}
}
