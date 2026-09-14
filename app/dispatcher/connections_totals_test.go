package dispatcher

import (
	"context"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func totalsRequest(t *testing.T, d *DefaultDispatcher) (*connectionEntry, *transport.Link) {
	t.Helper()
	row := d.connections.begin(context.Background(), net.TCPDestination(net.LocalHostIP, 80))
	if row == nil {
		t.Fatal("admission unexpectedly disabled")
	}
	link := &transport.Link{
		Reader: buf.NewReader(strings.NewReader("prefetch")),
		Writer: buf.Discard,
	}
	link = preparedObservationLink(d, row, link.Reader, io.Discard)
	return row, link
}

func outboundTotals(t *testing.T, d *DefaultDispatcher, tag string) UserOutboundTotal {
	t.Helper()
	for _, total := range d.ConnectionSnapshot().OutboundTotals {
		if total.OutboundTag == tag {
			return total
		}
	}
	t.Fatalf("missing totals for %q: %+v", tag, d.ConnectionSnapshot())
	return UserOutboundTotal{}
}

func TestOutboundTotalsRetirementAndLiveCapacity(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	a, link := totalsRequest(t, d)
	mb, err := link.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != nil {
		t.Fatal(err)
	}
	// Sniffed/prefetched bytes arrive before outbound selection.
	d.connections.selected(a, "A", "rule", net.TCPDestination(net.LocalHostIP, 80))
	b, _ := totalsRequest(t, d)
	if b.ID != 0 {
		t.Fatal("live limit not enforced")
	}
	d.connections.selected(b, "A", "rule", net.TCPDestination(net.LocalHostIP, 80))
	b.uplink.Add(5)
	a.downlink.Add(3)
	before := outboundTotals(t, d, "A")
	if before.UplinkReadBytes != 13 || before.DownlinkWrittenBytes != 3 || before.UplinkCoverage != BytesExact || before.DownlinkCoverage != BytesExact {
		t.Fatalf("live totals: %+v", before)
	}
	finish := buf.BeginRawCopy(link.Writer)
	d.connections.end(a)
	d.connections.end(b)
	if s := d.ConnectionSnapshot(); len(s.Connections) != 0 || s.Dropped != 1 || s.TotalsDropped != 0 {
		t.Fatalf("row/total capacity mixed: %+v", s)
	}
	if got := outboundTotals(t, d, "A"); got.DownlinkCoverage != BytesDeferredRawCopy || got.DownlinkWrittenBytes != 3 {
		t.Fatalf("retirement lost deferred state: %+v", got)
	}
	// A handler return does not prove all native I/O has finished.
	finish(7)
	b.uplink.Add(2)
	got := outboundTotals(t, d, "A")
	if got.UplinkReadBytes != 15 || got.DownlinkWrittenBytes != 10 || got.DownlinkCoverage != BytesExact {
		t.Fatalf("late completion lost or doubled: %+v", got)
	}
	if before.UplinkReadBytes != 13 || before.DownlinkWrittenBytes != 3 {
		t.Fatal("snapshot aliases mutable totals")
	}
	// A reused tag accumulates into its old bucket after every live row is gone.
	c, _ := totalsRequest(t, d)
	d.connections.selected(c, "A", "new-rule", net.TCPDestination(net.LocalHostIP, 81))
	c.uplink.Add(4)
	d.connections.end(c)
	if got := outboundTotals(t, d, "A"); got.UplinkReadBytes != 19 {
		t.Fatalf("tag reuse reset totals: %+v", got)
	}
}

func TestOutboundTotalsSelectionCapacityAndCoverage(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(2); err != nil {
		t.Fatal(err)
	}
	dest := net.TCPDestination(net.LocalHostIP, 80)
	for _, tag := range []string{"B", "", "C", "B"} {
		row, link := totalsRequest(t, d)
		d.connections.selected(row, tag, "", dest)
		row.uplink.Add(1)
		if tag == "C" {
			var wg sync.WaitGroup
			wg.Go(func() {
				for range 100 {
					row.uplink.Add(1)
				}
			})
			wg.Go(func() {
				for range 100 {
					finish := buf.BeginRawCopy(link.Writer)
					finish(1)
				}
			})
			wg.Wait()
			if !row.uplink.totalBindingResolved.Load() || !row.downlink.totalBindingResolved.Load() {
				t.Fatal("omitted tag left pending counter binding")
			}
		}
		// Repeated selection cannot move or double-count an already bound flow.
		d.connections.selected(row, "different", "", dest)
		d.connections.end(row)
	}
	s := d.ConnectionSnapshot()
	if len(s.OutboundTotals) != 2 || s.OutboundTotals[0].OutboundTag != "" || s.OutboundTotals[1].OutboundTag != "B" || s.OutboundTotals[1].UplinkReadBytes != 2 || s.TotalsDropped != 1 {
		t.Fatalf("bounded tag retention: %+v", s)
	}
	d.connections.totalsDropped = math.MaxUint64
	row, _ := totalsRequest(t, d)
	d.connections.selected(row, "D", "", dest)
	d.connections.end(row)
	if d.ConnectionSnapshot().TotalsDropped != math.MaxUint64 {
		t.Fatal("totals drop wrapped")
	}
	// Unsupported writers leave sticky partial coverage even after retirement.
	row = d.connections.begin(context.Background(), dest)
	row.uplink = &flowByteCounter{tracker: &d.connections}
	d.connections.selected(row, "B", "", dest)
	d.connections.end(row)
	if got := outboundTotals(t, d, "B"); got.DownlinkCoverage != BytesUnavailable {
		t.Fatalf("missing direction falsely exact: %+v", got)
	}
}

func TestOutboundTotalsOrdinaryAndUnselectedExcluded(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(2); err != nil {
		t.Fatal(err)
	}
	dest := net.TCPDestination(net.LocalHostIP, 80)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "same-user-metadata"})
	h := &observationHandler{tag: "A"}
	d.ohm = observationManager{h: h}
	depth := 0
	h.run = func(ctx context.Context, link *transport.Link) {
		if depth == 0 {
			depth++
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
			if err := d.DispatchLink(ctx, dest, &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: &buf.BufferToBytesWriter{Writer: io.Discard}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("body"))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.DispatchUserStream(ctx, dest, observationStream()); err != nil {
		t.Fatal(err)
	}
	if got := outboundTotals(t, d, "A"); got.DownlinkWrittenBytes != 4 {
		t.Fatalf("helper included in USER totals: %+v", got)
	}
	d.ohm = observationManager{}
	if err := d.DispatchUserStream(context.Background(), dest, observationStream()); err != nil {
		t.Fatal(err)
	}
	if len(d.ConnectionSnapshot().OutboundTotals) != 1 {
		t.Fatal("missing selection became empty-tag bucket")
	}
}

func TestOutboundTotalsOverflowAndMultipleDeferred(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(2); err != nil {
		t.Fatal(err)
	}
	a, aLink := totalsRequest(t, d)
	b, bLink := totalsRequest(t, d)
	a.uplink.Add(math.MaxInt64)
	first := buf.BeginRawCopy(aLink.Writer) // Begin before selection.
	for _, row := range []*connectionEntry{a, b} {
		d.connections.selected(row, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	}
	b.uplink.Add(1) // Individual counters valid, sum overflows.
	second := buf.BeginRawCopy(bLink.Writer)
	first(3)
	got := outboundTotals(t, d, "A")
	if got.UplinkCoverage != BytesOverflow || got.UplinkReadBytes != math.MaxInt64 || got.DownlinkCoverage != BytesDeferredRawCopy {
		t.Fatalf("aggregate overflow/deferred hidden: %+v", got)
	}
	second(4)
	got = outboundTotals(t, d, "A")
	if got.DownlinkCoverage != BytesExact || got.DownlinkWrittenBytes != 7 {
		t.Fatalf("deferred count incorrect: %+v", got)
	}
}

func TestOutboundTotalsConcurrentBindingRetirementAndClose(t *testing.T) {
	d, other := new(DefaultDispatcher), new(DefaultDispatcher)
	for _, instance := range []*DefaultDispatcher{d, other} {
		if err := instance.EnableConnectionTracking(2); err != nil {
			t.Fatal(err)
		}
	}
	row, link := totalsRequest(t, d)
	second, _ := totalsRequest(t, d)
	d.connections.selected(second, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			second.uplink.Add(1)
			second.downlink.Add(1)
		}
		d.connections.end(second)
	})
	wg.Go(func() {
		for range 1000 {
			row.uplink.Add(1)
			finish := buf.BeginRawCopy(link.Writer)
			finish(1)
		}
	})
	wg.Go(func() {
		for range 1000 {
			_ = d.ConnectionSnapshot()
		}
	})
	d.connections.selected(row, "A", "", net.TCPDestination(net.LocalHostIP, 80))
	d.connections.end(row)
	wg.Wait()
	got := outboundTotals(t, d, "A")
	if got.UplinkReadBytes != 1500 || got.DownlinkWrittenBytes != 1500 || got.UplinkCoverage != BytesExact || got.DownlinkCoverage != BytesExact {
		t.Fatalf("concurrent binding lost bytes: %+v", got)
	}
	if len(other.ConnectionSnapshot().OutboundTotals) != 0 {
		t.Fatal("cross-instance totals")
	}
	wg.Go(func() {
		for range 1000 {
			row.uplink.Add(1)
			finish := buf.BeginRawCopy(link.Writer)
			finish(1)
			_ = d.ConnectionSnapshot()
		}
	})
	_ = d.Close()
	wg.Wait()
	if s := d.ConnectionSnapshot(); !s.Closed || len(s.Connections) != 0 || len(s.OutboundTotals) != 0 {
		t.Fatalf("late aggregate publication: %+v", s)
	}
}
