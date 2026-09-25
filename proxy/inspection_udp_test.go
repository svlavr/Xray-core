package proxy_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

type inspectionUDPPacketReader struct {
	destinations []cnet.Destination
	read         bool
}

func (r *inspectionUDPPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.read {
		return nil, io.EOF
	}
	r.read = true
	first := buf.FromBytes([]byte("first"))
	first.UDP = &r.destinations[0]
	second := buf.FromBytes([]byte("second"))
	second.UDP = &r.destinations[1]
	return buf.MultiBuffer{first, second}, io.EOF
}

var errInspectionUDPWrite = errors.New("injected UDP write failure")

type inspectionUDPPrefixWriter struct{ calls int }

func (w *inspectionUDPPrefixWriter) Write(payload []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return len(payload), nil
	}
	return min(2, len(payload)), errInspectionUDPWrite
}

func TestObserveUDPPacketReceiptsOriginsAndTerminalGate(t *testing.T) {
	for _, test := range []struct {
		name   string
		origin session.TrafficOrigin
	}{
		{name: "unknown", origin: session.TrafficOriginUnknown},
		{name: "internal", origin: session.TrafficOriginInternal},
		{name: "measurement", origin: session.TrafficOriginControlledMeasurement},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close() })
			conn, peer := net.Pipe()
			t.Cleanup(func() { conn.Close(); peer.Close() })
			destinations := []cnet.Destination{
				cnet.UDPDestination(cnet.DomainAddress("one.example"), 53),
				cnet.UDPDestination(cnet.DomainAddress("two.example"), 443),
			}
			lower := &inspectionUDPPacketReader{destinations: destinations}
			writer := &inspectionUDPPrefixWriter{}
			link := &transport.Link{
				Reader: &buf.BufferedReader{Reader: lower},
				Writer: &buf.SequentialWriter{Writer: writer},
			}
			ctx := context.Background()
			if test.origin != session.TrafficOriginUnknown {
				ctx = session.ContextWithTrafficOrigin(ctx, test.origin)
			}
			ctx, finish := proxy.ObserveUDP(ctx, manager, conn, cnet.UDPDestination(cnet.LocalHostIP, 5353), link)
			if finish == nil {
				t.Fatal("enabled UDP observation returned no cleanup")
			}
			cursor, ok := link.Reader.(*buf.InspectionReader)
			if !ok {
				t.Fatalf("UDP reader type = %T", link.Reader)
			}
			cache := buf.New()
			if err := cursor.Cache(cache, time.Second); err != nil || cache.String() != "firstsecond" {
				cache.Release()
				t.Fatalf("sniff cache %q: %v", cache.String(), err)
			}
			cache.Release()
			mb, err := link.Reader.ReadMultiBuffer()
			if !errors.Is(err, io.EOF) || mb.String() != "firstsecond" {
				buf.ReleaseMulti(mb)
				t.Fatalf("sniff replay %q: %v", mb.String(), err)
			}
			buf.ReleaseMulti(mb)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("packet-one")), buf.FromBytes([]byte("packet-two"))}); !errors.Is(err, errInspectionUDPWrite) {
				t.Fatalf("sequential packet result: %v", err)
			}

			observation := session.LogicalObservationFromContext(ctx)
			if observation == nil || buf.WriterReceipt(link.Writer) != observation.Exchange {
				t.Fatal("UDP endpoint receipts were not bound")
			}
			flow := observation.Exchange
			finish()
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 0 {
				t.Fatalf("owner-end UDP snapshot: %+v %v", page, err)
			}
			flow.AddDownlink(1)
			page, err = view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("UDP terminal: %+v %v", page, err)
			}
			row := page.Rows[0]
			if row.Flow.Origin != fs.TrafficOrigin(test.origin) || row.Flow.Uplink.Known != uint64(len("firstsecond")) || row.Flow.Downlink.Known != 0 || !row.Flow.Downlink.Incomplete || row.Reason != fs.EndReasonWriteError || len(row.Flow.Destinations) != 2 || row.Flow.Destinations[0] != destinations[0] || row.Flow.Destinations[1] != destinations[1] {
				t.Fatalf("UDP terminal receipts: %+v", row)
			}
			totals, _ := view.ReadTotals(context.Background())
			var down uint64
			for _, total := range totals.Rows {
				down += total.Downlink.Known
			}
			if down != 1 {
				t.Fatalf("late UDP total: %+v", totals)
			}
		})
	}
}

func TestObserveUDPDisabledPreservesEndpoint(t *testing.T) {
	for _, manager := range []fs.Manager{nil, fs.NoopManager{}, new(appstats.Manager)} {
		ctx := context.Background()
		link := &transport.Link{Reader: &inspectionUDPPacketReader{}, Writer: buf.Discard}
		original := *link
		observed, finish := proxy.ObserveUDP(ctx, manager, nil, cnet.UDPDestination(cnet.LocalHostIP, 53), link)
		if observed != ctx || finish != nil || *link != original {
			t.Fatal("disabled UDP collection changed the endpoint")
		}
	}
}
