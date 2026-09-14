package dispatcher

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type partialByteWriter struct {
	remaining int
	terminal  error
}

type partialStreamConn struct {
	directUserConn
	writer *partialByteWriter
}

func (c *partialStreamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (w *partialByteWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.remaining)
	w.remaining -= n
	if n < len(p) {
		return n, w.terminal
	}
	return n, nil
}

func TestConnectionBytesNativeWriterBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []string
		limit int
		want  int64
		fail  bool
	}{
		{"single", []string{"abcdef"}, 6, 6, false},
		{"single partial error", []string{"abcdef"}, 3, 3, true},
		{"vector", []string{"abc", "def"}, 6, 6, false},
		{"vector partial error", []string{"abc", "def"}, 4, 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terminal := errors.New("partial writer failure")
			conn := &partialStreamConn{writer: &partialByteWriter{remaining: tc.limit, terminal: terminal}}
			d := new(DefaultDispatcher)
			if err := d.EnableConnectionTracking(1); err != nil {
				t.Fatal(err)
			}
			d.ohm = observationManager{h: &observationHandler{run: func(_ context.Context, link *transport.Link) {
				var mb buf.MultiBuffer
				for _, part := range tc.parts {
					mb = append(mb, buf.FromBytes([]byte(part)))
				}
				err := link.Writer.WriteMultiBuffer(mb)
				if (err != nil) != tc.fail || (tc.fail && !errors.Is(err, terminal)) {
					t.Fatalf("write result: %v", err)
				}
				row := d.ConnectionSnapshot().Connections[0]
				if row.DownlinkCoverage != BytesExact || row.DownlinkWrittenBytes != tc.want {
					t.Fatalf("accepted bytes: row=%+v", row)
				}
			}}}
			if err := d.DispatchUserStream(context.Background(), net.TCPDestination(net.LocalHostIP, 80), routing.UserStream{
				Connection: conn,
			}); err != nil {
				t.Fatal(err)
			}
			total := outboundTotals(t, d, "")
			if total.DownlinkCoverage != BytesExact || total.DownlinkWrittenBytes != tc.want || len(d.ConnectionSnapshot().Connections) != 0 {
				t.Fatalf("retired partial/error total: %+v", total)
			}
		})
	}
}

type payloadWithEOF struct{ payload string }

func (r payloadWithEOF) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return buf.MultiBuffer{buf.FromBytes([]byte(r.payload))}, io.EOF
}

func TestConnectionBytesReaderCountsAndRawState(t *testing.T) {
	for _, timed := range []bool{false, true} {
		d := new(DefaultDispatcher)
		if err := d.EnableConnectionTracking(2); err != nil {
			t.Fatal(err)
		}
		dest := net.TCPDestination(net.LocalHostIP, 80)
		id := d.connections.begin(context.Background(), dest)
		oldRead, oldWrite := new(appstats.Counter), new(appstats.Counter)
		uplink, downlink := d.connections.prepareUserStream(id, oldRead)
		r := newUserStreamReader(payloadWithEOF{payload: "body"}, nil, io.NopCloser(strings.NewReader("")), uplink)
		w := buf.NewBufferToBytesWriter(io.Discard, oldWrite, downlink)
		var mb buf.MultiBuffer
		var err error
		if timed {
			mb, err = r.ReadMultiBufferTimeout(time.Second)
		} else {
			mb, err = r.ReadMultiBuffer()
		}
		buf.ReleaseMulti(mb)
		if err != io.EOF {
			t.Fatalf("read result: %v", err)
		}
		row := d.ConnectionSnapshot().Connections[0]
		if row.UplinkCoverage != BytesExact || row.UplinkReadBytes != 4 || oldRead.Value() != 4 {
			t.Fatalf("read accounting: %+v", row)
		}
		if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hi"))}); err != nil {
			t.Fatal(err)
		}
		// The outer legacy user stats wrapper must not hide the byte counter.
		finish := buf.BeginRawCopy(&SizeStatWriter{Writer: w, Counter: new(appstats.Counter)})
		if finish == nil {
			t.Fatal("raw-copy hook missing")
		}
		row = d.ConnectionSnapshot().Connections[0]
		if row.DownlinkCoverage != BytesDeferredRawCopy || row.DownlinkWrittenBytes != 2 {
			t.Fatalf("raw interval falsely exact: %+v", row)
		}
		// Simulate ReadFrom returning n>0 + error. The direct writer owns legacy
		// user accounting; native connection counters stay in the copy path.
		finish(7)
		row = d.ConnectionSnapshot().Connections[0]
		if row.DownlinkCoverage != BytesExact || row.DownlinkWrittenBytes != 9 || oldWrite.Value() != 9 {
			t.Fatalf("raw bytes doubled/lost: %+v legacy=%d", row, oldWrite.Value())
		}
		d.connections.end(id)
	}
}

func TestConnectionBytesPrefetchedPayloadCountedOnce(t *testing.T) {
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	dest := net.TCPDestination(net.LocalHostIP, 80)
	id := d.connections.begin(context.Background(), dest)
	legacy := new(appstats.Counter)
	uplink, _ := d.connections.prepareUserStream(id, legacy)
	r := newUserStreamReader(buf.NewReader(strings.NewReader("")), buf.MultiBuffer{buf.FromBytes([]byte("prefetched payload"))}, io.NopCloser(strings.NewReader("")), uplink)
	cache := &cachedReader{reader: r}
	b := buf.New()
	defer b.Release()
	if err := cache.Cache(b, time.Second); err != nil {
		t.Fatal(err)
	}
	mb, err := cache.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(mb)
	row := d.ConnectionSnapshot().Connections[0]
	if row.UplinkReadBytes != int64(len("prefetched payload")) || legacy.Value() != row.UplinkReadBytes {
		t.Fatalf("sniff cache double count: %+v", row)
	}
	if row.DownlinkCoverage != BytesExact || row.DownlinkWrittenBytes != 0 {
		t.Fatal("constructed writer boundary not exact")
	}
	if buf.BeginRawCopy(buf.Discard) != nil {
		t.Fatal("unsupported raw writer counted")
	}
	d.connections.end(id)
}

func TestConnectionBytesOverflowAndConcurrentClose(t *testing.T) {
	c := new(flowByteCounter)
	c.Counter.Set(math.MaxInt64)
	c.Add(1)
	if _, coverage := c.sample(); coverage != BytesOverflow {
		t.Fatal("overflow hidden")
	}
	c.Counter.Set(0)
	if _, coverage := c.sample(); coverage != BytesOverflow {
		t.Fatal("overflow forgotten")
	}
	d := new(DefaultDispatcher)
	if err := d.EnableConnectionTracking(1); err != nil {
		t.Fatal(err)
	}
	id := d.connections.begin(context.Background(), net.TCPDestination(net.LocalHostIP, 80))
	link := preparedObservationLink(d, id, buf.NewReader(strings.NewReader("")), io.Discard)
	up := id.uplink
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			up.Add(1)
		}
	})
	wg.Go(func() {
		for range 1000 {
			finish := buf.BeginRawCopy(link.Writer)
			finish(1)
		}
	})
	wg.Go(func() {
		for range 1000 {
			_ = d.ConnectionSnapshot()
		}
	})
	_ = d.Close()
	wg.Wait()
	if len(d.ConnectionSnapshot().Connections) != 0 {
		t.Fatal("late byte update republished row")
	}
}
