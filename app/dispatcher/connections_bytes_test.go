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
	"github.com/xtls/xray-core/transport"
)

type partialByteWriter struct {
	remaining int
	terminal  error
}

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
			legacy := new(appstats.Counter)
			w := &buf.BufferToBytesWriter{Writer: &partialByteWriter{remaining: tc.limit, terminal: terminal}, Counter: legacy}
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
				if row.DownlinkCoverage != BytesExact || row.DownlinkWrittenBytes != tc.want || legacy.Value() != tc.want {
					t.Fatalf("accepted bytes: row=%+v legacy=%d", row, legacy.Value())
				}
			}}}
			link := &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: w}
			if err := d.DispatchUserLink(context.Background(), net.TCPDestination(net.LocalHostIP, 80), link); err != nil {
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
		r := &buf.TimeoutWrapperReader{Reader: payloadWithEOF{payload: "body"}, Counter: oldRead}
		w := &buf.BufferToBytesWriter{Writer: io.Discard, Counter: oldWrite}
		link := &transport.Link{Reader: r, Writer: w}
		d.connections.observeLink(id, link)
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
		finish := BeginConnectionRawCopy(&SizeStatWriter{Writer: w, Counter: new(appstats.Counter)})
		if finish == nil {
			t.Fatal("raw-copy hook missing")
		}
		row = d.ConnectionSnapshot().Connections[0]
		if row.DownlinkCoverage != BytesDeferredRawCopy || row.DownlinkWrittenBytes != 2 {
			t.Fatalf("raw interval falsely exact: %+v", row)
		}
		// Simulate stock native accounting and a ReadFrom returning n>0 + error.
		oldWrite.Add(7)
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
	r := &buf.TimeoutWrapperReader{Reader: &buf.BufferedReader{Reader: buf.NewReader(strings.NewReader("")), Buffer: buf.MultiBuffer{buf.FromBytes([]byte("prefetched payload"))}}, Counter: legacy}
	link := &transport.Link{Reader: r, Writer: buf.Discard}
	d.connections.observeLink(id, link)
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
	if row.DownlinkCoverage != BytesUnavailable {
		t.Fatal("unsupported writer falsely exact")
	}
	if BeginConnectionRawCopy(buf.Discard) != nil {
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
	link := &transport.Link{Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(strings.NewReader(""))}, Writer: &buf.BufferToBytesWriter{Writer: io.Discard}}
	d.connections.observeLink(id, link)
	up := link.Reader.(*buf.TimeoutWrapperReader).Counter
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			up.Add(1)
		}
	})
	wg.Go(func() {
		for range 1000 {
			finish := BeginConnectionRawCopy(link.Writer)
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
