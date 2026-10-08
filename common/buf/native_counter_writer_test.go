package buf_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// NewWriter only queries syscall.Conn capability. This sink preserves its
// native TCP unwrapping path and supplies deterministic actual write results.
type nativeCounterSink struct {
	net.Conn
	limits  []int
	err     error
	written int
}

func (*nativeCounterSink) SyscallConn() (syscall.RawConn, error) { return nil, nil }

func (s *nativeCounterSink) Write(p []byte) (int, error) {
	n := len(p)
	if len(s.limits) != 0 {
		n = min(n, s.limits[0])
		s.limits = s.limits[1:]
	}
	s.written += n
	return n, s.err
}

func nativeCounterWriter(t *testing.T, sink *nativeCounterSink, inspected bool) (buf.Writer, *appstats.Counter, fs.FlowInspection) {
	t.Helper()
	counter := &appstats.Counter{}
	writer := buf.NewWriter(&stat.CounterConnection{Connection: sink, WriteCounter: counter})
	if _, ok := writer.(*buf.BufferToBytesWriter); !ok {
		t.Fatal("fixture did not reach unwrapped native TCP writer")
	}
	if !inspected {
		return writer, counter, nil
	}
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	flow := manager.Observation().PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	flow.Route(fs.OutboundRef{Tag: "native-write"})
	return buf.AttachWriterReceipt(writer, flow), counter, view
}

func checkNativeCounterWrite(t *testing.T, sink *nativeCounterSink, counter *appstats.Counter, view fs.FlowInspection, want int) {
	t.Helper()
	if sink.written != want || counter.Value() != int64(want) {
		t.Fatalf("native accepted bytes: lower=%d counter=%d want=%d", sink.written, counter.Value(), want)
	}
	if view != nil {
		totals, err := view.ReadTotals()
		if err != nil || totals.User.Downlink != uint64(want) || len(totals.Rows) != 1 || totals.Rows[0].Downlink != uint64(want) {
			t.Fatalf("native/decoded accounting diverged: %+v %v want=%d", totals, err, want)
		}
	}
}

func TestNativeCounterWriterScalarResult(t *testing.T) {
	failure := errors.New("native partial failure")
	for _, inspected := range []bool{false, true} {
		for _, tc := range []struct {
			name string
			n    int
			err  error
		}{
			{"full", 6, nil}, {"partial-error", 2, failure}, {"zero-error", 0, failure}, {"empty", 0, nil},
		} {
			t.Run(tc.name+map[bool]string{false: "/native", true: "/inspected"}[inspected], func(t *testing.T) {
				sink := &nativeCounterSink{limits: []int{tc.n}, err: tc.err}
				writer, counter, view := nativeCounterWriter(t, sink, inspected)
				payload := []byte("abcdef")
				if tc.name == "empty" {
					payload = nil
				}
				n, err := writer.(io.Writer).Write(payload)
				if n != tc.n || err != tc.err {
					t.Fatalf("native result changed: %d %v", n, err)
				}
				checkNativeCounterWrite(t, sink, counter, view, tc.n)
			})
		}
	}
}

func TestNativeCounterWriterBatchOnce(t *testing.T) {
	failure := errors.New("native batch partial failure")
	for _, inspected := range []bool{false, true} {
		for _, tc := range []struct {
			name     string
			payloads []string
			limits   []int
			err      error
			want     int
		}{
			{"single", []string{"abcdef"}, nil, nil, 6},
			{"single-short-progress", []string{"abcdef"}, []int{2, 4}, nil, 6},
			{"single-partial-error", []string{"abcdef"}, []int{2}, failure, 2},
			{"vector", []string{"abc", "def"}, nil, nil, 6},
			{"vector-partial-error", []string{"abc", "def"}, []int{2}, failure, 2},
		} {
			t.Run(tc.name+map[bool]string{false: "/native", true: "/inspected"}[inspected], func(t *testing.T) {
				sink := &nativeCounterSink{limits: append([]int(nil), tc.limits...), err: tc.err}
				writer, counter, view := nativeCounterWriter(t, sink, inspected)
				var mb buf.MultiBuffer
				for _, payload := range tc.payloads {
					mb = append(mb, buf.FromBytes([]byte(payload)))
				}
				if err := writer.WriteMultiBuffer(mb); err != tc.err {
					t.Fatalf("native batch error changed: %v", err)
				}
				for _, b := range mb {
					if !b.IsEmpty() {
						t.Fatal("batch custody retained after write")
					}
				}
				checkNativeCounterWrite(t, sink, counter, view, tc.want)
			})
		}
	}
}

func TestNativeCounterWriterBufferedAndReadFrom(t *testing.T) {
	for _, inspected := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "inspected"}[inspected], func(t *testing.T) {
			sink := &nativeCounterSink{}
			writer, counter, view := nativeCounterWriter(t, sink, inspected)
			buffered := buf.NewBufferedWriter(writer)
			if n, err := buffered.Write([]byte("head")); n != 4 || err != nil {
				t.Fatalf("buffer header: %d %v", n, err)
			}
			checkNativeCounterWrite(t, sink, counter, view, 0)
			if err := buffered.SetBuffered(false); err != nil {
				t.Fatal(err)
			}
			if n, err := buffered.Write([]byte("body")); n != 4 || err != nil {
				t.Fatalf("scalar body: %d %v", n, err)
			}
			checkNativeCounterWrite(t, sink, counter, view, 8)
			n, err := writer.(io.ReaderFrom).ReadFrom(strings.NewReader("tail"))
			if n != 4 || err != nil {
				t.Fatalf("ReadFrom: %d %v", n, err)
			}
			checkNativeCounterWrite(t, sink, counter, view, 12)
		})
	}
}
