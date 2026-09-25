package encoding

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

type inspectionPacketOutput struct {
	bytes.Buffer
	limit int
	fail  error
}

func (w *inspectionPacketOutput) Write(p []byte) (int, error) {
	n := len(p)
	if w.limit >= 0 {
		n = min(n, max(0, w.limit-w.Len()))
	}
	w.Buffer.Write(p[:n])
	if w.limit >= 0 && w.Len() >= w.limit {
		return n, w.fail
	}
	return n, nil
}

func inspectionPacketFlow(t *testing.T) (fs.Exchange, fs.FlowInspection) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, func() error { return nil })
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	return flow, view
}

func inspectionPacketFact(t *testing.T, view fs.FlowInspection) fs.ByteFact {
	t.Helper()
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("packet view: %+v %v", live, err)
	}
	return live.Rows[0].Downlink
}

func TestInspectionVLESSPacketPrefixResults(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, 2, 3, 7, 8, 11} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			flow, view := inspectionPacketFlow(t)
			output := &inspectionPacketOutput{limit: limit, fail: io.ErrUnexpectedEOF}
			buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
			buffered.Write([]byte{0, 0})
			buffered.SetFlushNext()
			native := NewMultiLengthPacketWriter(buffered)
			writer := buf.AttachWriterReceipt(native, flow)
			mb := buf.MultiBuffer{buf.FromBytes([]byte("abc")), buf.FromBytes([]byte("de"))}
			err := writer.WriteMultiBuffer(mb)
			if (limit < 0) != (err == nil) {
				t.Fatalf("lower result: %v", err)
			}
			fact := inspectionPacketFact(t, view)
			known := uint64(5)
			incomplete := false
			if limit >= 0 {
				known = 0
				incomplete = true
			}
			if fact.Known != known || fact.Incomplete != incomplete {
				t.Fatalf("decoded operation result: %+v, want %d/%v", fact, known, incomplete)
			}
		})
	}
}

func TestInspectionVLESSPacketDropsAndAttachment(t *testing.T) {
	flow, view := inspectionPacketFlow(t)
	output := &inspectionPacketOutput{limit: -1}
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
	buffered.Write([]byte{0, 0})
	native := NewMultiLengthPacketWriter(buffered)
	if native.WithWriterReceipt(nil) != native {
		t.Fatal("disabled writer identity changed")
	}
	attached := native.WithWriterReceipt(flow)
	if attached == native || buf.WriterReceipt(attached) != flow || inspectionPacketFact(t, view).Incomplete {
		t.Fatal("decoded packet owner was not attached")
	}
	other, otherView := inspectionPacketFlow(t)
	buffered.SetFlushNext()
	writer := native.WithWriterReceipt(other)
	oversized := buf.New()
	oversized.Extend(buf.Size)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{oversized}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 || !oversized.IsEmpty() {
		t.Fatal("all-dropped batch flushed framing or retained input")
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ok"))}); err != nil {
		t.Fatal(err)
	}
	if fact := inspectionPacketFact(t, otherView); fact.Known != 2 || fact.Incomplete {
		t.Fatalf("drop/next packet: %+v", fact)
	}
	if output.Len() != 6 {
		t.Fatalf("native header and packet shape: %d", output.Len())
	}
}

type inspectionBlockingPacketWriter struct {
	started, release chan struct{}
	once             sync.Once
}

func (w *inspectionBlockingPacketWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func TestInspectionVLESSPacketLateWriteAfterStop(t *testing.T) {
	flow, view := inspectionPacketFlow(t)
	output := &inspectionBlockingPacketWriter{started: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(output.release) }) })
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
	buffered.SetFlushNext()
	writer := buf.AttachWriterReceipt(NewMultiLengthPacketWriter(buffered), flow)
	done := make(chan error, 1)
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("late"))}) }()
	select {
	case <-output.started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	out, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
	if err != nil || out[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("stop: %+v %v", out, err)
	}
	flow.Finish()
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Reason != fs.EndReasonLocalStop || page.Rows[0].Flow.Downlink.Known != 0 {
		t.Fatalf("owner-end packet snapshot: %+v", page)
	}
	release.Do(func() { close(output.release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late write did not finish")
	}
	page, _ = view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Reason != fs.EndReasonLocalStop || page.Rows[0].Flow.Downlink.Known != 0 {
		t.Fatalf("late packet result: %+v", page)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, total := range totals.Rows {
		known += total.Downlink.Known
	}
	if known != 4 {
		t.Fatalf("late packet totals: %+v", totals)
	}
}

func TestInspectionVLESSPartialPacketRead(t *testing.T) {
	for _, size := range []int{7, buf.Size + 7} {
		wire := append([]byte{byte(size >> 8), byte(size)}, make([]byte, size-1)...)
		mb, err := NewLengthPacketReader(bytes.NewReader(wire)).ReadMultiBuffer()
		if err == nil || len(mb) != 0 {
			buf.ReleaseMulti(mb)
			t.Fatal("incomplete frame escaped decoder")
		}
	}
}
