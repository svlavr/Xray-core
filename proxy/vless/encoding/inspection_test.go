package encoding

import (
	"bytes"
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
	flow := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, func() error { return nil })
	flow.Route(fs.OutboundRef{Tag: "direct"})
	return flow, view
}

func TestInspectionVLESSPacketPrefixResults(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, 2, 3, 7, 8, 11} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			output := &inspectionPacketOutput{limit: limit, fail: io.ErrUnexpectedEOF}
			buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
			buffered.Write([]byte{0, 0})
			buffered.SetFlushNext()
			native := NewMultiLengthPacketWriter(buffered)
			writer := native
			mb := buf.MultiBuffer{buf.FromBytes([]byte("abc")), buf.FromBytes([]byte("de"))}
			err := writer.WriteMultiBuffer(mb)
			if (limit < 0) != (err == nil) {
				t.Fatalf("lower result: %v", err)
			}
			for _, b := range mb {
				if !b.IsEmpty() {
					t.Fatal("input packet not released")
				}
			}
		})
	}
}

func TestInspectionVLESSPacketDropsAndAttachment(t *testing.T) {
	output := &inspectionPacketOutput{limit: -1}
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
	buffered.Write([]byte{0, 0})
	native := NewMultiLengthPacketWriter(buffered)
	buffered.SetFlushNext()
	writer := native
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

func TestInspectionVLESSPacketPendingWrite(t *testing.T) {
	output := &inspectionBlockingPacketWriter{started: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(output.release) }) })
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
	buffered.SetFlushNext()
	writer := NewMultiLengthPacketWriter(buffered)
	mb := buf.MultiBuffer{buf.FromBytes([]byte("late"))}
	done := make(chan error, 1)
	go func() { done <- writer.WriteMultiBuffer(mb) }()
	select {
	case <-output.started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	release.Do(func() { close(output.release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write did not finish")
	}
	if !mb[0].IsEmpty() {
		t.Fatal("packet input not released")
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
