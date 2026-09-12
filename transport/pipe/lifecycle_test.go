package pipe_test

import (
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/pipe"
)

type testWriteLifecycle struct {
	writer    *Writer
	bytes     atomic.Uint64
	halfClose atomic.Bool
	sealed    atomic.Bool
	drained   atomic.Bool
}

func (l *testWriteLifecycle) BeginWrite() bool { return true }
func (l *testWriteLifecycle) CompleteWrite(_ bool, bytes uint64) {
	l.bytes.Store(bytes)
}

func (l *testWriteLifecycle) HalfClose() {
	_ = l.writer.Len()
	l.halfClose.Store(true)
}

func (l *testWriteLifecycle) Seal() {
	_ = l.writer.Len()
	l.sealed.Store(true)
}

func (l *testWriteLifecycle) MarkDrained() {
	_ = l.writer.Len()
	l.drained.Store(true)
}

func TestWriteLifecycleRunsAfterStockActionsAndOutsidePipeLock(t *testing.T) {
	lifecycle := &testWriteLifecycle{}
	reader, writer := New(WithWriteLifecycle(lifecycle))
	lifecycle.writer = writer
	payload := buf.New()
	payload.WriteString("four")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.bytes.Load(); got != 4 {
		t.Fatalf("got %d accepted bytes, want 4", got)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !lifecycle.halfClose.Load() || !lifecycle.sealed.Load() || lifecycle.drained.Load() {
		t.Fatalf("unexpected close receipts half=%v sealed=%v drained=%v", lifecycle.halfClose.Load(), lifecycle.sealed.Load(), lifecycle.drained.Load())
	}
	if _, err := reader.ReadMultiBuffer(); err != nil {
		t.Fatal(err)
	}
	if !lifecycle.drained.Load() {
		t.Fatal("drain receipt missing after buffered data left the pipe")
	}
}
