package buf_test

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	fs "github.com/xtls/xray-core/features/stats"
)

type inspectionReceipt struct {
	fs.Exchange
	up, down   atomic.Uint64
	reason     atomic.Uint32
	incomplete atomic.Bool
}

func (r *inspectionReceipt) AddUplink(n uint64)               { r.up.Add(n) }
func (r *inspectionReceipt) AddDownlink(n uint64)             { r.down.Add(n) }
func (r *inspectionReceipt) MarkUplinkIncomplete()            { r.incomplete.Store(true) }
func (r *inspectionReceipt) MarkDownlinkIncomplete()          { r.incomplete.Store(true) }
func (r *inspectionReceipt) SetEndReason(reason fs.EndReason) { r.reason.Store(uint32(reason)) }

type inspectionReader struct {
	started chan struct{}
	release chan struct{}
	done    chan struct{}
}

func (r *inspectionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.started)
	<-r.release
	close(r.done)
	return buf.MultiBuffer{buf.FromBytes([]byte("tail"))}, io.EOF
}

func TestInspectionCursorTimeoutPositiveErrorAndReplay(t *testing.T) {
	for _, timed := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "timed-read"}[timed], func(t *testing.T) {
			receipt := new(inspectionReceipt)
			lower := &inspectionReader{started: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
			cursor := buf.NewInspectionReader(&buf.BufferedReader{Reader: lower, Buffer: buf.MultiBuffer{buf.FromBytes([]byte("prefix"))}}, receipt, func() {})
			defer cursor.Interrupt()
			cache := buf.New()
			defer cache.Release()
			if err := cursor.Cache(cache, time.Millisecond); err != nil || cache.String() != "prefix" {
				t.Fatalf("residual %q %v", cache.String(), err)
			}
			if err := cursor.Cache(cache, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			<-lower.started
			if receipt.up.Load() != 6 {
				t.Fatal("pending read credited or released")
			}
			close(lower.release)
			<-lower.done
			if err := cursor.Cache(cache, time.Second); err != nil || cache.String() != "prefixtail" {
				t.Fatalf("cache %q %v", cache.String(), err)
			}
			var mb buf.MultiBuffer
			var err error
			if timed {
				mb, err = cursor.ReadMultiBufferTimeout(time.Second)
			} else {
				mb, err = cursor.ReadMultiBuffer()
			}
			if mb.String() != "prefixtail" || err != io.EOF {
				t.Fatalf("replay %q %v", mb.String(), err)
			}
			buf.ReleaseMulti(mb)
			if receipt.up.Load() != 10 {
				t.Fatalf("double credit: %d", receipt.up.Load())
			}
		})
	}
}

func TestInspectionCursorInterruptPending(t *testing.T) {
	receipt := new(inspectionReceipt)
	lower := &inspectionReader{started: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	cursor := buf.NewInspectionReader(&buf.BufferedReader{Reader: lower}, receipt, func() { close(lower.release) })
	mb, err := cursor.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || mb.Len() != 0 {
		t.Fatalf("pending %v %v", mb, err)
	}
	<-lower.started
	cursor.Interrupt()
	<-lower.done
	if receipt.up.Load() != 0 {
		t.Fatal("abandoned result retained or credited")
	}
	if mb, err = cursor.ReadMultiBuffer(); !errors.Is(err, io.ErrClosedPipe) || mb.Len() != 0 {
		t.Fatalf("sealed read %v %v", mb, err)
	}
	cursor.Interrupt()
}

type prefixWriter struct{ calls int }

var errInspectionWrite = errors.New("injected write failure")

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return len(p), nil
	}
	return min(2, len(p)), errInspectionWrite
}

func TestInspectionWriterBatchErrorIsCoarse(t *testing.T) {
	for _, vector := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequential", true: "vector"}[vector], func(t *testing.T) {
			receipt := new(inspectionReceipt)
			lower := new(prefixWriter)
			var writer buf.Writer
			if vector {
				writer = &buf.BufferToBytesWriter{Writer: lower}
			} else {
				writer = &buf.SequentialWriter{Writer: lower}
			}
			writer = buf.AttachWriterReceipt(writer, receipt)
			err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("abc")), buf.FromBytes([]byte("defgh"))})
			if !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 0 || !receipt.incomplete.Load() || fs.EndReason(receipt.reason.Load()) != fs.EndReasonWriteError {
				t.Fatalf("prefix %d err %v", receipt.down.Load(), err)
			}
		})
	}
}

type inspectionWriteFunc func([]byte) (int, error)

func (f inspectionWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestInspectionWriterBatchErrorsAreCoarse(t *testing.T) {
	for _, kind := range []string{"scalar", "vector", "sequential"} {
		t.Run(kind, func(t *testing.T) {
			receipt := new(inspectionReceipt)
			lower := inspectionWriteFunc(func(p []byte) (int, error) {
				return min(2, len(p)), errInspectionWrite
			})
			var writer buf.Writer = &buf.BufferToBytesWriter{Writer: lower}
			if kind == "sequential" {
				writer = &buf.SequentialWriter{Writer: lower}
			}
			writer = buf.AttachWriterReceipt(writer, receipt)
			mb := buf.MultiBuffer{buf.FromBytes([]byte("first"))}
			if kind != "scalar" {
				mb = append(mb, buf.FromBytes([]byte("second")))
			}
			err := writer.WriteMultiBuffer(mb)
			if !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 0 || !receipt.incomplete.Load() || fs.EndReason(receipt.reason.Load()) != fs.EndReasonWriteError {
				t.Fatalf("known=%d reason=%d err=%v", receipt.down.Load(), receipt.reason.Load(), err)
			}
		})
	}
}

func TestInspectionWriterReadFromUsesReceiptPath(t *testing.T) {
	receipt := new(inspectionReceipt)
	lower := inspectionWriteFunc(func(p []byte) (int, error) {
		return min(2, len(p)), errInspectionWrite
	})
	writer := buf.AttachWriterReceipt(&buf.BufferToBytesWriter{Writer: lower}, receipt)
	readerFrom, ok := writer.(io.ReaderFrom)
	if !ok {
		t.Fatal("observed vector writer lost ReaderFrom")
	}
	n, err := readerFrom.ReadFrom(strings.NewReader("payload"))
	if n != 7 || !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 0 || !receipt.incomplete.Load() || fs.EndReason(receipt.reason.Load()) != fs.EndReasonWriteError {
		t.Fatalf("read-from n=%d known=%d reason=%d err=%v", n, receipt.down.Load(), receipt.reason.Load(), err)
	}
}

func TestInspectionWriterDirectWriteUsesReceiptPath(t *testing.T) {
	for _, sequential := range []bool{false, true} {
		t.Run(map[bool]string{false: "vector", true: "sequential"}[sequential], func(t *testing.T) {
			receipt := new(inspectionReceipt)
			lower := inspectionWriteFunc(func(p []byte) (int, error) {
				return min(2, len(p)), errInspectionWrite
			})
			var writer buf.Writer = &buf.BufferToBytesWriter{Writer: lower}
			if sequential {
				writer = &buf.SequentialWriter{Writer: lower}
			}
			writer = buf.AttachWriterReceipt(writer, receipt)
			direct, ok := writer.(io.Writer)
			if !ok {
				t.Fatal("observed writer lost io.Writer")
			}
			n, err := direct.Write([]byte("payload"))
			if n != 2 || !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 2 || fs.EndReason(receipt.reason.Load()) != fs.EndReasonWriteError {
				t.Fatalf("write n=%d known=%d reason=%d err=%v", n, receipt.down.Load(), receipt.reason.Load(), err)
			}
		})
	}
}

type bufferedInspectionWriter struct {
	writes [][]byte
	result func([]byte) (int, error)
}

func (w *bufferedInspectionWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, append([]byte(nil), p...))
	if w.result != nil {
		return w.result(p)
	}
	return len(p), nil
}

func TestInspectionBufferedWriterExcludesPendingPrefix(t *testing.T) {
	for _, test := range []struct {
		name      string
		result    func([]byte) (int, error)
		wantKnown uint64
		wantErr   error
	}{
		{name: "complete", wantKnown: 7},
		{name: "partial-error-inside-header", result: func([]byte) (int, error) { return 2, errInspectionWrite }, wantErr: errInspectionWrite},
		{name: "partial-error-crosses-header", result: func([]byte) (int, error) { return 6, errInspectionWrite }, wantKnown: 2, wantErr: errInspectionWrite},
		{name: "nil-short", result: func([]byte) (int, error) { return 6, nil }, wantKnown: 2, wantErr: io.ErrShortWrite},
		{name: "nil-zero", result: func([]byte) (int, error) { return 0, nil }, wantErr: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := new(inspectionReceipt)
			lower := &bufferedInspectionWriter{result: test.result}
			writer := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: lower})
			if _, err := writer.Write([]byte("head")); err != nil {
				t.Fatal(err)
			}
			if got := buf.AttachWriterReceipt(writer, receipt); got != writer || buf.WriterReceipt(got) != receipt {
				t.Fatal("buffered writer identity or receipt binding changed")
			}
			writer.SetFlushNext()
			err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
			if !errors.Is(err, test.wantErr) || receipt.down.Load() != test.wantKnown {
				t.Fatalf("known=%d err=%v", receipt.down.Load(), err)
			}
			if len(lower.writes) != 1 || string(lower.writes[0]) != "headpayload" {
				t.Fatalf("native coalescing/order changed: %q", lower.writes)
			}
		})
	}
}

func TestInspectionBufferedWriterPrefixIsConsumedOnce(t *testing.T) {
	receipt := new(inspectionReceipt)
	lower := new(bufferedInspectionWriter)
	writer := buf.NewBufferedWriter(&buf.BufferToBytesWriter{Writer: lower})
	if _, err := writer.Write([]byte("head")); err != nil {
		t.Fatal(err)
	}
	buf.AttachWriterReceipt(writer, receipt)
	if err := writer.SetBuffered(false); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("direct")); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("multi"))}); err != nil {
		t.Fatal(err)
	}
	readerFrom, ok := interface{}(writer).(io.ReaderFrom)
	if !ok {
		t.Fatal("buffered writer lost ReaderFrom")
	}
	if n, err := readerFrom.ReadFrom(strings.NewReader("stream")); n != 6 || err != nil {
		t.Fatalf("ReadFrom %d %v", n, err)
	}
	if receipt.down.Load() != uint64(len("directmultistream")) {
		t.Fatalf("prefix repeated or payload lost: %d", receipt.down.Load())
	}
	if got := strings.Join(func() []string {
		out := make([]string, len(lower.writes))
		for i := range lower.writes {
			out[i] = string(lower.writes[i])
		}
		return out
	}(), ""); got != "headdirectmultistream" {
		t.Fatalf("write order changed: %q", got)
	}
}

func TestInspectionBufferedWriterFailedFlushDiscardsHeaderTail(t *testing.T) {
	receipt := new(inspectionReceipt)
	calls := 0
	lower := &bufferedInspectionWriter{result: func(p []byte) (int, error) {
		calls++
		if calls == 1 {
			return 2, errInspectionWrite
		}
		return len(p), nil
	}}
	writer := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: lower})
	if _, err := writer.Write([]byte("head")); err != nil {
		t.Fatal(err)
	}
	buf.AttachWriterReceipt(writer, receipt)
	writer.SetFlushNext()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("lost"))}); !errors.Is(err, errInspectionWrite) {
		t.Fatalf("first write: %v", err)
	}
	if _, err := writer.Write([]byte("next")); err != nil {
		t.Fatalf("continuation: %v", err)
	}
	if receipt.down.Load() != 4 {
		t.Fatalf("discarded header tail subtracted from new payload: %d", receipt.down.Load())
	}
}

type unsupportedBufferedWriter struct{ got string }

func (w *unsupportedBufferedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.got += mb.String()
	buf.ReleaseMulti(mb)
	return nil
}

func TestInspectionBufferedWriterUnsupportedLowerIsUnchanged(t *testing.T) {
	receipt := new(inspectionReceipt)
	lower := new(unsupportedBufferedWriter)
	writer := buf.NewBufferedWriter(lower)
	if _, err := writer.Write([]byte("header")); err != nil {
		t.Fatal(err)
	}
	if got := buf.AttachWriterReceipt(writer, receipt); got != writer || buf.WriterReceipt(got) != nil {
		t.Fatal("unsupported buffered writer acquired a false receipt")
	}
	if !receipt.incomplete.Load() {
		t.Fatal("unsupported buffered writer did not report unavailable result")
	}
	if err := writer.SetBuffered(false); err != nil || lower.got != "header" {
		t.Fatalf("unsupported writer state changed: %q %v", lower.got, err)
	}
}

type inspectionCounter struct{ value atomic.Int64 }

func (c *inspectionCounter) Value() int64      { return c.value.Load() }
func (c *inspectionCounter) Set(n int64) int64 { return c.value.Swap(n) }
func (c *inspectionCounter) Add(n int64) int64 { return c.value.Add(n) }

type inspectionRepeatedReader struct{}

func (inspectionRepeatedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return buf.MultiBuffer{buf.FromBytes([]byte{1})}, nil
}

func TestInspectionCursorCounterBinding(t *testing.T) {
	receipt := new(inspectionReceipt)
	cursor := buf.NewInspectionReader(&buf.BufferedReader{Reader: inspectionRepeatedReader{}}, receipt, func() {})
	defer cursor.Interrupt()
	a, b := new(inspectionCounter), new(inspectionCounter)
	cursor.SetCounter(a)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cursor.SetCounter(a)
			cursor.SetCounter(b)
		}
	}()
	for i := 0; i < 1000; i++ {
		mb, err := cursor.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		buf.ReleaseMulti(mb)
	}
	wg.Wait()
	if a.Value()+b.Value() != 1000 || receipt.up.Load() != 1000 {
		t.Fatal("counter binding lost or duplicated consumption")
	}
}
