package buf_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func TestInspectionSelectedExecutionBoundaries(t *testing.T) {
	for _, mode := range []string{"direct", "sniff-replay", "sniff-failed-dial", "sniff-rejected"} {
		t.Run(mode, func(t *testing.T) {
			manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
			if err != nil {
				t.Fatal(err)
			}
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close() })
			flow := manager.Observation().PrepareTCP(fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
			payload := buf.MultiBuffer{buf.FromBytes([]byte("prefix"))}
			cursor := buf.NewInspectionReader(inspectionPacketRead(func() (buf.MultiBuffer, error) {
				mb := payload
				payload = nil
				return mb, io.EOF
			}), flow, func() {})
			t.Cleanup(cursor.Interrupt)
			if mode != "direct" {
				cache := buf.New()
				defer cache.Release()
				if err := cursor.Cache(cache, time.Second); err != nil || cache.String() != "prefix" {
					t.Fatalf("sniff prefix: %q %v", cache.String(), err)
				}
			}
			if mode == "sniff-rejected" {
				flow.Unassign()
			} else {
				flow.Route(fs.OutboundRef{Tag: "selected"})
			}
			before, _ := view.ReadTotals()
			if len(before.Rows) > 0 && before.Rows[0].Uplink != 0 {
				t.Fatal("selection retroactively credited the sniff prefix")
			}
			wantSelected := uint64(0)
			if mode == "direct" || mode == "sniff-replay" {
				mb, err := cursor.ReadMultiBuffer()
				if err != io.EOF || mb.Len() != 6 {
					t.Fatalf("positive read/error changed: %d %v", mb.Len(), err)
				}
				buf.ReleaseMulti(mb)
				mb, err = cursor.ReadMultiBuffer()
				if err != io.EOF || !mb.IsEmpty() {
					t.Fatal("prefix replayed twice")
				}
				wantSelected = 6
			}
			flow.Finish()
			got, _ := view.ReadTotals()
			if got.User.Uplink != 6 || (mode == "sniff-rejected" && len(got.Rows) != 0) {
				t.Fatalf("general admission: %+v", got)
			}
			if mode != "sniff-rejected" && (len(got.Rows) != 1 || got.Rows[0].Outbound.Tag != "selected" || got.Rows[0].Uplink != wantSelected) {
				t.Fatalf("selected consumption: %+v", got)
			}
		})
	}
}

func TestInspectionSelectedLateOverlappingRays(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	root := manager.Observation().Begin(xnet.Network_UDP, fs.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
	older, newer := root.NewLeg(), root.NewLeg()
	older.AddUplink(6) // The callback decoded input before pipe submission.
	newer.AddUplink(3)
	older.Route(fs.OutboundRef{Tag: "older"})
	newer.Route(fs.OutboundRef{Tag: "newer"})
	entered, release := make(chan struct{}), make(chan struct{})
	cursor := buf.NewInspectionReader(inspectionPacketRead(func() (buf.MultiBuffer, error) {
		close(entered)
		<-release
		return buf.MultiBuffer{buf.FromBytes([]byte("prefix"))}, io.ErrUnexpectedEOF
	}), older, func() {})
	cursor.InputAlreadyObserved = true
	t.Cleanup(cursor.Interrupt)
	done := make(chan error, 1)
	go func() {
		mb, err := cursor.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		done <- err
	}()
	<-entered
	newer.AddSelectedUplink(3)
	root.Finish()
	close(release)
	if err := <-done; err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
	older.AddDownlink(2) // Late actual callback output belongs to the older ray.
	got, _ := view.ReadTotals()
	if got.User != (fs.ClientTotals{Uplink: 9, Downlink: 2}) || len(got.Rows) != 2 {
		t.Fatalf("general bytes changed: %+v", got)
	}
	for _, row := range got.Rows {
		if row.Outbound.Tag == "older" && row.Uplink == 6 && row.Downlink == 2 ||
			row.Outbound.Tag == "newer" && row.Uplink == 3 && row.Downlink == 0 {
			continue
		}
		t.Fatalf("late result moved to another ray: %+v", row)
	}
	terminal, _ := view.ReadTerminals()
	if len(terminal.Rows) != 1 || terminal.Rows[0].Flow.Uplink != 9 || terminal.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("late result rewrote owner-end snapshot: %+v", terminal)
	}
}

type inspectionReceipt struct {
	fs.Exchange
	up, down atomic.Uint64
	selected atomic.Uint64
}

func (r *inspectionReceipt) AddUplink(n uint64)         { r.up.Add(n) }
func (r *inspectionReceipt) AddDownlink(n uint64)       { r.down.Add(n) }
func (r *inspectionReceipt) AddSelectedUplink(n uint64) { r.selected.Add(n) }

type inspectionPacketReceipt struct {
	fs.Exchange
	up, packets  uint64
	destinations []xnet.Destination
}

func (r *inspectionPacketReceipt) AddUplink(n uint64)       { r.up += n }
func (r *inspectionPacketReceipt) AddSelectedUplink(uint64) {}
func (r *inspectionPacketReceipt) PacketDestination(d xnet.Destination) {
	r.destinations = append(r.destinations, d)
}

func (r *inspectionPacketReceipt) RecordPacketInput(d xnet.Destination, n uint64) {
	r.packets++
	r.destinations = append(r.destinations, d)
	r.up += n
}

type inspectionInputCounter struct{ value int64 }

func (c *inspectionInputCounter) Value() int64      { return c.value }
func (c *inspectionInputCounter) Set(n int64) int64 { old := c.value; c.value = n; return old }
func (c *inspectionInputCounter) Add(n int64) int64 { c.value += n; return c.value }

type inspectionPacketRead func() (buf.MultiBuffer, error)

func (r inspectionPacketRead) ReadMultiBuffer() (buf.MultiBuffer, error) { return r() }

func TestInspectionCursorPacketInput(t *testing.T) {
	fallback := xnet.UDPDestination(xnet.LocalHostIP, 53)
	explicit := xnet.UDPDestination(xnet.LocalHostIP, 443)
	for _, mode := range []string{"packet", "fallback", "invalid", "empty", "batch", "nil-entry", "observed", "tcp", "replay"} {
		t.Run(mode, func(t *testing.T) {
			packet := buf.FromBytes([]byte("data"))
			packet.UDP = &explicit
			mb := buf.MultiBuffer{packet}
			wantBytes, wantEvents := uint64(4), uint64(1)
			wantDestinations := []xnet.Destination{explicit}
			switch mode {
			case "fallback":
				packet.UDP = nil
				wantDestinations = []xnet.Destination{fallback}
			case "invalid":
				packet.UDP = new(xnet.Destination)
				wantDestinations = []xnet.Destination{{}}
			case "empty":
				packet.Clear()
				wantBytes = 0
			case "batch":
				mb = append(mb, buf.FromBytes([]byte("tail")))
				wantBytes, wantEvents = 8, 0
				wantDestinations = append(wantDestinations, fallback)
			case "nil-entry":
				mb = append(mb, nil)
				wantEvents = 0
			case "observed", "tcp":
				wantEvents, wantDestinations = 0, nil
			}
			receipt, counter := new(inspectionPacketReceipt), new(inspectionInputCounter)
			cursor := buf.NewInspectionReader(inspectionPacketRead(func() (buf.MultiBuffer, error) { return mb, io.EOF }), receipt, func() {})
			defer cursor.Interrupt()
			cursor.SetCounter(counter)
			if mode != "tcp" {
				cursor.PacketDestination = fallback
			}
			cursor.InputAlreadyObserved = mode == "observed"
			if mode == "replay" {
				cache := buf.New()
				defer cache.Release()
				if err := cursor.Cache(cache, time.Second); err != nil || cache.String() != "data" {
					t.Fatalf("packet cache: %q %v", cache.String(), err)
				}
			}
			got, err := cursor.ReadMultiBuffer()
			if err != io.EOF || uint64(got.Len()) != wantBytes {
				t.Fatalf("packet/error changed: %d %v", got.Len(), err)
			}
			buf.ReleaseMulti(got)
			if counter.Value() != int64(wantBytes) {
				t.Fatalf("native counter: %d want %d", counter.Value(), wantBytes)
			}
			if mode == "observed" {
				wantBytes = 0
			}
			if receipt.up != wantBytes || receipt.packets != wantEvents || len(receipt.destinations) != len(wantDestinations) {
				t.Fatalf("receipt up=%d packets=%d destinations=%v", receipt.up, receipt.packets, receipt.destinations)
			}
			for i, want := range wantDestinations {
				if receipt.destinations[i] != want {
					t.Fatalf("packet %d destination: %+v want %+v", i, receipt.destinations[i], want)
				}
			}
		})
	}
}

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

func TestInspectionWriterBatchCountsPartialProgress(t *testing.T) {
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
			if !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 5 {
				t.Fatalf("prefix %d err %v", receipt.down.Load(), err)
			}
		})
	}
}

type inspectionWriteFunc func([]byte) (int, error)

func (f inspectionWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestInspectionWriterBatchCountsPositiveError(t *testing.T) {
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
			if !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 2 {
				t.Fatalf("known=%d err=%v", receipt.down.Load(), err)
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
	if n != 7 || !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 2 {
		t.Fatalf("read-from n=%d known=%d err=%v", n, receipt.down.Load(), err)
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
			if n != 2 || !errors.Is(err, errInspectionWrite) || receipt.down.Load() != 2 {
				t.Fatalf("write n=%d known=%d err=%v", n, receipt.down.Load(), err)
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

func TestInspectionBufferedWriterEmptyAttachment(t *testing.T) {
	for _, test := range []struct {
		name      string
		result    func([]byte) (int, error)
		wantKnown uint64
		wantErr   error
	}{
		{name: "complete", wantKnown: 7},
		{name: "positive-error", result: func([]byte) (int, error) { return 2, errInspectionWrite }, wantKnown: 2, wantErr: errInspectionWrite},
		{name: "zero-error", result: func([]byte) (int, error) { return 0, errInspectionWrite }, wantErr: errInspectionWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := new(inspectionReceipt)
			lower := &bufferedInspectionWriter{result: test.result}
			writer := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: lower})
			if got, attached := buf.AttachWriterReceiptWithStatus(writer, receipt); !attached || got != writer || buf.WriterReceipt(got) != receipt {
				t.Fatal("buffered writer identity or receipt binding changed")
			}
			writer.SetFlushNext()
			err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
			if !errors.Is(err, test.wantErr) || receipt.down.Load() != test.wantKnown {
				t.Fatalf("known=%d err=%v", receipt.down.Load(), err)
			}
			if len(lower.writes) != 1 || string(lower.writes[0]) != "payload" {
				t.Fatalf("native coalescing/order changed: %q", lower.writes)
			}
		})
	}
}

func TestInspectionBufferedWriterFlushedAttachment(t *testing.T) {
	receipt := new(inspectionReceipt)
	lower := new(bufferedInspectionWriter)
	writer := buf.NewBufferedWriter(&buf.BufferToBytesWriter{Writer: lower})
	if _, err := writer.Write([]byte("head")); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetBuffered(false); err != nil {
		t.Fatal(err)
	}
	if got, attached := buf.AttachWriterReceiptWithStatus(writer, receipt); !attached || got != writer || buf.WriterReceipt(got) != receipt {
		t.Fatal("flushed writer did not bind the original receipt")
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
		t.Fatalf("payload credit changed: %d", receipt.down.Load())
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

type inspectionReceiptBindingProbe struct{ bound fs.Exchange }

func (w *inspectionReceiptBindingProbe) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (w *inspectionReceiptBindingProbe) WithWriterReceipt(receipt fs.Exchange) buf.Writer {
	w.bound = receipt
	return w
}

func TestInspectionBufferedWriterRejectsPendingBytes(t *testing.T) {
	for _, kind := range []string{"vector", "sequential", "capability", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			receipt := new(inspectionReceipt)
			sink := new(bufferedInspectionWriter)
			probe := new(inspectionReceiptBindingProbe)
			unsupported := new(unsupportedBufferedWriter)
			var lower buf.Writer = &buf.BufferToBytesWriter{Writer: sink}
			switch kind {
			case "sequential":
				lower = &buf.SequentialWriter{Writer: sink}
			case "capability":
				lower = probe
			case "unsupported":
				lower = unsupported
			}
			buffered := buf.NewBufferedWriter(lower)
			defer buf.DiscardBufferedWriter(buffered)
			if _, err := buffered.Write([]byte("head")); err != nil {
				t.Fatal(err)
			}
			if got, attached := buf.AttachWriterReceiptWithStatus(buffered, receipt); attached || got != buffered || buf.WriterReceipt(got) != nil || probe.bound != nil {
				t.Fatal("pending bytes accepted or lower writer changed")
			}
			if got := buf.AttachWriterReceipt(buffered, receipt); got != buffered {
				t.Fatal("convenience attachment changed rejected writer")
			}
			if len(sink.writes) != 0 || unsupported.got != "" {
				t.Fatal("attachment flushed pending bytes")
			}
			buffered.SetFlushNext()
			if err := buffered.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))}); err != nil {
				t.Fatal(err)
			}
			if kind == "vector" || kind == "sequential" {
				if len(sink.writes) != 1 || string(sink.writes[0]) != "headpayload" {
					t.Fatalf("native coalescing/order changed: %q", sink.writes)
				}
			} else if kind == "unsupported" && unsupported.got != "headpayload" {
				t.Fatalf("unsupported writer lost bytes: %q", unsupported.got)
			}
			if receipt.down.Load() != 0 || probe.bound != nil {
				t.Fatal("rejected writer credited framing or payload")
			}
		})
	}
}

func TestInspectionReceiptBatchResult(t *testing.T) {
	receipt := new(inspectionReceipt)
	buf.RecordBufferOperation(receipt, 7, errInspectionWrite)
	buf.RecordBufferOperation(receipt, 0, nil)
	if receipt.down.Load() != 0 {
		t.Fatal("failed or empty batch credited")
	}
	buf.RecordBufferOperation(receipt, 4, nil)
	if receipt.down.Load() != 4 {
		t.Fatal("completed batch credit lost")
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

// BenchmarkInspectionWriter measures adapter/allocation cost with an in-memory
// sink. It does not measure kernel writev or network throughput.
func BenchmarkInspectionWriter(b *testing.B) {
	for _, kind := range []string{"vector", "sequential"} {
		for _, mode := range []string{"off", "on"} {
			for _, operation := range []string{"scalar", "batch"} {
				b.Run(kind+"/"+mode+"/"+operation, func(b *testing.B) {
					payload := make([]byte, 1024)
					receipt := new(inspectionReceipt)
					batchSize := 1
					if operation == "batch" {
						batchSize = 4
					}
					b.SetBytes(int64(batchSize * len(payload)))
					b.ReportAllocs()
					for b.Loop() {
						var writer buf.Writer
						if kind == "vector" {
							writer = &buf.BufferToBytesWriter{Writer: io.Discard}
						} else {
							writer = &buf.SequentialWriter{Writer: io.Discard}
						}
						if mode == "on" {
							writer = buf.AttachWriterReceipt(writer, receipt)
						}
						if operation == "scalar" {
							if n, err := writer.(io.Writer).Write(payload); err != nil || n != len(payload) {
								b.Fatalf("scalar: %d %v", n, err)
							}
						} else if err := writer.WriteMultiBuffer(buf.MultiBuffer{
							buf.FromBytes(payload), buf.FromBytes(payload), buf.FromBytes(payload), buf.FromBytes(payload),
						}); err != nil {
							b.Fatal(err)
						}
					}
					if mode == "on" && receipt.down.Load() != uint64(b.N*batchSize*len(payload)) {
						b.Fatal("writer lost or duplicated byte credit")
					}
				})
			}
		}
	}
}
