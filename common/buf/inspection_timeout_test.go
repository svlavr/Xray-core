package buf

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
)

type timeoutInspectionReceipt struct {
	stats.Exchange
	decoded, selected uint64
	destinations      []net.Destination
}

func (r *timeoutInspectionReceipt) AddUplink(n uint64)         { r.decoded += n }
func (r *timeoutInspectionReceipt) AddSelectedUplink(n uint64) { r.selected += n }
func (r *timeoutInspectionReceipt) RecordPacketInput(d net.Destination, n uint64) {
	r.destinations = append(r.destinations, d)
	r.decoded += n
}

type timeoutInspectionCounter struct{ value uint64 }

func (c *timeoutInspectionCounter) Value() int64 { return int64(c.value) }
func (c *timeoutInspectionCounter) Set(n int64) int64 {
	old := c.Value()
	c.value = uint64(n)
	return old
}
func (c *timeoutInspectionCounter) Add(n int64) int64 { c.value += uint64(n); return c.Value() }

type timeoutInspectionLower struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	once    sync.Once
	payload *Buffer
	err     error
}

func (r *timeoutInspectionLower) ReadMultiBuffer() (MultiBuffer, error) {
	if r.calls.Add(1) != 1 {
		return nil, io.EOF
	}
	close(r.started)
	<-r.release
	return MultiBuffer{r.payload}, r.err
}

func (r *timeoutInspectionLower) finish() { r.once.Do(func() { close(r.release) }) }

func waitInspectionSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending lower read did not complete")
	}
}

func TestInspectionTimeoutReusesPendingRead(t *testing.T) {
	lower := &timeoutInspectionLower{started: make(chan struct{}), release: make(chan struct{}), payload: FromBytes([]byte("tail")), err: io.EOF}
	receipt, counter := new(timeoutInspectionReceipt), new(timeoutInspectionCounter)
	cursor := NewInspectionReader(lower, receipt, func() {})
	cursor.SetCounter(counter)
	t.Cleanup(func() { cursor.Interrupt(); lower.finish() })
	var pending *inspectionRead
	for i := 0; i < 3; i++ {
		mb, err := cursor.ReadMultiBufferTimeout(time.Millisecond)
		if err != ErrReadTimeout || !mb.IsEmpty() {
			t.Fatalf("wait %d: %q %v", i, mb.String(), err)
		}
		if i == 0 {
			pending = cursor.pending
			waitInspectionSignal(t, lower.started)
		}
		if pending == nil || cursor.pending != pending || lower.calls.Load() != 1 {
			t.Fatal("timeout replaced or duplicated the pending lower read")
		}
	}
	cache := New()
	defer cache.Release()
	if err := cursor.Cache(cache, time.Millisecond); err != ErrReadTimeout || !cache.IsEmpty() || cursor.replayErr != nil || cursor.pending != pending {
		t.Fatalf("empty cache retained timeout: %q %v", cache.String(), err)
	}
	if receipt.decoded != 0 || receipt.selected != 0 || counter.Value() != 0 {
		t.Fatal("pending bytes were credited before consumption")
	}
	lower.finish()
	waitInspectionSignal(t, pending.done)
	mb, err := cursor.ReadMultiBufferTimeout(time.Second)
	defer ReleaseMulti(mb)
	if mb.String() != "tail" || err != io.EOF || lower.calls.Load() != 1 || receipt.decoded != 4 || receipt.selected != 4 || counter.Value() != 4 {
		t.Fatalf("delayed result changed: %q %v decoded=%d selected=%d counter=%d reads=%d", mb.String(), err, receipt.decoded, receipt.selected, counter.Value(), lower.calls.Load())
	}
}

func TestInspectionCacheTimeoutRetainsPrefixAndTerminalReplay(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("injected terminal read")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			fallback := net.UDPDestination(net.LocalHostIP, 53)
			explicit := net.UDPDestination(net.LocalHostIP, 443)
			prefix := FromBytes([]byte("prefix"))
			tail := FromBytes([]byte("tail"))
			tail.UDP = &explicit
			lower := &timeoutInspectionLower{started: make(chan struct{}), release: make(chan struct{}), payload: tail, err: terminal}
			receipt, counter := new(timeoutInspectionReceipt), new(timeoutInspectionCounter)
			cursor := NewInspectionReader(&BufferedReader{Reader: lower, Buffer: MultiBuffer{prefix}}, receipt, func() {})
			cursor.PacketDestination = fallback
			cursor.SetCounter(counter)
			t.Cleanup(func() { cursor.Interrupt(); lower.finish() })
			cache := New()
			defer cache.Release()
			if err := cursor.Cache(cache, time.Second); err != nil || cache.String() != "prefix" {
				t.Fatalf("initial prefix: %q %v", cache.String(), err)
			}
			for i := 0; i < 2; i++ {
				if err := cursor.Cache(cache, time.Millisecond); err != nil || cache.String() != "prefix" || cursor.replayErr != nil {
					t.Fatalf("retained prefix after timeout: %q %v", cache.String(), err)
				}
			}
			waitInspectionSignal(t, lower.started)
			if lower.calls.Load() != 1 || receipt.decoded != 6 || receipt.selected != 0 || counter.Value() != 6 {
				t.Fatal("timed cache changed lower read or prefix credit")
			}
			pending := cursor.pending
			lower.finish()
			waitInspectionSignal(t, pending.done)
			if err := cursor.Cache(cache, time.Second); err != nil || cache.String() != "prefixtail" {
				t.Fatalf("delayed cache: %q %v", cache.String(), err)
			}
			if err := cursor.Cache(cache, time.Second); err != terminal || lower.calls.Load() != 1 {
				t.Fatalf("terminal cache result: %v reads=%d", err, lower.calls.Load())
			}
			mb, err := cursor.ReadMultiBuffer()
			if mb.String() != "prefixtail" || err != terminal || len(mb) != 2 || mb[0] != prefix || mb[1] != tail || mb[1].UDP != &explicit {
				ReleaseMulti(mb)
				t.Fatalf("retained bytes/metadata/error changed: %v", err)
			}
			ReleaseMulti(mb)
			mb, err = cursor.ReadMultiBuffer()
			defer ReleaseMulti(mb)
			if !mb.IsEmpty() || err != io.EOF || lower.calls.Load() != 2 {
				t.Fatalf("terminal replay was delivered twice: %q %v", mb.String(), err)
			}
			if receipt.decoded != 10 || receipt.selected != 10 || counter.Value() != 10 || len(receipt.destinations) != 2 || receipt.destinations[0] != fallback || receipt.destinations[1] != explicit {
				t.Fatalf("duplicate/missing decoded packet credit: %+v counter=%d", receipt, counter.Value())
			}
		})
	}
}

func TestInspectionTimeoutInterruptReleasesLateResult(t *testing.T) {
	payload := New()
	payload.Write([]byte("abandoned"))
	lower := &timeoutInspectionLower{started: make(chan struct{}), release: make(chan struct{}), payload: payload, err: io.ErrUnexpectedEOF}
	receipt, counter := new(timeoutInspectionReceipt), new(timeoutInspectionCounter)
	unblocks := 0
	cursor := NewInspectionReader(lower, receipt, func() { unblocks++ })
	cursor.SetCounter(counter)
	t.Cleanup(func() { cursor.Interrupt(); lower.finish() })
	if mb, err := cursor.ReadMultiBufferTimeout(time.Millisecond); err != ErrReadTimeout || !mb.IsEmpty() {
		t.Fatalf("pending wait: %q %v", mb.String(), err)
	}
	pending := cursor.pending
	cursor.Interrupt()
	cursor.Interrupt()
	if unblocks != 1 {
		t.Fatalf("owned endpoint unblocked %d times", unblocks)
	}
	lower.finish()
	waitInspectionSignal(t, pending.done)
	if !payload.IsEmpty() || receipt.decoded != 0 || receipt.selected != 0 || counter.Value() != 0 {
		t.Fatal("late abandoned result was retained or credited")
	}
	if mb, err := cursor.ReadMultiBuffer(); err != io.ErrClosedPipe || !mb.IsEmpty() {
		t.Fatalf("sealed read: %q %v", mb.String(), err)
	}
}
