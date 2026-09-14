package buf

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type streamReadResult struct {
	payload []byte
	err     error
}

type noDeadlineStreamConn struct {
	started   chan struct{}
	result    chan streamReadResult
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	remaining int
	writeErr  error
	panicAt   int
	writes    int
}

func (c *noDeadlineStreamConn) Read(p []byte) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	select {
	case result := <-c.result:
		return copy(p, result.payload), result.err
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *noDeadlineStreamConn) Write(p []byte) (int, error) {
	c.writes++
	if c.panicAt > 0 && c.writes == c.panicAt {
		panic("scripted write panic")
	}
	n := min(len(p), c.remaining)
	c.remaining -= n
	if c.panicAt > 0 {
		return n, nil
	}
	if n < len(p) {
		return n, c.writeErr
	}
	return n, nil
}

func (c *noDeadlineStreamConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*noDeadlineStreamConn) LocalAddr() net.Addr              { return streamAddr("local") }
func (*noDeadlineStreamConn) RemoteAddr() net.Addr             { return streamAddr("remote") }
func (*noDeadlineStreamConn) SetDeadline(time.Time) error      { return nil }
func (*noDeadlineStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*noDeadlineStreamConn) SetWriteDeadline(time.Time) error { return nil }

type streamAddr string

func (a streamAddr) Network() string { return string(a) }
func (a streamAddr) String() string  { return string(a) }

func newNoDeadlineStreamConn() *noDeadlineStreamConn {
	return &noDeadlineStreamConn{
		started: make(chan struct{}), result: make(chan streamReadResult, 1), closed: make(chan struct{}),
	}
}

func TestBufferToBytesWriterAccounting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []string
		limit int
	}{
		{"single partial", []string{"abcdef"}, 3},
		{"vector partial", []string{"abc", "def"}, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terminal := errors.New("write failure")
			conn := newNoDeadlineStreamConn()
			conn.remaining, conn.writeErr = tc.limit, terminal
			native, offered, accepted := new(appstats.Counter), new(appstats.Counter), new(appstats.Counter)
			writer := NewBufferToBytesWriter(&stat.CounterConnection{Connection: conn, WriteCounter: native}, offered, accepted)
			var mb MultiBuffer
			var total int
			for _, part := range tc.parts {
				total += len(part)
				mb = append(mb, FromBytes([]byte(part)))
			}
			if err := writer.WriteMultiBuffer(mb); !errors.Is(err, terminal) {
				t.Fatalf("write result: %v", err)
			}
			if native.Value() != int64(tc.limit) || accepted.Value() != int64(tc.limit) || offered.Value() != int64(total) {
				t.Fatalf("native=%d accepted=%d offered=%d", native.Value(), accepted.Value(), offered.Value())
			}
		})
	}
}

func TestBufferToBytesWriterRawAndPanicPrefix(t *testing.T) {
	flow := newFlowRawCounter()
	offered := new(appstats.Counter)
	w := NewBufferToBytesWriter(io.Discard, offered, flow)
	finish := BeginRawCopy(w)
	if finish == nil || !flow.deferred {
		t.Fatal("raw begin not visible")
	}
	finish(7)
	if flow.Value() != 7 || offered.Value() != 7 || flow.deferred {
		t.Fatal("raw final count/state")
	}

	conn := newNoDeadlineStreamConn()
	conn.remaining, conn.panicAt = 2, 2
	native, accepted := new(appstats.Counter), new(appstats.Counter)
	w = NewBufferToBytesWriter(&stat.CounterConnection{Connection: conn, WriteCounter: native}, nil, accepted)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("write panic hidden")
			}
		}()
		_ = w.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("abcdef"))})
	}()
	if native.Value() != 2 || accepted.Value() != 2 {
		t.Fatalf("accepted panic prefix native=%d observed=%d", native.Value(), accepted.Value())
	}
}

type flowRawCounter struct {
	appstats.Counter
	deferred bool
}

func newFlowRawCounter() *flowRawCounter { return new(flowRawCounter) }
func (c *flowRawCounter) BeginRawCopy() func(int64) {
	c.deferred = true
	return func(n int64) {
		c.Add(n)
		c.deferred = false
	}
}
