package dispatcher

import (
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
)

type streamReadResult struct {
	payload []byte
	err     error
}

type blockingUserConn struct {
	started   chan struct{}
	result    chan streamReadResult
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingUserConn() *blockingUserConn {
	return &blockingUserConn{started: make(chan struct{}), result: make(chan streamReadResult, 1), closed: make(chan struct{})}
}

func (c *blockingUserConn) Read(p []byte) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	select {
	case result := <-c.result:
		return copy(p, result.payload), result.err
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}
func (*blockingUserConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *blockingUserConn) Close() error                   { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*blockingUserConn) LocalAddr() stdnet.Addr           { return directUserAddr("local") }
func (*blockingUserConn) RemoteAddr() stdnet.Addr          { return directUserAddr("remote") }
func (*blockingUserConn) SetDeadline(time.Time) error      { return nil }
func (*blockingUserConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingUserConn) SetWriteDeadline(time.Time) error { return nil }

func TestUserStreamReaderRetainedTimeoutAndResume(t *testing.T) {
	counter := new(appstats.Counter)
	conn := newBlockingUserConn()
	retained := buf.New()
	_, _ = retained.Write([]byte("retained"))
	reader := newUserStreamReader(buf.NewReader(conn), buf.MultiBuffer{retained}, conn, counter)

	mb, err := reader.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || string(mb[0].Bytes()) != "retained" {
		t.Fatalf("retained read: %q %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	mb, err = reader.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || mb != nil {
		t.Fatalf("timeout result: %v %v", mb, err)
	}
	<-conn.started
	conn.result <- streamReadResult{payload: []byte("resumed"), err: io.EOF}
	mb, err = reader.ReadMultiBuffer()
	if !errors.Is(err, io.EOF) || string(mb[0].Bytes()) != "resumed" {
		t.Fatalf("resumed read: %q %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	if counter.Value() != int64(len("retainedresumed")) {
		t.Fatalf("returned bytes counted %d", counter.Value())
	}
}

type gatedUserCounter struct {
	appstats.Counter
	entered chan struct{}
	resume  chan struct{}
}

func (c *gatedUserCounter) Add(n int64) int64 {
	close(c.entered)
	<-c.resume
	return c.Counter.Add(n)
}

func TestUserStreamReaderStopJoinsAndReleases(t *testing.T) {
	conn := newBlockingUserConn()
	retained := buf.New()
	_, _ = retained.Write([]byte("held"))
	counter := &gatedUserCounter{entered: make(chan struct{}), resume: make(chan struct{})}
	reader := newUserStreamReader(buf.NewReader(conn), buf.MultiBuffer{retained}, conn, counter)
	readDone := make(chan struct{})
	go func() {
		mb, _ := reader.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		close(readDone)
	}()
	<-counter.entered
	closeDone := make(chan struct{})
	go func() { _ = reader.Close(); close(closeDone) }()
	<-conn.closed
	select {
	case <-closeDone:
		t.Fatal("stop returned before admitted read accounting")
	case <-time.After(20 * time.Millisecond):
	}
	close(counter.resume)
	<-readDone
	<-closeDone
	if reader.retained != nil || reader.pending != nil || !retained.IsEmpty() || counter.Value() != 4 {
		t.Fatal("stop did not join accounting and release ownership")
	}
	if mb, err := reader.ReadMultiBuffer(); mb != nil || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read admitted after stop: %v %v", mb, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUserStreamReaderInterruptJoinsPendingRead(t *testing.T) {
	conn := newBlockingUserConn()
	reader := newUserStreamReader(buf.NewReader(conn), nil, conn, new(appstats.Counter))
	if mb, err := reader.ReadMultiBufferTimeout(time.Millisecond); mb != nil || err != nil {
		t.Fatalf("timeout result: %v %v", mb, err)
	}
	<-conn.started
	reader.Interrupt()
	if reader.pending != nil {
		t.Fatal("pending read survived interrupt")
	}
}
