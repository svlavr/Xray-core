package mux

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestXUDPStoppedSessionDoesNotDequeueRetainedPacket(t *testing.T) {
	r, w := pipe.New()
	defer r.Interrupt()
	m := NewSessionManager()
	x := &XUDP{selected: true, Status: Active}
	old := &Session{ID: 1, parent: m, input: r, output: w, XUDP: x, server: true, done: done.New()}
	x.Mux = old
	m.Add(old)
	w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("queued"))})
	old.Close(false)
	mb, err := old.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != io.EOF {
		t.Fatalf("stopped session retained read access: %v", err)
	}
	mb, err = r.ReadMultiBufferTimeout(time.Second)
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "queued" {
		t.Fatalf("old session consumed queued packet: %q %v", mb.String(), err)
	}
	old.finishServer()
}

func TestXUDPReadFenceJoinsNativeReadAndRecoversEOF(t *testing.T) {
	r, w := pipe.New()
	defer r.Interrupt()
	m := NewSessionManager()
	x := &XUDP{selected: true, Status: Active}
	old := &Session{ID: 1, parent: m, input: r, output: w, XUDP: x, server: true, done: done.New()}
	x.Mux = old
	m.Add(old)
	result := make(chan error, 1)
	go func() { mb, err := old.ReadMultiBuffer(); buf.ReleaseMulti(mb); result <- err }()
	deadline := time.Now().Add(time.Second)
	for old.ioGate.TryLock() {
		old.ioGate.Unlock()
		if !time.Now().Before(deadline) {
			t.Fatal("old read did not enter its gate")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { old.Close(false); close(closed) }()
	muxWait(t, closed)
	if err := retainedResult(t, result); err != io.EOF {
		t.Fatalf("native read did not acknowledge EOF: %v", err)
	}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("next"))}); err != nil {
		t.Fatal(err)
	}
	mb, err := r.ReadMultiBufferTimeout(time.Second)
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != "next" {
		t.Fatalf("EOF poisoned next native reader: %q %v", mb.String(), err)
	}
	old.finishServer()
}
