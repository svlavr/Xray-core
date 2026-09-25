package hysteria

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestInterConnCloseDuringBlockedWrite(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	manager := &udpSessionManager{m: make(map[uint32]*InterConn)}
	conn := &InterConn{id: 1, ch: make(chan []byte), write: func([]byte) error {
		close(started)
		<-release
		return nil
	}}
	sibling := &InterConn{id: 2, ch: make(chan []byte, 1)}
	manager.m[conn.id], manager.m[sibling.id] = conn, sibling
	conn.close = func() { manager.Lock(); manager.close(conn); manager.Unlock() }
	writeDone := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 4)); writeDone <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("write did not reach the blocked transport")
	}
	closed := make(chan struct{})
	go func() { conn.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("session close waited for the blocked transport write")
	}
	// Native manager access and a different session must remain usable before
	// the outstanding send finishes, without closing the shared carrier.
	progress := make(chan struct{})
	go func() { manager.feed(sibling.id, []byte("sibling")); close(progress) }()
	select {
	case <-progress:
	case <-time.After(time.Second):
		t.Fatal("blocked write held the manager or sibling")
	}
	if got := <-sibling.ch; string(got) != "sibling" {
		t.Fatalf("sibling payload %q", got)
	}
	if _, err := conn.Write(make([]byte, 4)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("new post-close write returned %v", err)
	}
	unblock()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted write did not finish after transport release")
	}
}
