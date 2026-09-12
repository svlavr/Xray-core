package hysteria

import (
	"sync"
	"testing"
)

func TestInterConnConcurrentWriteAndClose(t *testing.T) {
	manager := &udpSessionManager{m: make(map[uint32]*InterConn)}
	conn := &InterConn{
		id:    1,
		ch:    make(chan []byte, 1),
		write: func([]byte) error { return nil },
	}
	conn.close = func() {
		manager.Lock()
		manager.close(conn)
		manager.Unlock()
	}
	manager.m[conn.id] = conn

	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		ready.Done()
		<-start
		for range 10_000 {
			_, _ = conn.Write(make([]byte, 4))
		}
	}()
	go func() {
		defer workers.Done()
		ready.Done()
		<-start
		_ = conn.Close()
	}()
	ready.Wait()
	close(start)
	workers.Wait()
}
