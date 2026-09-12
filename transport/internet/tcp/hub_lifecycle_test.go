package tcp

import (
	"context"
	stdnet "net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type controlledListener struct {
	accepts chan stdnet.Conn
	closed  chan struct{}
	once    sync.Once
}

func TestListenTCPClosesSocketAfterPostBindConfigFailure(t *testing.T) {
	probe, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*stdnet.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	stream := &internet.MemoryStreamConfig{
		ProtocolName: "tcp",
		ProtocolSettings: &Config{HeaderSettings: &serial.TypedMessage{
			Type: "invalid.lifecycle.header",
		}},
	}
	if _, err := ListenTCP(context.Background(), xnet.LocalHostIP, xnet.Port(port), stream, func(stat.Connection) {}); err == nil {
		t.Fatal("invalid header configuration unexpectedly succeeded")
	}
	rebound, err := stdnet.Listen("tcp", (&stdnet.TCPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: port}).String())
	if err != nil {
		t.Fatalf("post-bind failure retained listener socket: %v", err)
	}
	rebound.Close()
}

func (l *controlledListener) Accept() (stdnet.Conn, error) {
	select {
	case conn := <-l.accepts:
		return conn, nil
	case <-l.closed:
		return nil, stdnet.ErrClosed
	}
}

func (l *controlledListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*controlledListener) Addr() stdnet.Addr { return &stdnet.TCPAddr{} }

func TestListenerCloseJoinsAcceptedCallbackReceipt(t *testing.T) {
	var tasks task.Lifecycle
	rawListener := &controlledListener{accepts: make(chan stdnet.Conn, 1), closed: make(chan struct{})}
	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	l := &Listener{
		listener:    rawListener,
		lifecycle:   &internet.InboundLifecycle{Tasks: &tasks},
		connections: make(map[stdnet.Conn]struct{}),
		addConn: func(stat.Connection) {
			close(handlerEntered)
			<-handlerRelease
		},
	}
	if !tasks.Acquire() {
		t.Fatal("accept-loop receipt was rejected")
	}
	go func() { defer tasks.Release(); l.keepAccepting() }()
	server, client := stdnet.Pipe()
	t.Cleanup(func() { client.Close() })
	rawListener.accepts <- server
	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("accepted callback did not start")
	}
	tasks.Seal()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() { tasks.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("listener lifecycle joined before the accepted callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(handlerRelease)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("listener lifecycle did not join the accepted callback")
	}
	l.mu.Lock()
	remaining := len(l.connections)
	l.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("accepted raw connection inventory retained %d entries", remaining)
	}
}

func TestListenerRejectsConnectionAfterLifecycleSeal(t *testing.T) {
	var tasks task.Lifecycle
	tasks.Seal()
	l := &Listener{
		lifecycle:   &internet.InboundLifecycle{Tasks: &tasks},
		connections: make(map[stdnet.Conn]struct{}),
	}
	server, client := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	if l.register(server) {
		t.Fatal("sealed listener admitted a connection")
	}
	tasks.Wait()
}

func TestLegacyAsyncHandoffRetainsConnectionOwnership(t *testing.T) {
	rawListener := &controlledListener{accepts: make(chan stdnet.Conn, 1), closed: make(chan struct{})}
	handed := make(chan stat.Connection, 1)
	l := &Listener{
		listener:    rawListener,
		connections: make(map[stdnet.Conn]struct{}),
		addConn: func(conn stat.Connection) {
			handed <- conn
		},
	}
	go l.keepAccepting()
	server, client := stdnet.Pipe()
	rawListener.accepts <- server
	var received stat.Connection
	select {
	case received = <-handed:
	case <-time.After(time.Second):
		t.Fatal("legacy connection was not handed off")
	}
	payload := []byte("still-open")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeDone <- err
	}()
	buffer := make([]byte, len(payload))
	if _, err := received.Read(buffer); err != nil {
		t.Fatalf("transport closed a successfully handed-off legacy connection: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	received.Close()
	client.Close()
	l.Close()
}
