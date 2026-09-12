package httpupgrade

import (
	"bufio"
	stdnet "net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type lifecycleListener struct {
	accepts chan stdnet.Conn
	closed  chan struct{}
	once    sync.Once
}

func (l *lifecycleListener) Accept() (stdnet.Conn, error) {
	select {
	case conn := <-l.accepts:
		return conn, nil
	case <-l.closed:
		return nil, stdnet.ErrClosed
	}
}

func (l *lifecycleListener) Close() error    { l.once.Do(func() { close(l.closed) }); return nil }
func (*lifecycleListener) Addr() stdnet.Addr { return &stdnet.TCPAddr{} }

func TestServerCloseLeavesHeldCallbackReceiptActive(t *testing.T) {
	var tasks task.Lifecycle
	rawListener := &lifecycleListener{accepts: make(chan stdnet.Conn, 1), closed: make(chan struct{})}
	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	s := &server{
		addConn: func(stat.Connection) {
			close(handlerEntered)
			<-handlerRelease
		},
		innnerListener: rawListener,
		lifecycle:      &internet.InboundLifecycle{Tasks: &tasks},
		connections:    make(map[net.Conn]*internet.InboundHandoff),
	}
	if !tasks.Acquire() {
		t.Fatal("accept receipt was rejected")
	}
	go func() { defer tasks.Release(); s.keepAccepting() }()
	server, client := stdnet.Pipe()
	t.Cleanup(func() { client.Close() })
	rawListener.accepts <- server
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
		writeDone <- err
	}()
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", response.StatusCode)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	tasks.Seal()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() { tasks.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("lifecycle joined before held callback returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(handlerRelease)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not join callback")
	}
}

func TestServerRejectsConnectionAfterLifecycleSeal(t *testing.T) {
	var tasks task.Lifecycle
	tasks.Seal()
	s := &server{lifecycle: &internet.InboundLifecycle{Tasks: &tasks}, connections: make(map[net.Conn]*internet.InboundHandoff)}
	server, client := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	if _, ok := s.register(server); ok {
		t.Fatal("sealed lifecycle admitted a connection")
	}
	tasks.Wait()
}

func TestServerCloseRejectsUpgradedCallbackBeforeInvocation(t *testing.T) {
	var tasks task.Lifecycle
	rawListener := &lifecycleListener{accepts: make(chan stdnet.Conn), closed: make(chan struct{})}
	s := &server{
		innnerListener: rawListener,
		lifecycle:      &internet.InboundLifecycle{Tasks: &tasks},
		connections:    make(map[net.Conn]*internet.InboundHandoff),
	}
	server, client := stdnet.Pipe()
	defer client.Close()
	handoff, ok := s.register(server)
	if !ok {
		t.Fatal("connection admission was rejected")
	}
	wrapped := newConnection(server, server.RemoteAddr(), handoff)
	tasks.Seal()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if internet.AcceptInboundHandoff(wrapped) {
		t.Fatal("closed listener allowed a first owner callback")
	}
	s.unregister(server)
	tasks.Release()
	tasks.Wait()
}
