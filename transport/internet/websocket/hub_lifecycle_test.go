package websocket

import (
	stdnet "net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestListenerCloseLeavesHeldCallbackReceiptActive(t *testing.T) {
	var tasks task.Lifecycle
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	ln := &Listener{
		listener:    listener,
		config:      &Config{},
		lifecycle:   &internet.InboundLifecycle{Tasks: &tasks},
		connections: make(map[*connection]struct{}),
		addConn: func(stat.Connection) {
			close(handlerEntered)
			<-handlerRelease
		},
	}
	ln.server = http.Server{Handler: &requestHandler{path: "/", ln: ln}}
	if !tasks.Acquire() {
		t.Fatal("serve receipt was rejected")
	}
	go func() { defer tasks.Release(); _ = ln.server.Serve(listener) }()
	client, _, err := websocket.DefaultDialer.Dial("ws://"+listener.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	tasks.Seal()
	if err := ln.Close(); err != nil {
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

func TestConnectionCloseJoinsHeartbeatWithoutHeartbeatDelay(t *testing.T) {
	serverReady := make(chan *websocket.Conn, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			serverReady <- conn
		}
	})}
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	client, _, err := websocket.DefaultDialer.Dial("ws://"+listener.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-serverReady
	t.Cleanup(func() { peer.Close() })
	conn := NewConnection(client, client.RemoteAddr(), nil, 60)
	started := time.Now()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Close waited for heartbeat period: %v", elapsed)
	}
	select {
	case <-conn.heartbeatDone:
	default:
		t.Fatal("Close returned before heartbeat joined")
	}
}

func TestListenerCloseRejectsRegisteredCallbackBeforeInvocation(t *testing.T) {
	serverReady := make(chan *websocket.Conn, 1)
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var tasks task.Lifecycle
	ln := &Listener{
		listener:    listener,
		lifecycle:   &internet.InboundLifecycle{Tasks: &tasks},
		connections: make(map[*connection]struct{}),
	}
	ln.server = http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			serverReady <- conn
		}
	})}
	go ln.server.Serve(listener)
	client, _, err := websocket.DefaultDialer.Dial("ws://"+listener.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-serverReady
	defer peer.Close()

	if !tasks.Acquire() {
		t.Fatal("request receipt was rejected")
	}
	wrapped := newConnection(client, client.RemoteAddr(), nil, 60, new(internet.InboundHandoff))
	if !ln.register(wrapped) {
		t.Fatal("upgraded connection registration was rejected")
	}
	tasks.Seal()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if internet.AcceptInboundHandoff(wrapped) {
		t.Fatal("closed listener allowed a first owner callback")
	}
	select {
	case <-wrapped.heartbeatDone:
	default:
		t.Fatal("abortive listener close returned before heartbeat joined")
	}
	ln.unregister(wrapped)
	tasks.Release()
	tasks.Wait()
}
