package hysteria

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestLifecycleCloseWaitsForHeldHysteriaCallback(t *testing.T) {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverCertificate := tls.ParseCertificate(certificate)
	serverCertificate.OneTimeLoading = true
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{Certificate: []*tls.Certificate{serverCertificate}},
	}
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Auth: "test-auth"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}},
	}
	var tasks task.Lifecycle
	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	port := udp.PickPort()
	ctx := internet.ContextWithInboundLifecycle(context.Background(), &internet.InboundLifecycle{Tasks: &tasks})
	listener, err := Listen(ctx, net.LocalHostIP, port, serverSettings, func(stat.Connection) {
		close(handlerEntered)
		<-handlerRelease
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(dialCtx, net.TCPDestination(net.DomainAddress("localhost"), port), clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Hysteria callback did not start")
	}
	tasks.Seal()
	if err := listener.Close(); err != nil {
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
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle did not join Hysteria callback")
	}
}

func TestDispatchRejectsSealedHandoff(t *testing.T) {
	var tasks task.Lifecycle
	tasks.Seal()
	var called atomic.Bool
	conn := &InterConn{ch: make(chan []byte), close: func() {}, handoff: new(internet.InboundHandoff)}
	l := &Listener{
		lifecycle: &internet.InboundLifecycle{Tasks: &tasks},
		callbacks: make(map[net.Conn]*internet.InboundHandoff),
		addConn:   func(stat.Connection) { called.Store(true) },
	}
	l.dispatch(conn)
	if called.Load() {
		t.Fatal("sealed lifecycle reached the first owner callback")
	}
	if internet.AcceptInboundHandoff(conn) {
		t.Fatal("sealed callback handoff was not rejected")
	}
}

func TestUDPSessionCleanCancelsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &udpSessionManager{ctx: ctx, m: make(map[uint32]*InterConn)}
	done := make(chan struct{})
	go func() { m.clean(); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP cleanup did not exit after cancellation")
	}
}
