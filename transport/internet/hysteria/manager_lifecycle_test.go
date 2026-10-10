package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/semaphore"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

func u2Carrier(t *testing.T) (*client, *quic.Conn) {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: common.Must2(x509.ParsePKCS8PrivateKey(certificate.PrivateKey))}}, NextProtos: []string{"fixture"}}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	qc, err := tr.Dial(ctx, listener.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"fixture"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.CloseWithError(0, "fixture cleanup") })
	c := &client{access: semaphore.New(1), conn: qc, tr: tr, pktConn: pc, udpSM: &udpSessionManager{conn: qc, m: make(map[uint32]*InterConn), next: 1}}
	go c.udpSM.run()
	t.Cleanup(func() { c.clean(true) })
	return c, peer
}

func u2Wait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("lifecycle completion did not arrive")
}

func u2Removed(m *clientManager, key dialerConf) bool {
	m.RLock()
	defer m.RUnlock()
	return m.m[key] == nil
}

func TestU2ManagerBusyClientProgress(t *testing.T) {
	busy := &client{access: semaphore.New(1), instance: new(core.Instance)}
	<-busy.access.Wait()
	defer busy.access.Signal()
	ready, _ := u2Carrier(t)
	retiring := &client{access: semaphore.New(1), instance: new(core.Instance)}
	kBusy, kReady, kRetiring := dialerConf{instance: busy.instance}, dialerConf{}, dialerConf{instance: retiring.instance}
	m := &clientManager{m: map[dialerConf]*client{kBusy: busy, kReady: ready, kRetiring: retiring}}
	for range 100 {
		m.cleanOnce()
	}
	u2Wait(t, func() bool { return u2Removed(m, kRetiring) })
	mapDone := make(chan struct{})
	go func() {
		m.Lock()
		m.m[dialerConf{instance: new(core.Instance)}] = &client{access: semaphore.New(1)}
		m.Unlock()
		close(mapDone)
	}()
	select {
	case <-mapDone:
	case <-time.After(time.Second):
		t.Fatal("busy client held manager membership")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	child, err := ready.udp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = child.Close()
	if u2Removed(m, kBusy) {
		t.Fatal("busy, unmarked client removed")
	}
}

type u2BlockedPacketClose struct {
	net.PacketConn
	entered, release chan struct{}
	once             sync.Once
}

func (p *u2BlockedPacketClose) Close() error {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.PacketConn.Close()
}

func TestU2ManagerBlockedCloseProgress(t *testing.T) {
	c, _ := u2Carrier(t)
	c.instance = new(core.Instance)
	p := &u2BlockedPacketClose{PacketConn: c.pktConn, entered: make(chan struct{}), release: make(chan struct{})}
	c.pktConn = p
	released := false
	defer func() {
		if !released {
			close(p.release)
		}
	}()
	other := &client{access: semaphore.New(1), instance: new(core.Instance)}
	key, otherKey := dialerConf{instance: c.instance}, dialerConf{instance: other.instance}
	m := &clientManager{m: map[dialerConf]*client{key: c, otherKey: other}}
	m.cleanOnce()
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("forced close did not reach lower socket")
	}
	for range 100 {
		m.cleanOnce()
	}
	u2Wait(t, func() bool { return u2Removed(m, otherKey) })
	if u2Removed(m, key) {
		t.Fatal("removed client before disposal completed")
	}
	close(p.release)
	released = true
	u2Wait(t, func() bool { return u2Removed(m, key) })
	<-c.access.Wait()
	defer c.access.Signal()
	if !c.forced || c.conn != nil || c.tr != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatal("forced cleanup retained resources")
	}
}

func TestU2ManagerExactReplacement(t *testing.T) {
	old := &client{access: semaphore.New(1)}
	replacement := &client{access: semaphore.New(1)}
	key := dialerConf{}
	m := &clientManager{m: map[dialerConf]*client{key: replacement}}
	<-old.access.Wait()
	m.cleanClient(key, old, true)
	if m.m[key] != replacement || !old.forced {
		t.Fatal("stale cleanup removed replacement or failed to mark old client")
	}
	old.clean(true) // Forced null cleanup is repeatable.
	for _, udp := range []bool{false, true} {
		var err error
		if udp {
			_, err = old.udp(context.Background())
		} else {
			_, err = old.tcp(context.Background())
		}
		if err == nil {
			t.Fatal("stale forced client admitted network work")
		}
	}
}

func TestU2ClientResetAndForcedSessions(t *testing.T) {
	c, peer := u2Carrier(t)
	child, err := c.udp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.CloseWithError(0, "reset")
	u2Wait(t, func() bool {
		select {
		case <-c.conn.Context().Done():
			return true
		default:
			return false
		}
	})
	c.clean(false)
	if c.forced || c.conn != nil || c.tr != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatal("ordinary reset became terminal or retained resources")
	}
	_ = child.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := child.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("reset UDP session: %v", err)
	}
	c.clean(true)
	if !c.forced {
		t.Fatal("null client was not marked terminal")
	}
}

func TestU2ManagerOwnerStateAndActiveSessions(t *testing.T) {
	for _, state := range []string{"nil", "running", "stopped"} {
		t.Run(state, func(t *testing.T) {
			c, _ := u2Carrier(t)
			if state != "nil" {
				instance, err := core.New(&core.Config{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = instance.Close() })
				if err := instance.Start(); err != nil {
					t.Fatal(err)
				}
				if state == "stopped" {
					if err := instance.Close(); err != nil {
						t.Fatal(err)
					}
				}
				c.instance = instance
			}
			child, err := c.udp(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			connected := c.conn
			key := dialerConf{instance: c.instance}
			m := &clientManager{m: map[dialerConf]*client{key: c}}
			m.cleanOnce()
			<-c.access.Wait() // Join the admitted cleanup before inspecting fields.
			forced, current := c.forced, c.conn
			c.access.Signal()
			if state != "stopped" {
				if forced || current != connected || u2Removed(m, key) {
					t.Fatal("healthy nil/running owner was retired")
				}
				return
			}
			u2Wait(t, func() bool { return u2Removed(m, key) })
			if !forced || current != nil {
				t.Fatal("stopped owner retained carrier")
			}
			_ = child.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := child.Read(make([]byte, 16)); err != io.EOF {
				t.Fatalf("forced active session: %v", err)
			}
		})
	}
}

func TestU2ClientPreexpiredAdmission(t *testing.T) {
	for _, udp := range []bool{false, true} {
		c := &client{access: semaphore.New(1)}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		for range 100 {
			var err error
			if udp {
				_, err = c.udp(ctx)
			} else {
				_, err = c.tcp(ctx)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("preexpired admission: %v", err)
			}
		}
		select {
		case <-c.access.Wait():
			c.access.Signal()
		default:
			t.Fatal("canceled waiter retained admission token")
		}
	}
}

func TestU2SilentHandshakeTwoAssociations(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	address, err := xnet.ParseDestination("udp:" + pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := &client{access: semaphore.New(1), dest: address, config: &Config{Auth: "fixture"}, tlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, quicParams: &internet.QuicParams{DisableChromeParrot: true, Congestion: "reno"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := c.udp(ctx); first <- err }()
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := pc.ReadFrom(make([]byte, 1500)); err != nil {
		cancel()
		<-first
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer secondCancel()
	if _, err := c.tcp(secondCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second association waited for silent handshake: %v", err)
	}
	select {
	case err := <-first:
		t.Fatalf("first handshake ended before cancel: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("silent provisional handshake survived cancellation")
	}
	if c.conn != nil || c.tr != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatal("canceled handshake published resources")
	}
	c.clean(true)
}
