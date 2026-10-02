package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/semaphore"
	"github.com/xtls/xray-core/transport/internet"
)

func TestMeasurementUDPWriteClose(t *testing.T) {
	m := &udpSessionManager{m: make(map[uint32]*InterConn)}
	c := &InterConn{id: 1, ch: make(chan []byte), write: func([]byte) error { return nil }}
	c.close = func() { m.Lock(); m.close(c); m.Unlock() }
	m.m[c.id] = c
	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		for range 10000 {
			_, _ = c.Write(make([]byte, 24))
		}
	}()
	<-started
	_ = c.Close()
	wg.Wait()
	if n, err := c.Write(make([]byte, 24)); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after close: %d, %v", n, err)
	}
}

func TestMeasurementUDPBlockedWriteClose(t *testing.T) {
	m := &udpSessionManager{m: make(map[uint32]*InterConn)}
	writing, release := make(chan struct{}), make(chan struct{})
	c := &InterConn{id: 1, ch: make(chan []byte), write: func([]byte) error { close(writing); <-release; return nil }}
	c.close = func() { m.Lock(); m.close(c); m.Unlock() }
	m.m[c.id] = c
	sibling := &InterConn{id: 2, ch: make(chan []byte), write: func([]byte) error { return nil }}
	m.m[sibling.id] = sibling
	writeDone := make(chan struct{})
	go func() { _, _ = c.Write(make([]byte, 24)); close(writeDone) }()
	<-writing
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		close(release)
		<-writeDone
		<-closed
		t.Fatal("Close waited for a blocked native send")
	}
	close(release)
	<-writeDone
	if n, err := sibling.Write(make([]byte, 24)); n != 24 || err != nil {
		t.Fatalf("closing one session broke its sibling: %d, %v", n, err)
	}
}

func TestMeasurementUDPManagerCleanupClose(t *testing.T) {
	m := &udpSessionManager{m: make(map[uint32]*InterConn)}
	done := make(chan struct{})
	go func() { m.clean(); close(done) }()
	m.Lock()
	m.closed = true
	m.Unlock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("closed manager cleanup did not exit")
	}
}

// The real HTTP/3 peer accepts QUIC and the auth request, then withholds a
// response. Cancellation must retire that provisional carrier and release the
// pooled-client owner so a fresh sibling can authenticate successfully.
func TestMeasurementColdAuthCancellation(t *testing.T) {
	certificate, _ := cert.MustGenerate(nil)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: common.Must2(x509.ParsePKCS8PrivateKey(certificate.PrivateKey))}}, NextProtos: []string{"h3"}}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authStarted := make(chan struct{})
	firstClosed := make(chan struct{})
	var mu sync.Mutex
	var connections []*quic.Conn
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			first := len(connections) == 1
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if first {
						close(authStarted)
						<-r.Context().Done()
						return
					}
					w.WriteHeader(StatusAuthOK)
				})}
				_ = server.ServeQUICConn(conn)
				if first {
					close(firstClosed)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-acceptDone
		mu.Lock()
		for _, conn := range connections {
			_ = conn.CloseWithError(0, "")
		}
		mu.Unlock()
		wg.Wait()
	})
	address, _ := xnet.ParseDestination("udp:" + listener.Addr().String())
	c := &client{dest: address, config: &Config{Auth: "fixture"}, tlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, quicParams: &internet.QuicParams{DisableChromeParrot: true, Congestion: "reno"}}
	// Initialized here in the same way as the production pooled-client owner.
	c.access = semaphore.New(1)
	callCtx, stop := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		conn, err := c.udp(callCtx)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case <-authStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("auth request did not reach fixture")
	}
	stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled auth: %v", err)
		}
	case <-time.After(time.Second):
		// Unblock the original native bug without leaving the test goroutine alive.
		mu.Lock()
		_ = connections[0].CloseWithError(0, "fixture cleanup")
		mu.Unlock()
		<-result
		t.Fatal("canceled cold auth kept waiting for peer")
	}
	select {
	case <-firstClosed:
	case <-time.After(time.Second):
		t.Fatal("provisional carrier survived canceled auth")
	}
	siblingCtx, stopSibling := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopSibling()
	sibling, err := c.udp(siblingCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	defer c.close()
}

func TestMeasurementCanceledClientWaiter(t *testing.T) {
	c := &client{access: semaphore.New(1)}
	<-c.access.Wait() // Another cold opener still owns the pooled client.
	defer c.access.Signal()
	for _, udp := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			var err error
			if udp {
				_, err = c.udp(ctx)
			} else {
				_, err = c.tcp(ctx)
			}
			done <- err
		}()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled sibling waited for the cold opener")
		}
	}
}
