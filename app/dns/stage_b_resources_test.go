package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	featuredns "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/http2"
)

func TestStageBTCPWithheldReplyCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			endpoint, _ := url.Parse("tcp+local://127.0.0.1:53")
			server, err := NewTCPLocalNameServer(endpoint, true, false, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			server.dial = func(context.Context) (net.Conn, error) { return client, nil }
			started, peerDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(peerDone)
				var size uint16
				if binary.Read(peer, binary.BigEndian, &size) != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, peer, int64(size)); err != nil {
					return
				}
				close(started)
				_, _ = io.Copy(io.Discard, peer)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			}
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, _, err := server.QueryIP(ctx, "withheld.test", featuredns.IPOption{IPv4Enable: true})
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("query did not reach withholding server")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("withheld query unexpectedly succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("query did not return on cancellation")
			}
			joined := make(chan struct{})
			go func() { server.workers.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("TCP request worker survived cancellation")
			}
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Fatal("TCP connection remained open")
			}
		})
	}
}

func TestStageBQUICWithheldReplyCancellationKeepsSibling(t *testing.T) {
	certificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := certificate.ToPEM()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{NextProtoDQ}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverCtx, stopServer := context.WithCancel(context.Background())
	t.Cleanup(stopServer)
	held, streamCanceled, served := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.Accept(serverCtx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "test complete")
		var streams sync.WaitGroup
		defer streams.Wait()
		for {
			stream, err := conn.AcceptStream(serverCtx)
			if err != nil {
				return
			}
			streams.Add(1)
			go func() {
				defer streams.Done()
				defer stream.CancelRead(0)
				defer stream.Close()
				payload, err := io.ReadAll(stream)
				query := new(mdns.Msg)
				if err != nil || len(payload) < 2 || query.Unpack(payload[2:]) != nil || len(query.Question) != 1 {
					return
				}
				if query.Question[0].Name == "hold.test." {
					close(held)
					select {
					case <-stream.Context().Done():
						close(streamCanceled)
					case <-serverCtx.Done():
					}
					return
				}
				answer := new(mdns.Msg)
				answer.SetReply(query)
				answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: query.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 18)}}
				wire, err := answer.Pack()
				if err == nil {
					_ = binary.Write(stream, binary.BigEndian, uint16(len(wire)))
					_, _ = stream.Write(wire)
				}
			}()
		}
	}()
	clientCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	// Inject a real loopback test connection so production trust settings
	// remain unchanged; the query path still uses native QUIC streams and I/O.
	client, err := quic.DialAddr(clientCtx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoDQ}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "test complete"); stopServer(); <-served })
	endpoint, _ := url.Parse("quic+local://" + listener.Addr().String())
	server, err := NewQUICNameServer(endpoint, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.connection = client
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		_, _, err := server.QueryIP(ctx, "hold.test", featuredns.IPOption{IPv4Enable: true})
		result <- err
	}()
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("DoQ query did not reach withholding server")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("withheld DoQ query unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DoQ query did not return on cancellation")
	}
	joined := make(chan struct{})
	go func() { server.workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("DoQ request worker survived cancellation")
	}
	select {
	case <-streamCanceled:
	case <-time.After(time.Second):
		t.Fatal("DoQ stream remained open")
	}
	siblingCtx, cancelSibling := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelSibling()
	ips, _, err := server.QueryIP(siblingCtx, "sibling.test", featuredns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(192, 0, 2, 18)) || server.connection != client {
		t.Fatalf("DoQ sibling did not survive on the same connection: ips=%v err=%v", ips, err)
	}
}

func TestStageBDoHPooledSiblingCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held, canceled := make(chan struct{}), make(chan struct{})
	shutdown := make(chan struct{})
	var accepts atomic.Int32
	var mu sync.Mutex
	var connections []net.Conn
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				new(http2.Server).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					payload, err := io.ReadAll(r.Body)
					if err != nil {
						return
					}
					query := new(mdns.Msg)
					if query.Unpack(payload) != nil || len(query.Question) != 1 {
						return
					}
					if query.Question[0].Name == "hold.test." {
						close(held)
						select {
						case <-r.Context().Done():
							close(canceled)
						case <-shutdown:
						}
						return
					}
					answer := new(mdns.Msg)
					answer.SetReply(query)
					answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: query.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 17)}}
					wire, err := answer.Pack()
					if err == nil {
						w.Header().Set("Content-Type", "application/dns-message")
						_, _ = w.Write(wire)
					}
				})})
			}()
		}
	}()
	t.Cleanup(func() {
		close(shutdown)
		_ = listener.Close()
		<-acceptDone
		mu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	endpoint, err := url.Parse("h2c+local://" + listener.Addr().String() + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	server := NewDoHNameServer(endpoint, nil, true, true, false, 0, nil)
	t.Cleanup(func() { _ = server.Close() })
	lookup := func(name string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, _, err := server.QueryIP(ctx, name, featuredns.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(192, 0, 2, 17)) {
			t.Fatalf("%s: ips=%v err=%v", name, ips, err)
		}
	}
	lookup("warm.test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		_, _, err := server.QueryIP(ctx, "hold.test", featuredns.IPOption{IPv4Enable: true})
		result <- err
	}()
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("held request did not reach HTTP/2 server")
	}
	lookup("sibling.test")
	cancel()
	select {
	case err := <-result:
		// Preserve the native cache/merge error classification. The server-side
		// stream cancellation below establishes the actual cancellation effect.
		if err == nil || ctx.Err() != context.Canceled {
			t.Fatalf("canceled query: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled query did not return")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/2 stream was not canceled")
	}
	lookup("after.test")
	if got := accepts.Load(); got != 1 {
		t.Fatalf("sibling pool was replaced: accepted connections=%d", got)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	remaining := len(server.connections)
	server.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("whole nameserver close retained %d connections", remaining)
	}
}
