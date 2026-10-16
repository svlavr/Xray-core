package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
	"github.com/apernet/quic-go/qlogwriter"
	mdns "github.com/miekg/dns"
)

type quicACKTrace struct{ ackFrames atomic.Int32 }

func (t *quicACKTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *quicACKTrace) SupportsSchemas(string) bool      { return true }
func (t *quicACKTrace) Close() error                     { return nil }
func (t *quicACKTrace) RecordEvent(event qlogwriter.Event) {
	if packet, ok := event.(qlog.PacketSent); ok {
		for _, frame := range packet.Frames {
			if _, ok := frame.Frame.(*qlog.AckFrame); ok {
				t.ackFrames.Add(1)
			}
		}
	}
}

// TCP recursive DNS must allow outstanding fragment queries on one connection;
// serial request/response forwarding would add a response wait per fragment.
func testPipelinedTCPFrontend(t *testing.T, f *recursiveForwarder) *ResolverProto {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})
	closed := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			select {
			case <-closed:
				mu.Unlock()
				c.Close()
				return
			default:
			}
			conns[c] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(conns, c); mu.Unlock() }()
				var writes sync.Mutex
				inflight := make(chan struct{}, 32)
				for {
					var prefix [2]byte
					if _, err := io.ReadFull(c, prefix[:]); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(prefix[:]))
					if n == 0 || n > 512 {
						return
					}
					p := make([]byte, n)
					if _, err := io.ReadFull(c, p); err != nil {
						return
					}
					q := new(mdns.Msg)
					if q.Unpack(p) != nil {
						return
					}
					select {
					case inflight <- struct{}{}:
					case <-closed:
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func() { <-inflight }()
						r, err := f.exchange(q)
						if err != nil {
							return
						}
						wire, err := r.Pack()
						if err != nil {
							return
						}
						var prefix [2]byte
						binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
						writes.Lock()
						defer writes.Unlock()
						_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
						buffers := net.Buffers{prefix[:], wire}
						_, _ = buffers.WriteTo(c)
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		close(closed)
		l.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return &ResolverProto{Type: "tcp", Addr: l.Addr().String()}
}

func TestQUICDirectOverXDNS(t *testing.T) {
	for _, protocol := range []string{"tcp", "https"} {
		t.Run(protocol, func(t *testing.T) {
			s := testServer(t, true)
			f := &recursiveForwarder{target: s.LocalAddr().String()}
			var rc *ResolverProto
			if protocol == "tcp" {
				rc = testPipelinedTCPFrontend(t, f)
			} else {
				rc = testDoH(t, f)
			}
			c := testClient(t, rc)
			certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(certificate.Close)
			roots := x509.NewCertPool()
			roots.AddCert(certificate.Certificate())
			serverTLS := &tls.Config{Certificates: certificate.TLS.Certificates, NextProtos: []string{"xdns-quic-test"}}
			clientTLS := &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"xdns-quic-test"}}
			config := &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, DisablePathMTUDiscovery: true, DisablePathManager: true, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 15 * time.Second}
			trace := new(quicACKTrace)
			config.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }
			serverTransport := &quic.Transport{Conn: s, DisableGSO: true}
			clientTransport := &quic.Transport{Conn: c, DisableGSO: true}
			var listener *quic.Listener
			var client, server *quic.Conn
			t.Cleanup(func() {
				if client != nil {
					_ = client.CloseWithError(0, "")
				}
				if server != nil {
					_ = server.CloseWithError(0, "")
				}
				if listener != nil {
					_ = listener.Close()
				}
				// Both packet connections are caller-owned and lack read deadlines.
				_ = c.Close()
				_ = s.Close()
				_ = clientTransport.Close()
				_ = serverTransport.Close()
			})
			var err error
			listener, err = serverTransport.Listen(serverTLS, config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, err = clientTransport.Dial(ctx, s.LocalAddr(), clientTLS, config)
			if err != nil {
				t.Fatalf("direct QUIC handshake: %v; UDP=%d TCP=%d", err, f.udp.Load(), f.tcp.Load())
			}
			server, err = listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if state := client.ConnectionState().TLS; len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != "xdns-quic-test" {
				t.Fatal("TLS verification or ALPN missing")
			}
			payload := bytes.Repeat([]byte("direct-quic-over-xdns;"), 512)
			reply := append([]byte("reply:"), payload...)
			echo := make(chan error, 1)
			go func() {
				stream, err := server.AcceptStream(ctx)
				if err != nil {
					echo <- err
					return
				}
				_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
				got, err := io.ReadAll(stream)
				if err == nil && !bytes.Equal(got, payload) {
					err = fmt.Errorf("stream upload mismatch: %d", len(got))
				}
				if err == nil {
					_, err = stream.Write(reply)
				}
				if err == nil {
					err = stream.Close()
				}
				echo <- err
			}()
			stream, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err = stream.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err = stream.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(stream)
			if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("stream reply: %d %v", len(got), err)
			}
			if err = <-echo; err != nil {
				t.Fatal(err)
			}
			for _, direction := range []struct {
				from, to *quic.Conn
				value    byte
			}{{client, server, 0x36}, {server, client, 0x59}} {
				want := bytes.Repeat([]byte{direction.value}, 1024)
				if err := direction.from.SendDatagram(want); err != nil {
					t.Fatal(err)
				}
				got, err := direction.to.ReceiveDatagram(ctx)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("datagram: bytes%d err%v", len(got), err)
				}
			}
			if f.payloadUDP.Load() == 0 || f.payloadTCP.Load() == 0 {
				t.Fatal("recursive fallback was not exercised")
			}
			if trace.ackFrames.Load() == 0 {
				t.Fatal("no actual QUIC ACK frames observed")
			}
			t.Logf("direct QUIC: verifiedTLS, %d-byte request and%d-byte reply,1024-byte datagrams bothways; UDP=%d TCP=%d maxDNS=%d maxBatch=%d ACKframes=%d", len(payload), len(reply), f.udp.Load(), f.tcp.Load(), f.maxWire.Load(), f.maxBatch.Load(), trace.ackFrames.Load())
		})
	}
}
