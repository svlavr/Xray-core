package xdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDOHResolverMessageSize(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, size := range []int{4095, 4096, 64000} {
			t.Run(fmt.Sprintf("chunked=%t/size=%d", chunked, size), func(t *testing.T) {
				body := bytes.Repeat([]byte{0x5a}, size)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					_, _ = io.Copy(io.Discard, req.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					if chunked {
						w.(http.Flusher).Flush()
					} else {
						w.Header().Set("Content-Length", strconv.Itoa(size))
					}
					_, _ = w.Write(body)
				}))
				defer server.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				r := &DOHResolver{
					ctx: ctx, client: server.Client(), url: server.URL,
					readCh: make(chan []byte, 1), closeCh: make(chan struct{}),
				}
				defer r.client.CloseIdleConnections()
				err := r.do([]byte{1, 2})
				if err != nil {
					t.Fatal(err)
				}
				if len(r.readCh) != 1 {
					t.Fatal("message was not delivered")
				}
				buf := make([]byte, maxDNSMessageSize)
				n, err := r.Read(buf)
				if err != nil || !bytes.Equal(buf[:n], body) {
					t.Fatalf("Read = %d, %v; want %d matching bytes", n, err, size)
				}
			})
		}
	}
}

type eofResolverBody struct {
	*bytes.Reader
	eofWithLastRead bool
}

func (b eofResolverBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if b.eofWithLastRead && b.Reader.Len() == 0 {
		err = io.EOF
	}
	return n, err
}
func (b eofResolverBody) Close() error { return nil }

func TestDOHResolverPreservesEOFPolicy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		size           int
		eof, delivered bool
	}{
		{"complete-at-limit", maxDNSMessageSize, true, true},
		{"full-without-EOF", maxDNSMessageSize, false, false},
		{"exceeds-limit", maxDNSMessageSize + 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &DOHResolver{
				ctx: context.Background(), url: "https://resolver.example/dns-query",
				client: &http.Client{Transport: resolverRoundTripper(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: eofResolverBody{bytes.NewReader(make([]byte, tc.size)), tc.eof}}, nil
				})}, readCh: make(chan []byte, 1), closeCh: make(chan struct{}),
			}
			if err := r.do(nil); err != nil {
				t.Fatal(err)
			}
			if got := len(r.readCh) > 0; got != tc.delivered {
				t.Fatalf("delivered=%v want%v", got, tc.delivered)
			}
			if tc.delivered {
				packet := <-r.readCh
				poolDNSMessage.Put(packet[:cap(packet)])
			}
		})
	}
}

type resolverRoundTripper func(*http.Request) (*http.Response, error)

func (f resolverRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingResolverBody struct{ err error }

func (b failingResolverBody) Read(p []byte) (int, error) { return copy(p, "partial"), b.err }
func (failingResolverBody) Close() error                 { return nil }

func TestDOHResolverBodyError(t *testing.T) {
	for _, want := range []error{io.ErrClosedPipe, io.ErrUnexpectedEOF} {
		t.Run(want.Error(), func(t *testing.T) {
			r := &DOHResolver{
				ctx: context.Background(), url: "https://resolver.example/dns-query",
				client: &http.Client{Transport: resolverRoundTripper(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: failingResolverBody{want}}, nil
				})},
				readCh: make(chan []byte, 1), closeCh: make(chan struct{}),
			}
			if err := r.do(nil); !errors.Is(err, want) {
				t.Fatalf("body error = %v", err)
			}
			if len(r.readCh) != 0 {
				t.Fatal("partial message was delivered after a body error")
			}
		})
	}
}

func TestClientRejectsOversizeApplicationDatagram(t *testing.T) {
	domain, err := NewDomain("example.com", 255, 63, []uint16{TypeTXT}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example.com."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	aggregate := append([]byte{0xd0, 1}, make([]byte, 4097)...)
	wire := NewResp(msg, domain, 0).Encode(nil, aggregate)
	c := &xdnsClient{domains: []*Domain{domain}, readCh: make(chan packet, 1), closeCh: make(chan struct{})}
	if c.read(wire, &net.UDPAddr{}) || len(c.readCh) != 0 {
		t.Fatal("oversized application packet was delivered")
	}
}

func TestTCPResolverReceiveFrames(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	r := &TCPResolver{conn: conn, readCh: make(chan []byte), closeCh: make(chan struct{})}
	r.wg.Add(1)
	go r.recv(conn)
	defer r.Close()

	sizes := []int{4095, 4096, maxDNSMessageSize}
	written := make(chan error, 1)
	go func() {
		// A zero-length frame must not consume bytes from the next frame.
		if _, err := peer.Write([]byte{0, 0}); err != nil {
			written <- err
			return
		}
		for _, size := range sizes {
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], uint16(size))
			for _, b := range prefix {
				if _, err := peer.Write([]byte{b}); err != nil {
					written <- err
					return
				}
			}
			if _, err := peer.Write(bytes.Repeat([]byte{byte(size)}, size)); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	for _, size := range sizes {
		select {
		case packet := <-r.readCh:
			if !bytes.Equal(packet, bytes.Repeat([]byte{byte(size)}, size)) {
				t.Errorf("frame size = %d, want %d matching bytes", len(packet), size)
			}
			poolDNSMessage.Put(packet[:cap(packet)])
		case <-time.After(5 * time.Second):
			t.Fatal("timed out receiving frame")
		}
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestTCPResolverSendFrames(t *testing.T) {
	for _, size := range []int{4095, 4096, maxDNSMessageSize} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
			r := &TCPResolver{conn: conn, closeCh: make(chan struct{})}
			body := bytes.Repeat([]byte{0x5a}, size)
			sent := make(chan struct{})
			go func() { r.Send(body); close(sent) }()
			var prefix [2]byte
			if _, err := io.ReadFull(peer, prefix[:]); err != nil {
				t.Fatal(err)
			}
			if n := int(binary.BigEndian.Uint16(prefix[:])); n != size {
				t.Fatalf("prefix = %d, want %d", n, size)
			}
			buf := make([]byte, size)
			if _, err := io.ReadFull(peer, buf); err != nil || !bytes.Equal(buf, body) {
				t.Fatalf("body read error = %v, matches = %t", err, bytes.Equal(buf, body))
			}
			<-sent
		})
	}
}

type shortResolverConn struct {
	net.Conn
	writes int
	short  int
	closed bool
}

func (c *shortResolverConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func (c *shortResolverConn) Close() error { c.closed = true; return nil }

func TestTCPResolverShortWrite(t *testing.T) {
	for _, short := range []int{1, 2} {
		conn := &shortResolverConn{short: short}
		r := &TCPResolver{conn: conn, closeCh: make(chan struct{})}
		r.Send([]byte{1, 2, 3})
		if !conn.closed || conn.writes != short {
			t.Fatalf("short write %d: closed=%t writes=%d", short, conn.closed, conn.writes)
		}
	}
}

func TestTCPResolverRejectOversizeQuery(t *testing.T) {
	conn := &shortResolverConn{}
	r := &TCPResolver{conn: conn, closeCh: make(chan struct{})}
	r.Send(make([]byte, maxDNSMessageSize+1))
	if conn.writes != 0 {
		t.Fatal("oversize query was written")
	}
}

func TestClientReadLargeAggregate(t *testing.T) {
	domain, err := NewDomain("example.com", 200, 63, []uint16{TypeTXT}, 0)
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example.com."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	var aggregate []byte
	for i := range 15 {
		// Individual application datagrams remain at their existing 4096-byte limit.
		prefix := []byte{0x10, 0}
		if i == 14 {
			prefix[0] |= 0xc0
		}
		aggregate = append(aggregate, prefix...)
		aggregate = append(aggregate, bytes.Repeat([]byte{byte(i)}, 4096)...)
	}
	wire := NewResp(msg, domain, 0).Encode(nil, aggregate)
	if len(wire) <= 4096 || len(wire) > maxDNSMessageSize {
		t.Fatalf("unexpected wire size %d", len(wire))
	}
	c := &xdnsClient{domains: []*Domain{domain}, readCh: make(chan packet, 15), closeCh: make(chan struct{})}
	if !c.read(wire, &net.UDPAddr{}) {
		t.Fatal("large aggregate was rejected")
	}
	if len(c.readCh) != 15 {
		t.Fatalf("delivered %d datagrams, want 15", len(c.readCh))
	}
	for i := range 15 {
		packet := <-c.readCh
		if !bytes.Equal(packet.p, bytes.Repeat([]byte{byte(i)}, 4096)) {
			t.Fatalf("datagram %d differs", i)
		}
	}
}
