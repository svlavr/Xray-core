package xdns

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
)

func testDomain() *DomainProto {
	return &DomainProto{Name: "x.example", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}
}

func testServer(t *testing.T, tcpOnly bool) *xdnsServer {
	t.Helper()
	// Select a TCP-eligible ephemeral port first: Windows can reserve ports for
	// TCP that remain available to a UDP :0 allocation.
	var listener net.Listener
	address := "127.0.0.1:0"
	var raw net.PacketConn
	var err error
	if tcpOnly {
		for range 256 {
			listener, err = net.Listen("tcp4", address)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = net.ListenPacket("udp4", listener.Addr().String())
			if err == nil {
				break
			}
			_ = listener.Close()
		}
	} else {
		raw, err = net.ListenPacket("udp4", address)
	}
	if err != nil {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatal(err)
	}
	cfg := &Config{Domains: []*DomainProto{testDomain()}, TcpOnly: tcpOnly}
	pc, err := cfg.WrapPacketConnServer(raw, &net.UDPAddr{}, &finalmask.ListenConfig{Listen: func(addr net.Addr) (net.Listener, error) {
		if addr.String() != raw.LocalAddr().String() {
			t.Errorf("TCP bind %v differs from actual UDP address %v", addr, raw.LocalAddr())
		}
		return listener, nil
	}})
	if err != nil {
		_ = raw.Close()
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatal(err)
	}
	s := pc.(*xdnsServer)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testDialer() *finalmask.Dialer {
	return &finalmask.Dialer{
		DialTCP: func(d xnet.Destination) (xnet.Conn, error) { return net.DialTimeout("tcp", d.NetAddr(), time.Second) },
		DialUDP: func(d xnet.Destination) (xnet.Conn, error) {
			dest, err := net.ResolveUDPAddr("udp4", d.NetAddr())
			if err != nil {
				return nil, err
			}
			pc, err := net.ListenUDP("udp4", nil)
			if err != nil {
				return nil, err
			}
			return &xnet.PacketConnWrapper{PacketConn: pc, Dest: dest}, nil
		},
	}
}

type recursiveForwarder struct {
	target                 string
	udp, tcp, maxWire      atomic.Int32
	payloadUDP, payloadTCP atomic.Int32
	maxBatch               atomic.Int32
	beforeTCP              func()
}

func (f *recursiveForwarder) exchange(q *mdns.Msg) (*mdns.Msg, error) {
	domain, _ := NewDomain("x.example", 255, 63, []uint16{TypeTXT}, 4096)
	name, _ := dnsmessage.NewName(q.Question[0].Name)
	var decoded [255]byte
	n := domain.Decode(&decoded, name)
	upload := n >= 12 && decoded[8]&0x3F == 3
	// A recursive resolver selects its own UDP receive size on the second leg.
	q.Extra = nil
	q.SetEdns0(1232, false)
	f.udp.Add(1)
	if upload {
		f.payloadUDP.Add(1)
	}
	r, _, err := (&mdns.Client{Net: "udp", UDPSize: 4096, Timeout: 2 * time.Second}).Exchange(q, f.target)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		if upload && f.beforeTCP != nil {
			f.beforeTCP()
		}
		f.tcp.Add(1)
		if upload {
			f.payloadTCP.Add(1)
		}
		r, _, err = (&mdns.Client{Net: "tcp", Timeout: 3 * time.Second}).Exchange(q, f.target)
	}
	if err == nil {
		r.Compress = true
		p, e := r.Pack()
		if e != nil {
			return nil, e
		}
		var reply dnsmessage.Message
		if reply.Unpack(p) == nil && len(reply.Answers) == 1 {
			if txt, ok := reply.Answers[0].Body.(*dnsmessage.TXTResource); ok {
				data := []byte(strings.Join(txt.TXT, ""))
				count := 0
				for len(data) >= 2 {
					last := data[0]&0xc0 == 0xc0
					n := int(data[0]&0x3f)<<8 | int(data[1])
					data = data[2:]
					if n > len(data) {
						count = 0
						break
					}
					count++
					data = data[n:]
					if last {
						break
					}
				}
				for old := f.maxBatch.Load(); int32(count) > old; old = f.maxBatch.Load() {
					if f.maxBatch.CompareAndSwap(old, int32(count)) {
						break
					}
				}
			}
		}
		for old := f.maxWire.Load(); int32(len(p)) > old; old = f.maxWire.Load() {
			if f.maxWire.CompareAndSwap(old, int32(len(p))) {
				break
			}
		}
	}
	return r, err
}

func testDoH(t *testing.T, f *recursiveForwarder) *ResolverProto {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, err := io.ReadAll(io.LimitReader(req.Body, 513))
		q := new(mdns.Msg)
		if err != nil || len(p) > 512 || q.Unpack(p) != nil {
			http.Error(w, "query", 400)
			return
		}
		r, err := f.exchange(q)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		p, err = r.Pack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", strconv.Itoa(len(p)))
		_, _ = w.Write(p)
	}))
	t.Cleanup(s.Close)
	return &ResolverProto{Type: "https", Addr: s.URL, Worker: 32, TlsConfig: &xtls.Config{
		DisableSystemRoot: true, ServerName: "example.com", NextProtocol: []string{"http/1.1"},
		Certificate: []*xtls.Certificate{{Usage: xtls.Certificate_AUTHORITY_VERIFY, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}},
	}}
}

func testTCPFrontend(t *testing.T, f *recursiveForwarder) *ResolverProto {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mdns.Server{Listener: l, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		r, err := f.exchange(q)
		if err == nil {
			_ = w.WriteMsg(r)
		}
	})}
	go s.ActivateAndServe()
	t.Cleanup(func() { _ = s.Shutdown(); _ = l.Close() })
	return &ResolverProto{Type: "tcp", Addr: l.Addr().String()}
}

func testClient(t *testing.T, rc *ResolverProto) *xdnsClient {
	t.Helper()
	pc, err := NewClient(&Config{Domains: []*DomainProto{testDomain()}, Resolvers: []*ResolverProto{rc}}, testDialer())
	if err != nil {
		t.Fatal(err)
	}
	c := pc.(*xdnsClient)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func testRead(t *testing.T, pc net.PacketConn, want []byte) {
	t.Helper()
	type result struct {
		p   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() { p := make([]byte, 4096); n, _, err := pc.ReadFrom(p); ch <- result{p[:n], err} }()
	select {
	case r := <-ch:
		if r.err != nil || !bytes.Equal(r.p, want) {
			t.Fatalf("packet mismatch: bytes=%d want=%d err=%v", len(r.p), len(want), r.err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("packet timeout")
	}
}

func TestServerLargeDNSResponse(t *testing.T) {
	for _, protocol := range []string{"tcp", "https"} {
		for _, packetSize := range []int{24, 4000} {
			t.Run(fmt.Sprintf("%s/%d", protocol, packetSize), func(t *testing.T) {
				s := testServer(t, true)
				f := &recursiveForwarder{target: s.LocalAddr().String()}
				var rc *ResolverProto
				if protocol == "https" {
					rc = testDoH(t, f)
				} else {
					rc = testTCPFrontend(t, f)
				}
				c := testClient(t, rc)
				var wants [][]byte
				for i := range 16 {
					p := bytes.Repeat([]byte{byte(i + 1)}, packetSize)
					wants = append(wants, p)
					if _, err := s.WriteTo(p, c.clientID.Addr()); err != nil {
						t.Fatal(err)
					}
				}
				var uploaded atomic.Int32
				uploads := make(chan []byte, 2)
				done := make(chan struct{})
				go func() {
					defer close(done)
					p := make([]byte, 4096)
					for {
						n, _, err := s.ReadFrom(p)
						if err != nil {
							return
						}
						uploaded.Add(1)
						select {
						case uploads <- append([]byte(nil), p[:n]...):
						default:
						}
					}
				}()
				t.Cleanup(func() { _ = s.Close(); <-done })
				var earlyUpload atomic.Bool
				f.beforeTCP = func() {
					if uploaded.Load() != 0 {
						earlyUpload.Store(true)
					}
				}
				upload := []byte("deliver-once")
				if _, err := c.WriteTo(upload, nil); err != nil {
					t.Fatal(err)
				}
				for _, want := range wants {
					testRead(t, c, want)
				}
				select {
				case got := <-uploads:
					if !bytes.Equal(got, upload) {
						t.Fatal("upload changed")
					}
				case <-time.After(time.Second):
					t.Fatal("upload absent")
				}
				if earlyUpload.Load() {
					t.Fatal("UDP TC consumed upload before TCP retry")
				}
				if f.payloadUDP.Load() != 1 || f.payloadTCP.Load() != 1 {
					t.Fatalf("expected one payload query with TCP retry; UDP=%d TCP=%d", f.payloadUDP.Load(), f.payloadTCP.Load())
				}
				if (packetSize == 4000 && f.maxWire.Load() <= 64000) || f.maxWire.Load() > maxDNSMessageSize {
					t.Fatalf("wire size %d", f.maxWire.Load())
				}
				if f.maxBatch.Load() != 16 {
					t.Fatalf("maximum batch %d want16", f.maxBatch.Load())
				}
				// Give an erroneously repeated upload time to reach the application reader.
				time.Sleep(20 * time.Millisecond)
				if uploaded.Load() != 1 {
					t.Fatalf("upload delivered %d times", uploaded.Load())
				}
				t.Logf("%d bytes in16 exact%d-byte packets; one%d-byte DNS response; UDP1232 TC -> nativeTCP -> %s", 16*packetSize, packetSize, f.maxWire.Load(), protocol)
			})
		}
	}
}

func TestServerUDPDefaultAndTCPFragments(t *testing.T) {
	for _, mode := range []string{"udp", "tcp", "https"} {
		sizes := []int{32, 3000}
		if mode != "udp" {
			sizes = append(sizes, 4096)
		}
		for _, size := range sizes {
			t.Run(fmt.Sprintf("%s-%d", mode, size), func(t *testing.T) {
				s := testServer(t, mode != "udp")
				rc := &ResolverProto{Type: mode, Addr: s.LocalAddr().String()}
				if mode == "https" {
					rc = testDoH(t, &recursiveForwarder{target: s.LocalAddr().String()})
				}
				c := testClient(t, rc)
				want := bytes.Repeat([]byte{0x63}, size)
				done := make(chan struct{})
				go func() {
					defer close(done)
					p := make([]byte, 4096)
					n, addr, err := s.ReadFrom(p)
					if err == nil {
						_, _ = s.WriteTo(p[:n], addr)
					}
				}()
				t.Cleanup(func() { _ = s.Close(); <-done })
				if _, err := c.WriteTo(want, nil); err != nil {
					t.Fatal(err)
				}
				testRead(t, c, want)
			})
		}
	}
}

func TestServerTCPConfigurationAndClose(t *testing.T) {
	for _, mode := range []bool{false, true} {
		t.Run(strconv.FormatBool(mode), func(t *testing.T) {
			s := testServer(t, mode)
			if !mode {
				if s.listener != nil {
					t.Fatal("default UDP opened TCP listener")
				}
				return
			}
			conn, err := net.Dial("tcp", s.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, _ = conn.Write([]byte{0}) // partial length prefix: Close must interrupt read.
			deadline := time.Now().Add(time.Second)
			for {
				s.mu.Lock()
				n := len(s.conns)
				s.mu.Unlock()
				if n == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("TCP connection was not admitted before Close")
				}
				time.Sleep(time.Millisecond)
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() { defer wg.Done(); _ = s.Close() }()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Close did not join TCP workers")
			}
			s.mu.Lock()
			n := len(s.conns)
			s.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d TCP connections retained", n)
			}
		})
	}
	for _, wrap := range []bool{false, true} {
		raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cfg := &Config{Domains: []*DomainProto{testDomain()}, TcpOnly: true}
		if wrap {
			_, err = cfg.WrapPacketConnServer(raw, raw.LocalAddr(), nil)
		} else {
			_, err = NewServer(cfg, raw)
		}
		_ = raw.Close()
		if err == nil {
			t.Fatal("tcpOnly accepted without listener provider")
		}
	}
}

func TestServerTCDoesNotConsumePayload(t *testing.T) {
	s := testServer(t, true)
	id := NewClientID()
	want := bytes.Repeat([]byte{0x5e}, 3000)
	if _, err := s.WriteTo(want, id.Addr()); err != nil {
		t.Fatal(err)
	}
	domain := s.domains[0]
	data := make([]byte, 13)
	copy(data, id[:])
	data[0] |= TypeMap[TypeTXT]
	data[8] = 3
	data[12] = 0x7a
	q := new(mdns.Msg)
	q.SetQuestion(domain.Encode(data).String(), mdns.TypeTXT)
	q.SetEdns0(1232, false)
	r, _, err := (&mdns.Client{Net: "udp", Timeout: time.Second}).Exchange(q, s.LocalAddr().String())
	if err != nil || !r.Truncated {
		t.Fatalf("UDP TC: %v %v", r, err)
	}
	select {
	case <-s.readCh:
		t.Fatal("UDP query delivered upload")
	default:
	}
	ch, _ := s.sendManager.Pop(id)
	select {
	case got := <-ch:
		if !bytes.Equal(got, want) {
			t.Fatal("queue changed")
		}
	default:
		t.Fatal("UDP TC consumed queued reply")
	}
}

func TestServerTCPReplyFraming(t *testing.T) {
	s := testServer(t, true)
	c, err := net.Dial("tcp", s.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := new(mdns.Msg)
	q.SetQuestion("outside.example.", mdns.TypeTXT)
	p, _ := q.Pack()
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(p)))
	_, _ = c.Write(prefix[:1])
	_, _ = c.Write(append(prefix[1:], p...))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
	if _, err := io.ReadFull(c, response); err != nil {
		t.Fatal(err)
	}
	r := new(mdns.Msg)
	if err := r.Unpack(response); err != nil || !r.Response || r.Id != q.Id {
		t.Fatalf("framed response: %v %v", r, err)
	}
}
