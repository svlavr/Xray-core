package measurement_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/measurement"
)

func auditRawTLS(t *testing.T, raw string, abrupt bool) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		if _, e = conn.Write([]byte(raw)); e != nil {
			t.Error(e)
		}
		if abrupt {
			if c, ok := conn.(*tls.Conn); ok {
				c.NetConn().Close()
			} else {
				t.Error("TLS fixture did not expose concrete TLS connection")
				conn.Close()
			}
		} else {
			conn.Close()
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestAuditDownloadFinalReadErrorRetainsCapFact(t *testing.T) {
	for _, digest := range []bool{false, true} {
		t.Run(fmt.Sprint(digest), func(t *testing.T) {
			s := auditRawTLS(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\naXX", false)
			e := executor(t, instance(t))
			q := request(s, measurement.Direct)
			q.MaxBodyBytes = 1
			d := measurement.DownloadRequest{HTTPS: q, TransferTimeout: time.Second}
			sum := sha256.Sum256([]byte("a"))
			if digest {
				d.ExpectedSHA256 = &sum
			}
			r, err := e.Download(context.Background(), d)
			t.Logf("payload=%d cap=%t complete=%t verified=%t error=%v", r.PayloadBytes, r.ByteLimitReached, r.HTTPS.BodyComplete, r.IntegrityVerified, err)
			if err == nil || !strings.Contains(err.Error(), "malformed chunked encoding") {
				t.Fatalf("fixture did not produce simultaneous positive read and framing failure: %+v %v", r, err)
			}
			if r.PayloadBytes != 1 || r.HTTPS.BodyComplete || r.IntegrityVerified {
				t.Fatalf("partial wire facts lost: %+v", r)
			}
			if digest && (r.SHA256 == nil || *r.SHA256 != sum) {
				t.Fatal("consumed-prefix digest lost")
			}
			if !r.ByteLimitReached {
				t.Error("consumed bytes reached the caller cap, but raw limit fact is false")
			}
		})
	}
}

func TestAuditHTTPFramingAndClosureFacts(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		abrupt    bool
	}{{"close_notify", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nprefix", false}, {"bare_TCP_close", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nprefix", true}, {"fixed_complete", "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nprefix", false}, {"fixed_short", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nprefix", false}, {"chunk_complete", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nprefix\r\n0\r\n\r\n", false}, {"chunk_short", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nprefix\r\n", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := auditRawTLS(t, tc.raw, tc.abrupt)
			r, e := executor(t, instance(t)).HTTPS(context.Background(), request(s, measurement.Direct))
			t.Logf("status=%d bytes=%d complete=%t header_CL=%q header_TE=%q error=%v", r.StatusCode, r.BodyBytes, r.BodyComplete, r.Header.Get("Content-Length"), r.Header.Get("Transfer-Encoding"), e)
			if r.StatusCode != 200 || string(r.Body) != "prefix" || r.BodyBytes != 6 {
				t.Fatalf("raw response prefix not preserved: %+v %v", r, e)
			}
			if strings.HasSuffix(tc.name, "short") && (e == nil || r.BodyComplete) {
				t.Fatal("truncation was not visible")
			}
			if !strings.HasSuffix(tc.name, "short") && (e != nil || !r.BodyComplete) {
				t.Fatalf("native reader completion lost: %+v %v", r, e)
			}
		})
	}
}

func auditDNSStream(t *testing.T, dot bool, rcode int, wrongID bool) (netip.AddrPort, *x509.CertPool) {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	var pool *x509.CertPool
	if dot {
		factory := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		pool = x509.NewCertPool()
		pool.AddCert(factory.Certificate())
		cfg := factory.TLS.Clone()
		factory.Close()
		ln = tls.NewListener(ln, cfg)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		var prefix [2]byte
		if _, e = io.ReadFull(c, prefix[:]); e != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, e = io.ReadFull(c, b); e != nil {
			return
		}
		q := new(dns.Msg)
		if e = q.Unpack(b); e != nil {
			t.Error(e)
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Question = nil
		r.Rcode = rcode
		if wrongID {
			r.Id++
		}
		b, e = r.Pack()
		if e != nil {
			t.Error(e)
			return
		}
		binary.BigEndian.PutUint16(prefix[:], uint16(len(b)))
		_, e = c.Write(append(prefix[:], b...))
		if e != nil {
			t.Error(e)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return addr, pool
}

func TestAuditDNSQuestionlessNegativeAnswer(t *testing.T) {
	for _, dot := range []bool{false, true} {
		for _, rcode := range []int{dns.RcodeRefused, dns.RcodeServerFailure} {
			t.Run(fmt.Sprintf("dot=%t/rcode=%d", dot, rcode), func(t *testing.T) {
				addr, pool := auditDNSStream(t, dot, rcode, false)
				transport := measurement.DNSTCP
				if dot {
					transport = measurement.DNSDoT
				}
				r, e := executor(t, instance(t)).DNSQuery(context.Background(), measurement.DNSRequest{Route: measurement.Route{Kind: measurement.Direct}, Transport: transport, Resolver: addr, Name: "fixture.invalid.", Type: dns.TypeA, Timeout: time.Second, MaxResponseBytes: 512, ServerName: "example.com", RootCAs: pool})
				t.Logf("wire=%d complete=%t decoded=%t invalid=%t error=%v", len(r.Wire), r.ResponseComplete, r.Message != nil, errors.Is(e, measurement.ErrDNSResponse), e)
				if len(r.Wire) != 12 || !r.ResponseComplete {
					t.Fatal("fixture was not a complete header-only response")
				}
				if e != nil || r.Message == nil || r.Message.Rcode != rcode {
					t.Error("well-framed matching stream negative answer was lost")
				}
			})
		}
	}
	t.Run("wrong_ID_rejected", func(t *testing.T) {
		addr, _ := auditDNSStream(t, false, dns.RcodeRefused, true)
		r, e := executor(t, instance(t)).DNSQuery(context.Background(), measurement.DNSRequest{Route: measurement.Route{Kind: measurement.Direct}, Transport: measurement.DNSTCP, Resolver: addr, Name: "fixture.invalid.", Type: dns.TypeA, Timeout: time.Second, MaxResponseBytes: 512})
		if !errors.Is(e, measurement.ErrDNSResponse) || r.Message != nil {
			t.Fatal("wrong ID response was admitted")
		}
	})
}

func TestAuditDoHMediaSizeBoundary(t *testing.T) {
	for _, size := range []int{65535, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, e := io.ReadAll(r.Body)
				if e != nil {
					t.Error(e)
					return
				}
				q := new(dns.Msg)
				if e = q.Unpack(b); e != nil {
					t.Error(e)
					return
				}
				reply := new(dns.Msg)
				reply.SetReply(q)
				reply.Rcode = dns.RcodeRefused
				reply.SetEdns0(4096, false)
				b, e = reply.Pack()
				if e != nil {
					t.Error(e)
					return
				}
				reply.IsEdns0().Option = append(reply.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, size-len(b)-4)})
				b, e = reply.Pack()
				if e != nil || len(b) != size {
					t.Errorf("DNS padding fixture: length=%d error=%v", len(b), e)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(b)
			}))
			defer s.Close()
			pool := x509.NewCertPool()
			pool.AddCert(s.Certificate())
			addr := s.Listener.Addr().(*net.TCPAddr).AddrPort()
			r, e := executor(t, instance(t)).DNSQuery(context.Background(), measurement.DNSRequest{Route: measurement.Route{Kind: measurement.Direct}, Transport: measurement.DNSDoH, Resolver: addr, Name: "fixture.invalid.", Type: dns.TypeA, Timeout: time.Second, MaxResponseBytes: 70000, ServerName: "example.com", RootCAs: pool, DoHPath: "/dns-query", MaxHeaderBytes: 4096})
			t.Logf("wire=%d complete=%t decoded=%t status=%d error=%v", len(r.Wire), r.ResponseComplete, r.Message != nil, r.HTTPStatus, e)
			if len(r.Wire) != size || r.HTTPStatus != 200 || !r.ResponseComplete {
				t.Fatalf("fixture failed: %+v %v", r, e)
			}
			if size == 65535 {
				if e != nil || r.Message == nil || r.Message.Rcode != dns.RcodeRefused {
					t.Fatalf("in-budget native DNS decoding lost: %+v %v", r, e)
				}
			} else if !errors.Is(e, measurement.ErrDNSLimit) || !errors.Is(e, measurement.ErrDNSResponse) || r.Message != nil {
				t.Fatalf("oversized DNS media admitted or typed causes lost: %+v %v", r, e)
			}
		})
	}
}

func TestAuditDoHQuestionlessNegativeAnswer(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if e != nil {
			t.Error(e)
			return
		}
		if e = q.Unpack(b); e != nil {
			t.Error(e)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Question = nil
		reply.Rcode = dns.RcodeRefused
		b, e = reply.Pack()
		if e != nil {
			t.Error(e)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
	}))
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	r, e := executor(t, instance(t)).DNSQuery(context.Background(), measurement.DNSRequest{Route: measurement.Route{Kind: measurement.Direct}, Transport: measurement.DNSDoH, Resolver: s.Listener.Addr().(*net.TCPAddr).AddrPort(), Name: "fixture.invalid.", Type: dns.TypeA, Timeout: time.Second, MaxResponseBytes: 512, ServerName: "example.com", RootCAs: pool, DoHPath: "/dns-query", MaxHeaderBytes: 4096})
	if e != nil || len(r.Wire) != 12 || !r.ResponseComplete || r.Message == nil || r.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("questionless DoH negative answer lost: %+v %v", r, e)
	}
}

func TestAuditDNSEDNSCarrierSize(t *testing.T) {
	for _, tc := range []struct {
		name   string
		route  measurement.Route
		noSend bool
	}{
		{"direct", measurement.Route{Kind: measurement.Direct}, false},
		{"exact", measurement.Route{Kind: measurement.ExactOutbound, Tag: "exact"}, false},
		{"missing_tag_no_send", measurement.Route{Kind: measurement.ExactOutbound, Tag: "missing"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if e = c.SetReadDeadline(time.Now().Add(2 * time.Second)); e != nil {
				t.Fatal(e)
			}
			done := make(chan int, 1)
			go func() {
				b := make([]byte, 512)
				n, peer, e := c.ReadFromUDP(b)
				if e != nil {
					done <- 0
					return
				}
				q := new(dns.Msg)
				if e = q.Unpack(b[:n]); e != nil {
					done <- 0
					return
				}
				r := new(dns.Msg)
				r.SetReply(q)
				r.SetEdns0(12000, false)
				parts := make([]string, 39)
				for i := range parts {
					parts[i] = strings.Repeat("x", 230)
				}
				r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "fixture.invalid.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: parts}}
				b, e = r.Pack()
				if e != nil {
					done <- 0
					return
				}
				n, e = c.WriteToUDP(b, peer)
				if e != nil {
					done <- 0
					return
				}
				done <- n
			}()
			r, e := executor(t, instance(t)).DNSQuery(context.Background(), measurement.DNSRequest{Route: tc.route, Transport: measurement.DNSUDP, Resolver: c.LocalAddr().(*net.UDPAddr).AddrPort(), Name: "fixture.invalid.", Type: dns.TypeTXT, Timeout: time.Second, MaxResponseBytes: 12000, EDNSSize: 12000})
			// Close before joining, including a pre-dispatch failure with no datagram.
			c.Close()
			sent := <-done
			t.Logf("peer_datagram=%d wire=%d complete=%t decoded=%t native_error=%v method_error=%v", sent, len(r.Wire), r.ResponseComplete, r.Message != nil, r.OutboundError, e)
			if tc.noSend {
				if e == nil || sent != 0 || len(r.Wire) != 0 {
					t.Fatalf("missing-tag no-send control failed: %+v %v, sent=%d", r, e, sent)
				}
				return
			}
			if sent <= 8192 || sent > 12000 {
				t.Fatal("fixture did not send legal larger native-carrier datagram")
			}
			if tc.route.Kind == measurement.Direct && (e != nil || len(r.Wire) != sent || r.Message == nil || !r.ResponseComplete) {
				t.Fatal("DIRECT baseline lost valid datagram")
			}
		})
	}
}

func TestAuditHTTPStatusAndExpectedContent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"expected204", 204, ""}, {"portal200", 200, "<html>login</html>"}, {"server500", 500, "failed"}, {"redirect302", 302, "redirect"}, {"wrongMarker200", 200, "not-the-expected-marker"}} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://fixture.invalid/login")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			r, e := executor(t, instance(t)).HTTP(context.Background(), http.MethodGet, measurement.HTTPRequest(request(s, measurement.Direct)))
			t.Logf("status=%d bytes=%d complete=%t method_error=%v body=%q", r.StatusCode, r.BodyBytes, r.BodyComplete, e, string(r.Body))
			if r.StatusCode != tc.status || string(r.Body) != tc.body || r.BodyBytes != int64(len(tc.body)) || !r.BodyComplete || e != nil {
				t.Fatalf("raw HTTP response hidden or qualified as an operation error: %+v %v", r, e)
			}
		})
	}
}
