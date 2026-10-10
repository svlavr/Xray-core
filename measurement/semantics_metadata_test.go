package measurement_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/measurement"
)

func TestAuditNativeHTTPFramingMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		length    int64
		chunked   bool
		method    string
		bodyBytes int64
	}{{"fixed", "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nprefix", 6, false, http.MethodGet, 6}, {"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nprefix\r\n0\r\n\r\n", -1, true, http.MethodGet, 6}, {"close_delimited", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nprefix", -1, false, http.MethodGet, 6}, {"head_advertised_length", "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n", 4096, false, http.MethodHead, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s := auditRawTLS(t, tc.raw, false)
			q := request(s, measurement.Direct)
			if tc.method == http.MethodHead {
				q.MaxBodyBytes = 0
			}
			r, e := executor(t, instance(t)).HTTP(context.Background(), tc.method, measurement.HTTPRequest(q))
			if e != nil || r.StatusCode != 200 || r.BodyBytes != tc.bodyBytes {
				t.Fatalf("fixture response failed: %+v %v", r, e)
			}
			if r.ContentLength == nil || *r.ContentLength != tc.length {
				t.Fatalf("native length fact lost: %+v", r)
			}
			if tc.chunked {
				if len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" || r.Header.Get("Transfer-Encoding") != "" {
					t.Fatalf("native framing fact was lost: %+v", r)
				}
			} else if len(r.TransferEncoding) != 0 {
				t.Fatalf("invented transfer encoding: %+v", r)
			}
		})
	}
}

func TestAuditHTTPMetadataAbsentBeforeResponse(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	e := executor(t, instance(t))
	t.Run("pre_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, err := e.HTTPS(ctx, request(s, measurement.Direct))
		if !errors.Is(err, context.Canceled) || r.StatusCode != 0 || r.ContentLength != nil || r.TransferEncoding != nil {
			t.Fatalf("pre-response metadata invented: %+v %v", r, err)
		}
	})
	t.Run("TLS_rejected", func(t *testing.T) {
		q := request(s, measurement.Direct)
		q.RootCAs = x509.NewCertPool()
		r, err := e.HTTPS(context.Background(), q)
		if err == nil || r.StatusCode != 0 || r.ContentLength != nil || r.TransferEncoding != nil || r.EndpointTLS == nil {
			t.Fatalf("TLS attempt and response facts conflated: %+v %v", r, err)
		}
	})
}

func TestAuditUDPQuestionlessResponseStaysUnqualified(t *testing.T) {
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		b := make([]byte, 512)
		n, peer, err := c.ReadFromUDP(b)
		if err != nil {
			done <- err
			return
		}
		q := new(dns.Msg)
		if err = q.Unpack(b[:n]); err != nil {
			done <- err
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeRefused
		r.Question = nil
		b, err = r.Pack()
		if err == nil {
			_, err = c.WriteToUDP(b, peer)
		}
		done <- err
	}()
	r, e := executor(t, instance(t)).DNSQuery(context.Background(), measurement.DNSRequest{Route: measurement.Route{Kind: measurement.Direct}, Transport: measurement.DNSUDP, Resolver: c.LocalAddr().(*net.UDPAddr).AddrPort(), Name: "fixture.invalid.", Type: dns.TypeA, Timeout: time.Second, MaxResponseBytes: 512})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture did not observe query")
	}
	if !errors.Is(e, measurement.ErrDNSResponse) || r.Message != nil || !r.ResponseComplete || len(r.Wire) != 12 {
		t.Fatalf("questionless UDP correlation was relaxed: %+v %v", r, e)
	}
}

func TestAuditReportedIdentityCanDifferFromPeerObservation(t *testing.T) {
	for _, ip := range []string{"203.0.113.7", "2001:db8::7"} {
		t.Run(ip, func(t *testing.T) {
			observed := make(chan netip.Addr, 1)
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				peer, err := netip.ParseAddrPort(request.RemoteAddr)
				if err != nil {
					t.Error(err)
					return
				}
				observed <- peer.Addr().Unmap()
				fmt.Fprintf(w, `{"ip":%q,"country":"ZZ","countrySource":"endpoint"}`, ip)
			}))
			defer s.Close()
			r, e := executor(t, instance(t)).EgressIdentity(context.Background(), measurement.IdentityRequest{HTTPS: request(s, measurement.Direct)})
			if e != nil || r.Address != netip.MustParseAddr(ip) {
				t.Fatalf("reported identity not preserved: %+v %v", r, e)
			}
			select {
			case peer := <-observed:
				if peer == r.Address {
					t.Fatal("fixture did not distinguish reported and observed address")
				}
				t.Logf("peer=%v declared=%v family=%d", peer, r.Address, r.Family)
			case <-time.After(time.Second):
				t.Fatal("fixture did not record source")
			}
		})
	}
}
