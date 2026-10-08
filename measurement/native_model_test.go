package measurement_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/measurement"
)

func TestOrdinaryTransferDoesNotAddACKWork(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "nonce=caller&resource=fixed" {
			t.Error("ordinary transfer changed caller query")
		}
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		_, _ = io.WriteString(w, "raw-body")
	}))
	defer s.Close()
	e := executor(t, instance(t))
	for _, route := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		d := downloadRequest(s, route)
		d.HTTPS.URL += "?nonce=caller&resource=fixed"
		d.HTTPS.MaxBodyBytes = 70 << 20 // Former engine ceiling no longer applies.
		download, err := e.Download(context.Background(), d)
		if err != nil || download.PayloadBytes != 8 || download.SHA256 != nil || download.IntegrityVerified {
			t.Fatalf("ordinary download: %+v %v", download, err)
		}
		u := uploadRequest(s, route)
		u.HTTPS.URL += "?nonce=caller&resource=fixed"
		u.RequireAcknowledgment = false
		upload, err := e.Upload(context.Background(), u)
		if err != nil || upload.GeneratedBytes != u.PayloadBytes || upload.WriterAcceptedBytes != u.PayloadBytes || upload.Nonce != "" || upload.WriterAcceptedSHA256 != nil || upload.Acknowledgment != nil {
			t.Fatalf("ordinary upload: %+v %v", upload, err)
		}
	}
}

func TestIdentityUsesNativeJSONWithoutReceiptCertificates(t *testing.T) {
	response := measurement.HTTPSReceipt{StatusCode: 200, Body: []byte(`{"IP":"192.0.2.7","country":"zz","extra":true}`)}
	identity, err := measurement.IdentityFromHTTPS(response, measurement.IPv4)
	if err != nil || identity.Address.String() != "192.0.2.7" || identity.Country != "zz" {
		t.Fatalf("ordinary JSON: %+v %v", identity, err)
	}
	for _, body := range []string{`{"ip":"invalid"}`, `{"ip":"2001:db8::7"}`, `{"ip":7}`, `{"ip":"192.0.2.7"}{}`} {
		response.Body = []byte(body)
		if got, err := measurement.IdentityFromHTTPS(response, measurement.IPv4); err == nil || got.Address.IsValid() {
			t.Fatalf("invalid identity: %+v %v", got, err)
		}
	}
}

func TestCallerBudgetsAboveFormerCaps(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer s.Close()
	e := executor(t, instance(t))
	r := request(s, measurement.ExactOutbound)
	r.URL += "?opaque=" + strings.Repeat("a", 9000)
	r.Timeout, r.MaxBodyBytes, r.MaxHeaderBytes = 3*time.Minute, 70<<20, 128<<10
	if got, err := e.HTTPS(context.Background(), r); err != nil || string(got.Body) != "ok" {
		t.Fatalf("caller HTTP budgets: %+v %v", got, err)
	}
	addr := dnsStreamFixture(t, nil, func(c net.Conn, q []byte) { dnsFrame(c, dnsReply(q)) })
	d := dnsRequest(addr, measurement.DNSTCP, measurement.ExactOutbound)
	d.Timeout, d.MaxResponseBytes, d.EDNSSize = 31*time.Second, 65536, 4096
	if got, err := e.DNSQuery(context.Background(), d); err != nil || got.Message == nil {
		t.Fatalf("caller DNS budgets: %+v %v", got, err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	if got, err := e.TCPConnect(context.Background(), measurement.TCPConnectRequest{Route: measurement.Route{Kind: measurement.Direct}, Destination: netip.MustParseAddrPort(ln.Addr().String()), Timeout: 31 * time.Second}); err != nil || !got.DestinationConnected {
		t.Fatalf("caller TCP budget: %+v %v", got, err)
	}
	<-done
}

func TestCallerUDPTrainBudgetsAndSingleNativePacket(t *testing.T) {
	packets := make(chan int, 80)
	pc := udpFixture(t, func(_ net.PacketConn, packet []byte, _ net.Addr) {
		select {
		case packets <- len(packet):
		default:
		}
	})
	e := executor(t, instance(t))
	for _, route := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		r := udpRequest(pc.LocalAddr(), route)
		r.Count, r.PacketBytes, r.MaxReplies, r.Interval, r.ReplyWait = 65, 1201, 513, 0, 10*time.Millisecond
		got, err := e.UDPEcho(context.Background(), r)
		if err != nil || len(got.Sends) != 65 || !got.WindowComplete {
			t.Fatalf("caller UDP budgets: %+v %v", got, err)
		}
		for len(packets) > 0 {
			<-packets
		}
		r.Count, r.PacketBytes, r.ReplyWait = 1, 9000, 40*time.Millisecond
		if got, err := e.UDPEcho(context.Background(), r); err != nil || len(got.Sends) != 1 {
			t.Fatalf("large single native packet: %+v %v", got, err)
		}
		found := false
		for len(packets) > 0 {
			if <-packets == 9000 {
				found = true
			}
		}
		if !found {
			t.Fatal("native writer split or lost the large packet")
		}
	}
}

func TestMappedAddressesUseNativeFamily(t *testing.T) {
	dnsPeer := udpFixture(t, func(pc net.PacketConn, packet []byte, addr net.Addr) {
		_, _ = pc.WriteTo(dnsReply(packet), addr)
	})
	echoPeer := udpFixture(t, func(pc net.PacketConn, packet []byte, addr net.Addr) {
		_, _ = pc.WriteTo(packet, addr)
	})
	e := executor(t, instance(t))
	for _, route := range []measurement.RouteKind{measurement.Direct, measurement.ExactOutbound} {
		d := dnsRequest(dnsPeer.LocalAddr(), measurement.DNSUDP, route)
		d.Resolver = netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), d.Resolver.Port())
		if got, err := e.DNSQuery(context.Background(), d); err != nil || got.Message == nil {
			t.Fatalf("mapped DNS address: %+v %v", got, err)
		}
		r := udpRequest(echoPeer.LocalAddr(), route)
		r.Destination = netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), r.Destination.Port())
		if got, err := e.UDPEcho(context.Background(), r); err != nil || len(got.Replies) != r.Count {
			t.Fatalf("mapped echo address: %+v %v", got, err)
		} else {
			for _, reply := range got.Replies {
				if reply.Issue != measurement.UDPReplyValid {
					t.Fatalf("mapped echo was mismatched: %+v", reply)
				}
			}
		}
	}
}
