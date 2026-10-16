package masque

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
)

type xdnsReadWitness struct {
	net.PacketConn
	entered chan struct{}
	once    sync.Once
}

func (c *xdnsReadWitness) ReadFrom(p []byte) (int, net.Addr, error) {
	c.once.Do(func() { close(c.entered) })
	return c.PacketConn.ReadFrom(p)
}

func TestXDNSListenerClose(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := xdns.NewServer(&xdns.Config{Domains: []*xdns.DomainProto{{Name: "x.example", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}}}, raw)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	observed := &xdnsReadWitness{PacketConn: pc, entered: make(chan struct{})}
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cert.Close()
	tr := &quic.Transport{Conn: observed}
	t.Cleanup(func() { pc.Close(); tr.Close() })
	ql, err := tr.Listen(&tls.Config{Certificates: cert.TLS.Certificates, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ql.Close() })
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("QUIC read was not entered")
	}
	l := &Listener{cancel: func() {}, quicListener: ql, transport: tr, pktConn: observed}
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		pc.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("MASQUE Close waited for an unsupported XDNS read deadline")
	}
}
