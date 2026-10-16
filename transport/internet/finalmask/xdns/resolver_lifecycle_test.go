package xdns

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type resolverCloseWitness struct {
	net.PacketConn
	closed chan struct{}
	once   sync.Once
}

func (c *resolverCloseWitness) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

func TestDOHH3FailedDialClosesPacketConn(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &resolverCloseWitness{PacketConn: raw, closed: make(chan struct{})}
	defer pc.Close()
	config := &ResolverProto{Type: "https", Addr: "https://example.com:9/dns-query", Worker: 1, TlsConfig: &xtls.Config{ServerName: "example.com", NextProtocol: []string{"h3"}}, QuicConfig: &internet.QuicParams{DisableChromeParrot: true}}
	resolver, err := NewDOHResolver(config, &finalmask.Dialer{DialUDP: func(xnet.Destination) (xnet.Conn, error) {
		return &xnet.PacketConnWrapper{PacketConn: pc, Dest: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = resolver.(*DOHResolver).client.Transport.(*http3.Transport).Dial(ctx, "example.com:9", &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}, &quic.Config{})
	if err == nil {
		t.Fatal("canceled dial succeeded")
	}
	select {
	case <-pc.closed:
	default:
		t.Fatal("failed DoH/H3 dial retained owned socket")
	}
}
