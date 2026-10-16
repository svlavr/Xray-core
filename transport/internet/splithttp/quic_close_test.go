package splithttp

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

type h3CloseWitness struct {
	net.PacketConn
	closed chan struct{}
	once   sync.Once
}

func (c *h3CloseWitness) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

func TestH3FailedDialClosesPacketConn(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &h3CloseWitness{PacketConn: raw, closed: make(chan struct{})}
	defer pc.Close()
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	fm := finalmask.NewFinalMask(nil, nil, nil, nil, func(context.Context, xnet.Destination) (net.PacketConn, net.Addr, error) { return pc, remote, nil }, nil)
	config := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}, SecuritySettings: &xtls.Config{ServerName: "example.com", NextProtocol: []string{"h3"}}, FinalMask: fm, QuicParams: &internet.QuicParams{DisableChromeParrot: true}}
	dest := xnet.UDPDestination(xnet.LocalHostIP, 9)
	client := createHTTPClient(dest, config).(*DefaultDialerClient)
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.client.Transport.(*http3.Transport).Dial(ctx, remote.String(), &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}, &quic.Config{})
	if err == nil {
		t.Fatal("canceled dial succeeded")
	}
	select {
	case <-pc.closed:
	default:
		t.Fatal("failed XHTTP/H3 dial retained owned socket")
	}
}
