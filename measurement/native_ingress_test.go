package measurement_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	proxymanin "github.com/xtls/xray-core/app/proxyman/inbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fin "github.com/xtls/xray-core/features/inbound"
	frouting "github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

var nativeIngressID atomic.Uint64

type nativeIngressConn struct {
	net.Conn
	destination  xnet.Destination
	once         sync.Once
	closeIngress func()
}

func (c *nativeIngressConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closeIngress)
	return err
}

// Existing XUDP fixtures write MultiBuffers. The stimulus remains a real UDP
// datagram through the SOCKS packet decoder, with no inspection receipt.
func (c *nativeIngressConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b.UDP != nil && *b.UDP != c.destination {
			return fmt.Errorf("native fixture destination changed: %v", b.UDP)
		}
		n, err := c.Conn.Write(b.Bytes())
		if err != nil {
			return err
		}
		if n != int(b.Len()) {
			return io.ErrShortWrite
		}
	}
	return nil
}

type nativeSOCKSPacketConn struct {
	*net.UDPConn
	control     net.Conn
	relay       *net.UDPAddr
	destination xnet.Destination
}

func (c *nativeSOCKSPacketConn) Write(payload []byte) (int, error) {
	packet, err := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: c.destination.Address, Port: c.destination.Port}, payload)
	if err != nil {
		return 0, err
	}
	defer packet.Release()
	n, err := c.WriteToUDP(packet.Bytes(), c.relay)
	if n != int(packet.Len()) {
		return 0, err
	}
	return len(payload), err
}

func (c *nativeSOCKSPacketConn) Read(payload []byte) (int, error) {
	packet := buf.New()
	defer packet.Release()
	n, sender, err := c.ReadFromUDP(packet.Extend(buf.Size))
	if err != nil {
		return 0, err
	}
	if sender.String() != c.relay.String() {
		return 0, fmt.Errorf("unexpected SOCKS relay: %v", sender)
	}
	packet.Resize(0, int32(n))
	request, err := socks.DecodeUDPPacket(packet)
	if err != nil {
		return 0, err
	}
	if request.Destination() != c.destination {
		return 0, fmt.Errorf("unexpected native packet source: %v", request.Destination())
	}
	return copy(payload, packet.Bytes()), nil
}

func (c *nativeSOCKSPacketConn) Close() error {
	_ = c.control.Close()
	return c.UDPConn.Close()
}

// Use the native receiver, worker and decoded admission path. The route is
// confined to this listener's inbound tag; Measurement retains its own routing.
// Each fixture owns a listener so Close also retires UDP state without wire EOF.
func nativeIngressDial(t *testing.T, ctx context.Context, instance *core.Instance, destination xnet.Destination) (net.Conn, xnet.Destination) {
	t.Helper()
	port := tcp.PickPort()
	tag := fmt.Sprintf("fixture-native-%d", nativeIngressID.Add(1))
	selectedTag := session.GetForcedOutboundTagFromContext(ctx)
	routing := instance.GetFeature(frouting.RouterType()).(frouting.Router)
	if err := routing.AddRule(serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{RuleTag: tag, InboundTag: []string{tag}, TargetTag: &router.RoutingRule_Tag{Tag: selectedTag}}}}), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routing.RemoveRule(tag) })
	ctx = context.WithValue(ctx, core.XrayKey(1), instance)
	ctx = context.WithValue(ctx, "cone", true)
	proxySettings := serial.ToTypedMessage(&dokodemo.Config{
		RewriteAddress: xnet.NewIPOrDomain(destination.Address), RewritePort: uint32(destination.Port),
		AllowedNetworks: []xnet.Network{destination.Network},
	})
	if destination.Network == xnet.Network_UDP {
		proxySettings = serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UdpEnabled: true})
	}
	handler, err := proxymanin.NewHandler(ctx, &core.InboundHandlerConfig{
		Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
		}),
		ProxySettings: proxySettings,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := instance.GetFeature(fin.ManagerType()).(fin.Manager)
	if err := manager.AddHandler(ctx, handler); err != nil {
		_ = handler.Close()
		t.Fatal(err)
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port.String()))
	if err != nil {
		_ = manager.RemoveHandler(context.Background(), tag)
		t.Fatal(err)
	}
	source := xnet.DestinationFromAddr(conn.LocalAddr())
	if destination.Network == xnet.Network_UDP {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		response, err := socks.ClientHandshake(&protocol.RequestHeader{Command: protocol.RequestCommandUDP}, conn, conn)
		if err != nil {
			_ = conn.Close()
			_ = manager.RemoveHandler(context.Background(), tag)
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Time{})
		packet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			_ = conn.Close()
			_ = manager.RemoveHandler(context.Background(), tag)
			t.Fatal(err)
		}
		conn = &nativeSOCKSPacketConn{UDPConn: packet, control: conn, destination: destination, relay: &net.UDPAddr{IP: response.Address.IP(), Port: int(response.Port)}}
		// Native SOCKS fills the association source from the first accepted
		// datagram; this is the actual UDP peer, also used for XUDP identity.
		source = xnet.DestinationFromAddr(conn.LocalAddr())
	}
	result := &nativeIngressConn{Conn: conn, destination: destination, closeIngress: func() { _ = manager.RemoveHandler(context.Background(), tag) }}
	t.Cleanup(func() { _ = result.Close() })
	return result, source
}

func nativeIngressContext(ctx context.Context, tag string) context.Context {
	return session.SetForcedOutboundTagToContext(ctx, tag)
}
