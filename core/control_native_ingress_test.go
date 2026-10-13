package core_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	proxymanin "github.com/xtls/xray-core/app/proxyman/inbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fin "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

var controlIngressID atomic.Uint64

// Each stimulus enters a real native listener/worker and decoded inbound owner.
// Closing the fixture also retires its UDP worker, whose peer has no wire EOF.
type controlIngressConn struct {
	net.Conn
	once         sync.Once
	closeIngress func()
}

func (c *controlIngressConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closeIngress)
	return err
}

func controlNativeDial(tb testing.TB, instance *core.Instance, destination xnet.Destination) net.Conn {
	tb.Helper()
	return controlNativeDialContext(tb, context.Background(), instance, destination)
}

func controlNativeDialContext(tb testing.TB, ctx context.Context, instance *core.Instance, destination xnet.Destination) net.Conn {
	tb.Helper()
	port := tcp.PickPort()
	if destination.Network == xnet.Network_UDP {
		port = udp.PickPort()
	}
	tag := fmt.Sprintf("control-native-%d", controlIngressID.Add(1))
	ctx = context.WithValue(ctx, core.XrayKey(1), instance)
	ctx = context.WithValue(ctx, "cone", true)
	handler, err := proxymanin.NewHandler(ctx, &core.InboundHandlerConfig{
		Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
		}),
		ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
			RewriteAddress: xnet.NewIPOrDomain(destination.Address), RewritePort: uint32(destination.Port),
			AllowedNetworks: []xnet.Network{destination.Network},
		}),
	})
	if err != nil {
		tb.Fatal(err)
	}
	manager := instance.GetFeature(fin.ManagerType()).(fin.Manager)
	if err := manager.AddHandler(ctx, handler); err != nil {
		_ = handler.Close()
		tb.Fatal(err)
	}
	conn, err := net.DialTimeout(strings.ToLower(destination.Network.String()), net.JoinHostPort("127.0.0.1", port.String()), 3*time.Second)
	if err != nil {
		_ = manager.RemoveHandler(ctx, tag)
		tb.Fatal(err)
	}
	result := &controlIngressConn{Conn: conn, closeIngress: func() { _ = manager.RemoveHandler(ctx, tag) }}
	tb.Cleanup(func() { _ = result.Close() })
	return result
}
