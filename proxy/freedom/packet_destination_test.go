package freedom

import (
	"context"
	"io"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type addressMask struct{}

func (addressMask) WrapPacketConnClient(c net.PacketConn, _ *net.Destination, _ *finalmask.Dialer) (net.PacketConn, error) {
	return c, nil
}

func (addressMask) WrapPacketConnServer(c net.PacketConn, _ net.Addr, _ *finalmask.ListenConfig) (net.PacketConn, error) {
	return c, nil
}

func TestFreedomPacketAddressesThroughNativeWrappers(t *testing.T) {
	for _, mode := range []string{"direct", "configured", "masked"} {
		t.Run(mode, func(t *testing.T) {
			listen := func() *net.UDPConn {
				c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				c.SetDeadline(time.Now().Add(3 * time.Second))
				return c
			}
			sender, first, second := listen(), listen(), listen()
			target := net.DestinationFromAddr(first.LocalAddr())
			var conn net.Conn = &net.PacketConnWrapper{PacketConn: sender, Dest: target.RawNetAddr()}
			if mode != "direct" {
				var masks []finalmask.UDPMask
				if mode == "masked" {
					masks = []finalmask.UDPMask{addressMask{}}
				}
				fm := finalmask.NewFinalMask(nil, masks, nil, nil, func(context.Context, net.Destination) (net.PacketConn, net.Addr, error) {
					return sender, first.LocalAddr(), nil
				}, nil)
				var err error
				conn, err = fm.DialUDP(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
			}
			up, down := new(appstats.Counter), new(appstats.Counter)
			counted := &stat.CounterConnection{Connection: conn, WriteCounter: up, ReadCounter: down}
			writer := NewPacketWriter(context.Background(), counted, &Handler{}, nil, net.Destination{}, target, nil)
			reader := NewPacketReader(counted, &Handler{}, nil, net.Destination{}, target)
			for _, receiver := range []*net.UDPConn{first, second} {
				b := buf.New()
				b.Write([]byte("payload"))
				dest := net.DestinationFromAddr(receiver.LocalAddr())
				b.UDP = &dest
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, 32)
				n, source, err := receiver.ReadFromUDP(payload)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = receiver.WriteToUDP(payload[:n], source); err != nil {
					t.Fatal(err)
				}
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				if string(mb[0].Bytes()) != "payload" || mb[0].UDP == nil || *mb[0].UDP != dest {
					t.Fatalf("response metadata: %v", mb[0].UDP)
				}
				buf.ReleaseMulti(mb)
			}
			if up.Value() != 14 || down.Value() != 14 {
				t.Fatalf("counters: %d/%d", up.Value(), down.Value())
			}
		})
	}
}

type fixedTargetConn struct {
	net.Conn
	writes int
	fail   bool
}

func (c *fixedTargetConn) Write(p []byte) (int, error) {
	c.writes++
	if c.fail {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestFreedomDialerProxyRejectsDifferentPacketTarget(t *testing.T) {
	target := net.UDPDestination(net.LocalHostIP, 1000)
	other := net.UDPDestination(net.LocalHostIP, 2000)
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "reject", true: "override"}[override], func(t *testing.T) {
			c := new(fixedTargetConn)
			redirect := net.Destination{}
			if override {
				redirect = target
			}
			writer := NewPacketWriter(context.Background(), c, &Handler{usesDialerProxy: true}, nil, redirect, target, nil)
			var mb buf.MultiBuffer
			for _, dest := range []net.Destination{target, other} {
				b := buf.New()
				b.Write([]byte("x"))
				d := dest
				b.UDP = &d
				mb = append(mb, b)
			}
			err := writer.WriteMultiBuffer(mb)
			if override {
				if err != nil || c.writes != 2 {
					t.Fatalf("override: writes=%d err=%v", c.writes, err)
				}
			} else if err == nil || c.writes != 1 {
				t.Fatalf("misroute: writes=%d err=%v", c.writes, err)
			}
		})
	}
}
