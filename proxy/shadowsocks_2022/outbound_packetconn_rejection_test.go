package shadowsocks_2022

import (
	"context"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type rejectedPacketConnProbe struct {
	reads, writes, closes int
}

func (c *rejectedPacketConnProbe) Read([]byte) (int, error) {
	c.reads++
	return 0, io.EOF
}

func (c *rejectedPacketConnProbe) Write(payload []byte) (int, error) {
	c.writes++
	return len(payload), nil
}

func (c *rejectedPacketConnProbe) Close() error {
	c.closes++
	return nil
}

func (*rejectedPacketConnProbe) LocalAddr() stdnet.Addr           { return &stdnet.UDPAddr{} }
func (*rejectedPacketConnProbe) RemoteAddr() stdnet.Addr          { return &stdnet.UDPAddr{} }
func (*rejectedPacketConnProbe) SetDeadline(time.Time) error      { return nil }
func (*rejectedPacketConnProbe) SetReadDeadline(time.Time) error  { return nil }
func (*rejectedPacketConnProbe) SetWriteDeadline(time.Time) error { return nil }

type rejectedSingPacketConn struct{ *rejectedPacketConnProbe }

func (c *rejectedSingPacketConn) ReadPacket(*B.Buffer) (M.Socksaddr, error) {
	c.reads++
	return M.Socksaddr{}, io.EOF
}

func (c *rejectedSingPacketConn) WritePacket(buffer *B.Buffer, _ M.Socksaddr) error {
	c.writes++
	buffer.Release()
	return nil
}

type rejectedNetPacketConn struct{ *rejectedPacketConnProbe }

func (c *rejectedNetPacketConn) ReadFrom([]byte) (int, stdnet.Addr, error) {
	c.reads++
	return 0, nil, io.EOF
}

func (c *rejectedNetPacketConn) WriteTo(payload []byte, _ stdnet.Addr) (int, error) {
	c.writes++
	return len(payload), nil
}

var (
	_ N.PacketConn      = (*rejectedSingPacketConn)(nil)
	_ stdnet.PacketConn = (*rejectedNetPacketConn)(nil)
)

type rejectedPacketDialer struct{ calls int }

func (d *rejectedPacketDialer) Dial(context.Context, cnet.Destination) (stat.Connection, error) {
	d.calls++
	return nil, io.ErrUnexpectedEOF
}

func (*rejectedPacketDialer) DestIpAddress() cnet.IP                                { return nil }
func (*rejectedPacketDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

var _ internet.Dialer = (*rejectedPacketDialer)(nil)

func TestSS2022RejectsDirectInboundPacketConn(t *testing.T) {
	constructors := []struct {
		name string
		new  func(*rejectedPacketConnProbe) cnet.Conn
	}{
		{"sing", func(probe *rejectedPacketConnProbe) cnet.Conn { return &rejectedSingPacketConn{probe} }},
		{"net", func(probe *rejectedPacketConnProbe) cnet.Conn { return &rejectedNetPacketConn{probe} }},
	}
	for _, constructor := range constructors {
		for _, enabled := range []bool{false, true} {
			t.Run(constructor.name+map[bool]string{false: "/disabled", true: "/enabled"}[enabled], func(t *testing.T) {
				probe := new(rejectedPacketConnProbe)
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: constructor.new(probe)})
				target := cnet.UDPDestination(cnet.DomainAddress("target.example"), 53)
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
				if enabled {
					manager := new(appstats.Manager)
					if _, err := manager.EnableInspection(fs.ObservationOptions{}); err != nil {
						t.Fatal(err)
					}
					defer manager.Close()
					flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, target, nil)
					defer flow.Finish()
					ctx = session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{Exchange: flow})
				}

				dialer := new(rejectedPacketDialer)
				err := (&Outbound{server: cnet.TCPDestination(cnet.LocalHostIP, 443)}).Process(ctx, &transport.Link{}, dialer)
				if err == nil || !strings.Contains(err.Error(), "direct inbound PacketConn is unsupported") {
					t.Fatalf("direct PacketConn rejection: %v", err)
				}
				if dialer.calls != 0 || probe.reads != 0 || probe.writes != 0 || probe.closes != 0 {
					t.Fatalf("rejected direct PacketConn was touched: dial=%d read=%d write=%d close=%d", dialer.calls, probe.reads, probe.writes, probe.closes)
				}
			})
		}
	}
}
