//go:build linux

package dokodemo

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

type inspectionRedirectConn struct {
	net.Conn
	input  *strings.Reader
	remote net.Addr
	closed chan struct{}
	once   sync.Once
}

func (c *inspectionRedirectConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *inspectionRedirectConn) RemoteAddr() net.Addr       { return c.remote }
func (c *inspectionRedirectConn) Close() error               { c.once.Do(func() { close(c.closed) }); return nil }

type inspectionRedirectDispatcher struct {
	routing.Dispatcher
	target, alternate net.Destination
	entered           chan context.Context
	t                 *testing.T
}

func (d *inspectionRedirectDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if dest != d.target {
		d.t.Errorf("redirect target: %v", dest)
	}
	if o := session.LogicalObservationFromContext(ctx); o != nil {
		o.Exchange.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
		proxy.ClaimObservedEndpoint(ctx, link.Reader, true)
	}
	mb, err := link.Reader.ReadMultiBuffer()
	got := mb.String()
	buf.ReleaseMulti(mb)
	if err != nil || got != "request" {
		d.t.Errorf("native input: %q %v", got, err)
	}
	alternate := buf.FromBytes([]byte("alternate"))
	alternate.UDP = &d.alternate
	if err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("primary")), alternate}); err != nil {
		return err
	}
	d.entered <- ctx
	<-ctx.Done()
	return ctx.Err()
}

// Explicit opt-in: native IP_TRANSPARENT sockets need Linux capabilities.
// This fixture only binds loopback; it never changes interfaces or routes.
func TestInspectionDokodemoNativeFakeUDP(t *testing.T) {
	if os.Getenv("XRAY_TEST_FAKEUDP") != "1" {
		t.Skip("set XRAY_TEST_FAKEUDP=1 for native Linux FakeUDP")
	}
	for _, enabled := range []bool{false, true} {
		client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP()})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		pick := func() net.Destination {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseAddress("127.0.0.2").IP()})
			if err != nil {
				t.Fatal(err)
			}
			d := net.DestinationFromAddr(c.LocalAddr())
			c.Close()
			return d
		}
		target, alternate := pick(), pick()
		manager := new(appstats.Manager)
		defer manager.Close()
		var view fs.FlowInspection
		if enabled {
			view, err = manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}
		door := &DokodemoDoor{statsManager: manager, config: &Config{FollowRedirect: true}}
		conn := &inspectionRedirectConn{input: strings.NewReader("request"), remote: client.LocalAddr(), closed: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: net.DestinationFromAddr(client.LocalAddr())})
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
		dispatcher := &inspectionRedirectDispatcher{target: target, alternate: alternate, entered: make(chan context.Context, 1), t: t}
		done := make(chan error, 1)
		go func() { done <- door.Process(ctx, net.Network_UDP, conn, dispatcher) }()
		for _, want := range []struct {
			payload string
			source  net.Destination
		}{{"primary", target}, {"alternate", alternate}} {
			client.SetReadDeadline(time.Now().Add(3 * time.Second))
			p := make([]byte, 64)
			n, source, err := client.ReadFromUDP(p)
			if err != nil || string(p[:n]) != want.payload || net.DestinationFromAddr(source) != want.source {
				t.Fatalf("native datagram: %q %v %v", p[:n], source, err)
			}
		}
		observed := <-dispatcher.entered
		if enabled {
			ref := session.LogicalObservationFromContext(observed).Exchange.Ref()
			outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
			if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
				t.Fatalf("stop: %+v %v", outcomes, err)
			}
			select {
			case <-conn.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("exact incoming association was not closed")
			}
		} else {
			cancel()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Process did not finish")
		}
		if enabled {
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("terminal: %+v %v", page, err)
			}
			f := page.Rows[0].Flow
			if f.Uplink.Known != 7 || f.Downlink.Known != 16 || f.Downlink.Incomplete || f.InitialDestination != target {
				t.Fatalf("native facts: %+v", f)
			}
		}
		// Both primary and per-destination FakeUDP handles must be retired by Process.
		for _, d := range []net.Destination{target, alternate} {
			c, err := net.ListenUDP("udp4", d.RawNetAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatalf("retained forged socket %v: %v", d, err)
			}
			c.Close()
		}
		if _, err = conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatal(err)
		}
	}
}
