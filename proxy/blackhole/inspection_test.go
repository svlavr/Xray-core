package blackhole_test

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
)

type inspectionPrefixWriter struct{}

func (inspectionPrefixWriter) Write([]byte) (int, error) { return 3, io.ErrClosedPipe }

type inspectionPendingReader struct{ release <-chan struct{} }

func (r inspectionPendingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.release
	return buf.MultiBuffer{buf.FromBytes([]byte("unconsumed"))}, io.EOF
}

func blackholeInspection(t *testing.T, link *transport.Link, network cnet.Network) (context.Context, fs.FlowInspection, func()) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	dest := cnet.TCPDestination(cnet.LocalHostIP, 80)
	dest.Network = network
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginInternal)
	observe := proxy.ObserveTCP
	if network == cnet.Network_UDP {
		observe = proxy.ObserveUDP
	}
	ctx, finish := observe(ctx, manager, conn, dest, link)
	t.Cleanup(finish)
	session.LogicalObservationFromContext(ctx).Exchange.Route(fs.OutboundRef{Tag: "block"})
	return ctx, view, finish
}

func TestInspectionBlackholePartialResponse(t *testing.T) {
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: &buf.SequentialWriter{Writer: inspectionPrefixWriter{}}}
	ctx, view, finish := blackholeInspection(t, link, cnet.Network_TCP)
	handler, err := blackhole.New(ctx, &blackhole.Config{Response: &blackhole.Response{Type: "custom", CustomResponseData: []byte("response")}})
	if err != nil {
		t.Fatal(err)
	}
	// Native Blackhole still ignores the write error; its native writer records
	// the three accepted bytes without changing that return.
	if err := handler.Process(ctx, link, nil); err != nil {
		t.Fatal(err)
	}
	live, err := view.ReadLiveInto(nil)
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Downlink != 3 || live.Rows[0].Uplink != 0 || live.Rows[0].Origin != fs.TrafficOriginInternal {
		t.Fatalf("prefix/error live receipt: %+v %v", live, err)
	}
	finish()
}

func TestInspectionBlackholePendingReadOwnerEnd(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	link := &transport.Link{Reader: inspectionPendingReader{release: release}, Writer: &buf.SequentialWriter{Writer: io.Discard}}
	ctx, _, finish := blackholeInspection(t, link, cnet.Network_TCP)
	cursor := link.Reader.(*buf.InspectionReader)
	mb, err := cursor.ReadMultiBufferTimeout(time.Millisecond)
	buf.ReleaseMulti(mb)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := blackhole.New(ctx, &blackhole.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Process(ctx, link, nil); err != nil {
		t.Fatal(err)
	}
	finish()

	close(release)
}

func TestInspectionBlackholeInheritedContextLeavesEndpointUnchanged(t *testing.T) {
	for _, network := range []cnet.Network{cnet.Network_TCP, cnet.Network_UDP} {
		link := &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: &buf.SequentialWriter{Writer: io.Discard}}
		ctx, view, finish := blackholeInspection(t, link, network)
		// A different link carrying only the inherited context is not
		// authority over the original observed endpoint, for either network.
		link = &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: buf.Discard}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		handler, err := blackhole.New(ctx, &blackhole.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if err := handler.Process(canceled, link, nil); err != nil {
			t.Fatal(err)
		}
		live, _ := view.ReadLiveInto(nil)
		if len(live.Rows) != 1 || live.Rows[0].Outbound.Tag != "block" || live.Rows[0].Uplink != 0 {
			t.Fatalf("claimed an inherited-only endpoint: %+v", live)
		}
		finish()

		totals, err := view.ReadTotals()
		if err != nil {
			t.Fatal(err)
		}
		if len(totals.Rows) != 0 || totals.User != (fs.ClientTotals{}) {
			t.Fatalf("inherited INTERNAL endpoint promoted to USER: %+v", totals)
		}
	}
}

type inspectionUDPDrainReader struct {
	started chan struct{}
	release <-chan struct{}
}

func (r inspectionUDPDrainReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.started)
	<-r.release
	b := buf.New()
	b.WriteString("late unconsumed UDP payload")
	return buf.MultiBuffer{b}, io.EOF
}

func TestInspectionBlackholeUDPDrainOwnerEnd(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	link := &transport.Link{Reader: inspectionUDPDrainReader{started, release}, Writer: &buf.SequentialWriter{Writer: io.Discard}}
	ctx, _, finish := blackholeInspection(t, link, cnet.Network_UDP)
	// The native target-resolution wrapper must not hide the logical cursor.
	link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: cnet.LocalHostIP}
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	handler, err := blackhole.New(ctx, &blackhole.Config{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- handler.Process(ctx, link, nil) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("UDP drain did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native cancellation waited for the detached drain")
	}
	finish()

	close(release)
}
