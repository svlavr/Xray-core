package tun

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

func inspectionNativeTCP(t *testing.T, tun Tun) *tcpConn {
	t.Helper()
	s := &stack{tun: tun, mtu: testMTU, window: tcpWindow, conns: make(map[flow]*tcpConn)}
	f := flow{src: netip.MustParseAddrPort("10.0.0.2:1234"), dst: netip.MustParseAddrPort("10.0.0.1:443")}
	c := newTCPConn(s, f, segment{seq: 1, window: 65535})
	c.established = true
	c.sndUna, c.sndBase = c.sndNxt, c.sndNxt
	s.conns[f] = c
	t.Cleanup(func() {
		c.mu.Lock()
		c.abort(io.ErrClosedPipe)
		c.mu.Unlock()
	})
	return c
}

func inspectionNativeFlow(t *testing.T, c *tcpConn) (fs.Exchange, fs.FlowInspection) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().PrepareTCP(fs.TrafficOriginUser, c.src, c.dst, c.Close)
	flow.Route(fs.OutboundRef{Tag: "direct"})
	return flow, view
}

func inspectionOwnedPacket(data string) *buf.Buffer {
	b := buf.New()
	_, _ = b.Write([]byte(data))
	return b
}

func TestInspectionTCPNativeAcceptedPrefixOnStop(t *testing.T) {
	for _, inspected := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "inspected"}[inspected], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			l := newLink()
			l.out = func(p []byte) {
				if len(p) > ipv4HeaderSize+tcpHeaderSize {
					once.Do(func() { close(entered); <-release })
				}
			}
			c := inspectionNativeTCP(t, l)
			c.sndWnd = 4
			counter := new(testCounter)
			var writer buf.Writer = &tunTCPWriter{writer: c, counter: counter}
			var flow fs.Exchange
			var view fs.FlowInspection
			if inspected {
				flow, view = inspectionNativeFlow(t, c)
				writer = buf.AttachWriterReceipt(writer, flow)
				if buf.WriterReceipt(writer) != flow {
					t.Fatal("native TCP receipt not bound")
				}
			}
			done := make(chan error, 1)
			go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("headtail"))}) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("native TCP writer did not enter output")
			}
			if inspected {
				outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
				if err != nil || len(outcomes) != 1 || outcomes[0] != nil {
					close(release)
					t.Fatalf("stop: %v %v", outcomes, err)
				}
				flow.Finish()
			} else {
				c.Close()
			}
			close(release)
			select {
			case err := <-done:
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("native TCP writer remained blocked after stop")
			}
			if counter.Value() != 4 {
				t.Fatalf("accepted native prefix: %d", counter.Value())
			}
			if inspected {
				totals, err := view.ReadTotals()
				if err != nil || totals.User.Downlink != 4 || len(totals.Rows) != 1 || totals.Rows[0].Downlink != 4 {
					t.Fatalf("accepted decoded prefix: %+v %v", totals, err)
				}
			}
		})
	}
}

// A failed packet emission is retried by the native TCP owner. It does not revoke
// decoded bytes accepted by the application writer, or count them again on retry.
type inspectionRetryTun struct {
	*link
	calls atomic.Int32
}

func (l *inspectionRetryTun) WritePacket(_, _ []byte) error {
	l.calls.Add(1)
	return io.ErrUnexpectedEOF
}

func TestInspectionTCPNativeRetryCountsApplicationOnce(t *testing.T) {
	l := &inspectionRetryTun{link: newLink()}
	c := inspectionNativeTCP(t, l)
	flow, view := inspectionNativeFlow(t, c)
	counter := new(testCounter)
	writer := buf.AttachWriterReceipt(&tunTCPWriter{writer: c, counter: counter}, flow)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("head")), buf.FromBytes([]byte("tail"))}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.retransmit(c.sndUna, c.sndNxt)
	c.mu.Unlock()
	if l.calls.Load() < 3 {
		t.Fatalf("fixture did not retry native output: %d", l.calls.Load())
	}
	totals, err := view.ReadTotals()
	if counter.Value() != 8 || err != nil || totals.User.Downlink != 8 || len(totals.Rows) != 1 || totals.Rows[0].Downlink != 8 {
		t.Fatalf("application output repeated or lost: counter=%d totals=%+v err=%v", counter.Value(), totals, err)
	}
}

func TestInspectionUDPShutdownSealsAndReleases(t *testing.T) {
	created := make(chan *udpConn, 1)
	u := newUdpConnectionHandler(func(c net.Conn, _ net.Destination) { created <- c.(*udpConn) }, nil)
	src := net.UDPDestination(net.LocalHostIP, 1234)
	dst := net.UDPDestination(net.LocalHostIP, 53)
	queued := inspectionOwnedPacket("queued")
	u.HandlePacket(src, dst, queued)
	c := <-created
	s := &stack{udp: u, conns: make(map[flow]*tcpConn)}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !queued.IsEmpty() {
		t.Fatal("queued UDP buffer was not released")
	}
	if mb, err := c.ReadMultiBuffer(); len(mb) != 0 || err != io.EOF {
		buf.ReleaseMulti(mb)
		t.Fatalf("closed UDP reader: %v %v", mb, err)
	}
	late := inspectionOwnedPacket("late")
	u.HandlePacket(src, dst, late)
	if !late.IsEmpty() {
		t.Fatal("late UDP buffer was not released")
	}
	if len(u.udpConns) != 0 {
		t.Fatal("UDP association recreated after shutdown")
	}
	c.Close()
	u.Close()
}

func TestInspectionUDPQueueDropAndRetirementRelease(t *testing.T) {
	u := newUdpConnectionHandler(nil, nil)
	src := net.UDPDestination(net.LocalHostIP, 1234)
	dst := net.UDPDestination(net.LocalHostIP, 53)
	c := &udpConn{handler: u, src: src, dst: dst, egress: make(chan *buf.Buffer, 1)}
	u.udpConns[src] = c
	queued, dropped := inspectionOwnedPacket("queued"), inspectionOwnedPacket("dropped")
	u.HandlePacket(src, dst, queued)
	u.HandlePacket(src, dst, dropped)
	if !dropped.IsEmpty() {
		t.Fatal("dropped UDP buffer was not released")
	}
	c.Close()
	if !queued.IsEmpty() {
		t.Fatal("unread UDP buffer was not released on retirement")
	}
}

func TestInspectionTCPNativeSegmenterCountsDecodedOnce(t *testing.T) {
	l := newLink()
	l.segments, l.wrong = true, t.Error
	var payloadBytes atomic.Int64
	l.out = func(p []byte) { payloadBytes.Add(int64(len(p) - ipv4HeaderSize - tcpHeaderSize)) }
	c := inspectionNativeTCP(t, l)
	c.stack.segmenter = l
	flow, view := inspectionNativeFlow(t, c)
	counter := new(testCounter)
	writer := buf.AttachWriterReceipt(&tunTCPWriter{writer: c, counter: counter}, flow)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("head")), buf.FromBytes(nil), buf.FromBytes([]byte("tail"))}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.retransmit(c.sndUna, c.sndNxt)
	c.mu.Unlock()
	totals, err := view.ReadTotals()
	if payloadBytes.Load() < 16 || counter.Value() != 8 || err != nil || totals.User.Downlink != 8 {
		t.Fatalf("segmenter decoded accounting: payload=%d counter=%d totals=%+v err=%v", payloadBytes.Load(), counter.Value(), totals, err)
	}
}

func TestInspectionTCPNativeZeroAcceptanceAfterClose(t *testing.T) {
	l := newLink()
	l.out = func([]byte) {}
	c := inspectionNativeTCP(t, l)
	flow, view := inspectionNativeFlow(t, c)
	counter := new(testCounter)
	writer := buf.AttachWriterReceipt(&tunTCPWriter{writer: c, counter: counter}, flow)
	c.Close()
	abandoned := inspectionOwnedPacket("abandoned")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{abandoned}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	totals, err := view.ReadTotals()
	if !abandoned.IsEmpty() || counter.Value() != 0 || err != nil || totals.User.Downlink != 0 {
		t.Fatalf("closed native write credited: counter=%d totals=%+v err=%v", counter.Value(), totals, err)
	}
}
