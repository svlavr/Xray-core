package dokodemo

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

type inspectionPacketSocket struct{ net.PacketConn }

func (*inspectionPacketSocket) WriteTo([]byte, net.Addr) (int, error) { return 0, io.ErrClosedPipe }
func (*inspectionPacketSocket) Close() error                          { return nil }

func TestInspectionPacketWriterConcurrentClose(t *testing.T) {
	for range 8 {
		w := &PacketWriter{conns: make(map[net.Destination]net.PacketConn), back: &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: 1234}}
		var mb buf.MultiBuffer
		for i := range 32 {
			d := net.UDPDestination(net.LocalHostIP, net.Port(20000+i))
			w.conns[d] = new(inspectionPacketSocket)
			b := buf.FromBytes([]byte("packet"))
			b.UDP = &d
			mb = append(mb, b)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; w.WriteMultiBuffer(mb) }()
		go func() { defer wg.Done(); <-start; w.Close() }()
		close(start)
		wg.Wait()
	}
}

type inspectionResultSocket struct {
	net.PacketConn
	result           int
	err              error
	entered, release chan struct{}
	once             sync.Once
}

func (s *inspectionResultSocket) WriteTo([]byte, net.Addr) (int, error) {
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	return s.result, s.err
}

func (s *inspectionResultSocket) Close() error {
	if s.release != nil {
		s.once.Do(func() { close(s.release) })
	}
	return nil
}

func TestInspectionPacketWriterRawResults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		offered, n int
		err        error
		known      uint64
	}{
		{"full", 4, 4, nil, 4},
		{"prefix error", 4, 2, io.ErrClosedPipe, 2},
		{"short nil", 4, 2, nil, 2},
		{"full error", 4, 4, io.ErrClosedPipe, 4},
		{"empty", 0, 0, nil, 0},
		{"empty error", 0, 0, io.ErrClosedPipe, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, perDestination := range []bool{false, true} {
				manager := new(appstats.Manager)
				view, err := manager.EnableInspection(fs.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				defer manager.Close()
				flow := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
				flow.Route(fs.OutboundRef{Tag: "direct"})
				destination := net.UDPDestination(net.LocalHostIP, 53)
				socket := &inspectionResultSocket{result: tc.n, err: tc.err}
				native := NewPacketWriter(socket, &destination, 0, &net.UDPAddr{}).(*PacketWriter)
				defer native.Close()
				packet := buf.FromBytes(make([]byte, tc.offered))
				if perDestination {
					packet.UDP = &destination
				}
				err = native.WithWriterReceipt(flow).WriteMultiBuffer(buf.MultiBuffer{packet})
				if perDestination && err != nil || !perDestination && !errors.Is(err, tc.err) {
					t.Fatalf("native return changed: %v", err)
				}
				flow.Finish()
				page, err := view.ReadTerminals()
				if err != nil || len(page.Rows) != 1 {
					t.Fatalf("terminal: %+v %v", page, err)
				}
				fact := page.Rows[0].Flow.Downlink
				if fact != tc.known {
					t.Fatalf("destination=%t fact=%+v", perDestination, fact)
				}
			}
		})
	}
}

func TestInspectionPacketWriterCloseUnblocksAndRetires(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	flow := manager.Observation().Begin(net.Network_UDP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
	flow.Route(fs.OutboundRef{Tag: "direct"})
	destination := net.UDPDestination(net.LocalHostIP, 53)
	socket := &inspectionResultSocket{result: 2, err: io.ErrClosedPipe, entered: make(chan struct{}), release: make(chan struct{})}
	native := NewPacketWriter(socket, &destination, 0, &net.UDPAddr{}).(*PacketWriter)
	defer native.Close()
	done := make(chan error, 1)
	go func() {
		done <- native.WithWriterReceipt(flow).WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("test")), buf.FromBytes([]byte("tail")), buf.FromBytes(nil)})
	}()
	select {
	case <-socket.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	flow.Finish()
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Downlink != 0 {
		t.Fatalf("owner-end write snapshot: %+v %v", page, err)
	}
	closed := make(chan struct{})
	go func() { native.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		socket.Close()
		t.Fatal("Close blocked behind native write")
	}
	if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	page, err = view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal: %+v %v", page, err)
	}
	fact := page.Rows[0].Flow.Downlink
	if fact != 0 {
		t.Fatalf("late write mutated history: %+v", fact)
	}
	totals, _ := view.ReadTotals()
	var known uint64
	for _, total := range totals.Rows {
		known += total.Downlink
	}
	if known != 2 {
		t.Fatalf("late write totals: %+v", totals)
	}
	if _, err := native.packetConn(&destination); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed writer reopened socket: %v", err)
	}
}
