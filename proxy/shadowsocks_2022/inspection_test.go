package shadowsocks_2022

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	fs "github.com/xtls/xray-core/features/stats"
)

type inspectionTestConn struct {
	net.Conn
	reader io.Reader
	write  func([]byte) (int, error)
	close  func() error
}

func (c *inspectionTestConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *inspectionTestConn) Write(p []byte) (int, error) { return c.write(p) }
func (c *inspectionTestConn) Close() error {
	if c.close != nil {
		return c.close()
	}
	return nil
}

func inspectionFlow(t *testing.T, close func() error) (fs.Exchange, fs.FlowInspection) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, close)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	return flow, view
}

func inspectionLive(t *testing.T, view fs.FlowInspection) fs.FlowRecord {
	t.Helper()
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("live: %+v %v", live, err)
	}
	return live.Rows[0]
}

type inspectionCodecHandler struct{ run func(net.Conn) error }

func (h inspectionCodecHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	return h.run(conn)
}

func (inspectionCodecHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("unexpected UDP")
}
func (inspectionCodecHandler) NewError(context.Context, error) {}

func TestInspectionSS2022NativeCodecResults(t *testing.T) {
	const methodName = "2022-blake3-aes-128-gcm"
	const key = "MDEyMzQ1Njc4OWFiY2RlZg=="
	failure := errors.New("injected lower result")
	for _, test := range []struct {
		name           string
		warm           bool
		failAt         int
		fullError      bool
		payload, known int
	}{
		{"first-success", false, 0, false, 7, 7},
		{"first-partial-error", false, 1, false, 7, 0},
		{"first-full-wire-error", false, 1, true, 7, 0},
		{"later-chunk-error", true, 2, false, shadowaead_2022.MaxPacketSize + 1, shadowaead_2022.MaxPacketSize},
		{"later-full-wire-error", true, 2, true, shadowaead_2022.MaxPacketSize + 1, shadowaead_2022.MaxPacketSize},
	} {
		t.Run(test.name, func(t *testing.T) {
			method, err := shadowaead_2022.NewWithPassword(methodName, key, nil)
			if err != nil {
				t.Fatal(err)
			}
			var request bytes.Buffer
			client := method.DialEarlyConn(&inspectionTestConn{write: request.Write}, M.ParseSocksaddr("example.invalid:80"))
			if _, err := client.Write([]byte("initial")); err != nil {
				t.Fatal(err)
			}
			calls := 0
			armed := !test.warm
			transport := &inspectionTestConn{reader: bytes.NewReader(request.Bytes()), write: func(p []byte) (int, error) {
				if armed {
					calls++
					if calls == test.failAt {
						if test.fullError {
							return len(p), failure
						}
						return 1, failure
					}
				}
				return len(p), nil
			}}
			flow, view := inspectionFlow(t, nil)
			handler := inspectionCodecHandler{run: func(conn net.Conn) error {
				if test.warm {
					if _, err := conn.Write([]byte("warm")); err != nil {
						t.Fatal(err)
					}
					armed = true
				}
				observed := &inspectionConn{Conn: conn, receipt: flow}
				input := make([]byte, 32)
				if n, err := observed.Read(input); n != 7 || err != nil || string(input[:n]) != "initial" {
					t.Fatalf("retained request: %d %v", n, err)
				}
				n, err := observed.Write(bytes.Repeat([]byte("p"), test.payload))
				if n != test.known || (test.failAt == 0 && err != nil) || (test.failAt != 0 && !errors.Is(err, failure)) {
					t.Fatalf("native codec n=%d err=%v", n, err)
				}
				return nil
			}}
			service, err := shadowaead_2022.NewServiceWithPassword(methodName, key, 500, handler, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.NewConnection(context.Background(), transport, M.Metadata{}); err != nil {
				t.Fatal(err)
			}
			row := inspectionLive(t, view)
			if row.Uplink.Known != 7 || row.Downlink.Known != uint64(test.known) || row.Downlink.Incomplete != (test.failAt != 0) {
				t.Fatalf("decoded receipts: %+v", row)
			}
		})
	}
}

func TestInspectionSS2022ScalarPositiveError(t *testing.T) {
	for _, accepted := range []int{0, 2, 4} {
		flow, view := inspectionFlow(t, nil)
		conn := &inspectionConn{Conn: &inspectionTestConn{write: func([]byte) (int, error) { return accepted, io.ErrUnexpectedEOF }}, receipt: flow}
		if n, err := conn.Write([]byte("data")); n != accepted || err != io.ErrUnexpectedEOF {
			t.Fatalf("result: %d %v", n, err)
		}
		fact := inspectionLive(t, view).Downlink
		if fact.Known != uint64(accepted) || fact.Incomplete != (accepted < 4) {
			t.Fatalf("positive error: %+v", fact)
		}
	}
}

func TestInspectionSS2022CloseAliases(t *testing.T) {
	for _, firstErr := range []error{nil, io.ErrUnexpectedEOF} {
		var calls atomic.Int32
		endpoint := &inspectionEndpoint{Conn: &inspectionTestConn{close: func() error { calls.Add(1); return firstErr }}}
		var group sync.WaitGroup
		for range 16 {
			group.Add(1)
			go func() {
				defer group.Done()
				if err := endpoint.Close(); err != firstErr {
					t.Errorf("first close result lost: %v", err)
				}
			}()
		}
		group.Wait()
		if calls.Load() != 1 {
			t.Fatalf("physical closes: %d", calls.Load())
		}
	}
}

func TestInspectionSS2022CloseUsesTransportOwner(t *testing.T) {
	failure := errors.New("physical close failed")
	endpoint := &inspectionEndpoint{Conn: &inspectionTestConn{close: func() error { return failure }}}
	observed := &inspectionConn{
		Conn:     &inspectionTestConn{close: func() error { t.Fatal("close inspected mutable codec aliases"); return nil }},
		endpoint: endpoint,
	}
	if err := observed.Close(); err != failure {
		t.Fatalf("physical failure hidden: %v", err)
	}
}

type inspectionHalfConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *inspectionHalfConn) CloseWrite() error { c.writes.Add(1); return nil }

func TestInspectionSS2022HalfCloseAndReceiptBoundary(t *testing.T) {
	physical := new(inspectionHalfConn)
	observed := &inspectionConn{Conn: &inspectionEndpoint{Conn: physical}}
	if _, ok := C.Cast[N.WriteCloser](observed); !ok {
		t.Fatal("native half-close capability hidden")
	}
	if err := N.CloseWrite(observed); err != nil || physical.writes.Load() != 1 {
		t.Fatalf("half close: %v", err)
	}
	if N.UnwrapReader(observed) != observed || N.UnwrapWriter(observed) != observed {
		t.Fatal("copy can bypass decoded receipt")
	}
}

func TestInspectionSS2022PendingWrite(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	flow, view := inspectionFlow(t, func() error { return nil })
	conn := &inspectionConn{Conn: &inspectionTestConn{write: func(p []byte) (int, error) { close(started); <-release; return len(p), nil }}, receipt: flow}
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("late")); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	result, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
	if err != nil || result[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("stop: %+v %v", result, err)
	}
	flow.Finish()
	page, _ := view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 0 || page.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatalf("owner-end write snapshot: %+v", page)
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write did not finish")
	}
	page, _ = view.ReadTerminals(context.Background())
	if len(page.Rows) != 1 || page.Rows[0].Flow.Downlink.Known != 0 || page.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatalf("late receipt: %+v", page)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, total := range totals.Rows {
		known += total.Downlink.Known
	}
	if known != 4 {
		t.Fatalf("late receipt totals: %+v", totals)
	}
}
