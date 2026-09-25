package trojan

import (
	"bytes"
	"context"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type inspectionPacketWrite func([]byte) (int, error)

func (f inspectionPacketWrite) Write(p []byte) (int, error) { return f(p) }

func TestInspectionTrojanPacketWriteResults(t *testing.T) {
	for _, mode := range []string{"full-error", "second-short-nil", "encode-error"} {
		t.Run(mode, func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close() })
			flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
			flow.BindRoute()
			calls := 0
			writer := &PacketWriter{Target: net.UDPDestination(net.LocalHostIP, 53), Writer: inspectionPacketWrite(func(p []byte) (int, error) {
				calls++
				if mode == "full-error" {
					return len(p), errors.New("after complete packet")
				}
				if calls == 2 {
					return len(p) - 1, nil
				}
				return len(p), nil
			})}
			first := buf.New()
			first.WriteString("first")
			mb := buf.MultiBuffer{first}
			if mode == "encode-error" {
				first.Clear()
				first.Extend(buf.Size)
			}
			if mode == "second-short-nil" {
				second := buf.New()
				second.WriteString("second")
				mb = append(mb, second)
			}
			err = writer.writeMultiBuffer(mb, flow)
			if (mode == "second-short-nil") != (err == nil) {
				t.Fatalf("native error behavior changed: %v", err)
			}
			for _, b := range mb {
				if !b.IsEmpty() {
					t.Fatal("packet buffer was not released")
				}
			}
			flow.Finish()
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("packet terminal: %+v %v", page, err)
			}
			fact := page.Rows[0].Flow.Downlink
			switch mode {
			case "full-error":
				if calls != 1 || fact.Known != 5 || fact.Incomplete {
					t.Fatalf("complete frame plus error: %+v", fact)
				}
			case "second-short-nil":
				if calls != 2 || fact.Known != 5 || !fact.Incomplete {
					t.Fatalf("completed frame before partial: %+v", fact)
				}
			default:
				if calls != 0 || fact.Known != 0 || fact.Incomplete {
					t.Fatalf("encoding drop: %+v", fact)
				}
			}
		})
	}
}

type inspectionLatePacketReader struct {
	first   *bytes.Reader
	blocked chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *inspectionLatePacketReader) Read(p []byte) (int, error) {
	if r.first.Len() != 0 {
		return r.first.Read(p)
	}
	r.once.Do(func() { close(r.blocked) })
	<-r.release
	return 0, io.EOF
}

type inspectionRejectPacketDispatcher struct{ routing.Dispatcher }

func (inspectionRejectPacketDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errors.New("test route rejection")
}

func TestInspectionTrojanUDPLateRequestCompletion(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{}})
	conn, peer := stdnet.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	var wire bytes.Buffer
	packetWriter := &PacketWriter{Writer: &wire, Target: net.UDPDestination(net.LocalHostIP, 53)}
	payload := buf.New()
	payload.WriteString("admitted request")
	if err := packetWriter.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	reader := &inspectionLatePacketReader{first: bytes.NewReader(wire.Bytes()), blocked: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(reader.release) }) })
	server := &Server{statsManager: manager, cone: true}
	policy := policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Hour, UplinkOnly: time.Hour, DownlinkOnly: time.Hour}}
	returned := make(chan error, 1)
	go func() {
		returned <- server.handleUDPPayload(ctx, policy, conn, &PacketReader{Reader: reader}, packetWriter, inspectionRejectPacketDispatcher{})
	}()
	select {
	case <-reader.blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach its pending read")
	}
	cancel()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("native task.Run did not return on cancellation")
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 0 {
		t.Fatalf("parent return fabricated completion: %+v %v", page, err)
	}
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 || live.Rows[0].Uplink.Known != uint64(len("admitted request")) {
		t.Fatalf("late request lost admission: %+v %v", live, err)
	}
	totals, _ := view.ReadTotals(context.Background())
	var known uint64
	for _, total := range totals.Rows {
		known += total.Uplink.Known
	}
	if known != uint64(len("admitted request")) {
		t.Fatalf("late request total: %+v", totals)
	}
	releaseOnce.Do(func() { close(reader.release) })
	deadline := time.Now().Add(3 * time.Second)
	for {
		page, err = view.ReadTerminals(context.Background())
		if err == nil && len(page.Rows) == 1 && page.Rows[0].Flow.Uplink.Known == uint64(len("admitted request")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("request exit did not finish: %+v %v", page, err)
		}
		time.Sleep(time.Millisecond)
	}
}
