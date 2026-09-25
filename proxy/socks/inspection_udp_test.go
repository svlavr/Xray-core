package socks

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
)

type responseResultConn struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c responseResultConn) Write(p []byte) (int, error) { return c.write(p) }

func TestSOCKSUDPResponseReceipts(t *testing.T) {
	for _, mode := range []string{"full", "full-error", "partial-error", "zero-error", "oversized", "missing-header", "encode-error"} {
		t.Run(mode, func(t *testing.T) {
			manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
			view, _ := manager.EnableInspection(fs.ObservationOptions{})
			defer manager.Close()
			flow := manager.Observation().Begin(fs.FlowKindUDPAssociation, fs.TrafficOriginUser, cnet.Destination{}, cnet.Destination{}, nil)
			flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Serial: 1}})
			flow.BindRoute()
			ctx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: flow})
			request := &protocol.RequestHeader{Address: cnet.LocalHostIP, Port: 53}
			if mode == "encode-error" {
				request.Address = cnet.DomainAddress(strings.Repeat("d", 257))
			}
			if mode != "missing-header" {
				ctx = protocol.ContextWithRequestHeader(ctx, request)
			}
			payload := buf.New()
			payload.WriteString("logical payload")
			if mode == "oversized" {
				payload.Release()
				payload = buf.New()
				payload.Extend(buf.Size)
			}
			want := uint64(payload.Len())
			var calls int
			conn := responseResultConn{write: func(p []byte) (int, error) {
				calls++
				switch mode {
				case "full-error":
					return len(p), errors.New("error after full datagram")
				case "partial-error":
					return len(p) - 1, errors.New("short framed datagram")
				case "zero-error":
					return 0, errors.New("no accepted datagram")
				default:
					return len(p), nil
				}
			}}
			writeUDPResponse(ctx, conn, &protocoludp.Packet{Payload: payload})
			if !payload.IsEmpty() {
				t.Fatal("response did not release input")
			}
			flow.Finish()
			page, _ := view.ReadTerminals(context.Background())
			if len(page.Rows) != 1 {
				t.Fatal("missing response terminal")
			}
			fact := page.Rows[0].Flow.Downlink
			switch mode {
			case "full", "full-error":
				if fact.Known != want || fact.Incomplete {
					t.Fatalf("full datagram receipt: %+v", fact)
				}
			case "partial-error":
				if fact.Known != 0 || !fact.Incomplete {
					t.Fatalf("partial datagram receipt: %+v", fact)
				}
			default:
				if fact.Known != 0 || fact.Incomplete {
					t.Fatalf("drop receipt: %+v", fact)
				}
			}
			if (mode == "missing-header" || mode == "encode-error") && calls != 0 {
				t.Fatal("invalid encoding reached writer")
			}
		})
	}
}

type inspectionCloseConn struct {
	net.Conn
	calls atomic.Int32
}

func (c *inspectionCloseConn) Close() error { c.calls.Add(1); return nil }

type inspectionClosePacketConn struct {
	net.PacketConn
	calls atomic.Int32
}

func (c *inspectionClosePacketConn) Close() error { c.calls.Add(1); return nil }

func TestSOCKSTempUDPConnCloseIsIdempotent(t *testing.T) {
	tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
	conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
	conn.SetTimeout(time.Hour)
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if tcp.calls.Load() != 1 || udp.calls.Load() != 1 {
		t.Fatalf("recursive/concurrent close: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
	}
}

func TestSOCKSTempUDPConnTimeoutInitialization(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Nanosecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			for range 16 {
				tcp, udp := &inspectionCloseConn{}, &inspectionClosePacketConn{}
				conn := NewTempUDPConn(udp, tcp, &net.UDPAddr{})
				conn.SetTimeout(timeout)
				deadline := time.Now().Add(time.Second)
				for udp.calls.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				if tcp.calls.Load() != 1 || udp.calls.Load() != 1 {
					t.Fatalf("timeout/native cleanup: TCP=%d UDP=%d", tcp.calls.Load(), udp.calls.Load())
				}
			}
		})
	}
}
