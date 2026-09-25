package shadowsocks

import (
	"bytes"
	"context"
	"errors"
	stdnet "net"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
)

func inspectionPacketRequest(t *testing.T) *protocol.RequestHeader {
	t.Helper()
	account, err := (&Account{CipherType: CipherType_AES_128_GCM, Password: "inspection-test-only"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.RequestHeader{Command: protocol.RequestCommandUDP, User: &protocol.MemoryUser{Account: account}, Address: net.LocalHostIP, Port: 53}
}

type inspectionResponseConn struct {
	stdnet.Conn
	write func([]byte) (int, error)
}

func (c inspectionResponseConn) Write(p []byte) (int, error) { return c.write(p) }

func TestInspectionShadowsocksUDPResponseMapping(t *testing.T) {
	for _, mode := range []string{"full-error", "short-nil", "oversized", "missing-header"} {
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
			ctx := session.ContextWithLogicalObservation(context.Background(), &session.LogicalObservation{Exchange: flow})
			if mode != "missing-header" {
				ctx = protocol.ContextWithRequestHeader(ctx, inspectionPacketRequest(t))
			}
			payload := buf.New()
			payload.WriteString("logical payload")
			if mode == "oversized" {
				payload.Clear()
				payload.Extend(buf.Size)
			}
			want := uint64(payload.Len())
			calls := 0
			conn := inspectionResponseConn{write: func(p []byte) (int, error) {
				calls++
				if mode == "full-error" {
					return len(p), errors.New("after complete encoded datagram")
				}
				return len(p) - 1, nil
			}}
			writeUDPResponse(ctx, conn, &protocoludp.Packet{Payload: payload})
			if !payload.IsEmpty() {
				t.Fatal("input payload was not released")
			}
			flow.Finish()
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("response terminal: %+v %v", page, err)
			}
			fact := page.Rows[0].Flow.Downlink
			switch mode {
			case "full-error":
				if calls != 1 || fact.Known != want || fact.Incomplete {
					t.Fatalf("accepted encrypted packet: %+v", fact)
				}
			case "short-nil":
				if calls != 1 || fact.Known != 0 || !fact.Incomplete {
					t.Fatalf("partial encrypted packet: %+v", fact)
				}
			default:
				if calls != 0 || fact.Known != 0 || fact.Incomplete {
					t.Fatalf("encoding drop: %+v, writes %d", fact, calls)
				}
			}
		})
	}
}

func TestInspectionShadowsocksUDPOversizedEncoding(t *testing.T) {
	for _, size := range []int{buf.Size, buf.Size - 16 - 7 - 8} {
		packet, err := EncodeUDPPacket(inspectionPacketRequest(t), make([]byte, size))
		if packet != nil {
			packet.Release()
			t.Fatal("oversized packet was encoded")
		}
		if err == nil {
			t.Fatal("oversized packet did not report an error")
		}
	}
	request := inspectionPacketRequest(t)
	payload := bytes.Repeat([]byte{0x19}, buf.Size-16-7-16)
	packet, err := EncodeUDPPacket(request, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	if packet.Len() != buf.Size {
		t.Fatalf("boundary packet length: %d", packet.Len())
	}
	validator := new(Validator)
	if err := validator.Add(request.User); err != nil {
		t.Fatal(err)
	}
	decoded, body, err := DecodeUDPPacket(validator, packet)
	if err != nil || decoded.Destination() != request.Destination() || !bytes.Equal(body.Bytes(), payload) {
		t.Fatalf("maximum valid packet changed: %v", err)
	}
}
