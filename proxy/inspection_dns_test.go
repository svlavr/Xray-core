package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	dnsproto "github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

func TestInspectionDeferredEndpointRawAndDecoded(t *testing.T) {
	for _, decoded := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "decoded"}[decoded], func(t *testing.T) {
			manager := new(appstats.Manager)
			view, err := manager.EnableInspection(fs.ObservationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			root := manager.Observation().PrepareTCP(fs.TrafficOriginUser, cnet.Destination{}, cnet.TCPDestination(cnet.LocalHostIP, 53), nil)
			root.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "dns", Serial: 1}})
			gate := &deferredEndpointReceipt{Exchange: root}
			gate.AddUplink(7)
			gate.AddDownlink(5)
			gate.MarkUplinkIncomplete()
			gate.SetEndReason(fs.EndReasonReadError)
			if decoded {
				if gate.selectDecoded() != root || gate.selectDecoded() != nil {
					t.Fatal("decoded claim was not one-shot")
				}
				gate.AddUplink(100)
				gate.AddDownlink(100)
				gate.MarkDownlinkIncomplete()
				gate.SetEndReason(fs.EndReasonWriteError)
				root.AddUplink(11)
				root.AddDownlink(13)
			} else {
				gate.BindRoute()
				gate.AddUplink(11)
				gate.AddDownlink(13)
				if gate.selectDecoded() != nil {
					t.Fatal("raw receipt was transferred after settlement")
				}
			}
			gate.Finish()
			page, err := view.ReadTerminals(context.Background())
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("terminal: %+v %v", page, err)
			}
			flow := page.Rows[0].Flow
			wantUp, wantDown := uint64(18), uint64(18)
			if decoded {
				wantUp, wantDown = 11, 13
			}
			if flow.Uplink.Known != wantUp || flow.Downlink.Known != wantDown || flow.Uplink.Incomplete != !decoded || page.Rows[0].Reason != map[bool]fs.EndReason{false: fs.EndReasonReadError, true: fs.EndReasonUnknown}[decoded] {
				t.Fatalf("deferred facts: %+v", page.Rows[0])
			}
		})
	}
}

func TestInspectionDecodedClaimAfterSniffReplay(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	payload := []byte("dns-message")
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	link := &transport.Link{Reader: buf.NewReader(local), Writer: buf.NewWriter(local)}
	ctx, finish := ObserveTCP(context.Background(), manager, local, cnet.TCPDestination(cnet.LocalHostIP, 53), link)
	defer finish()
	root := session.LogicalObservationFromContext(ctx).Exchange
	root.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "dns", Serial: 1}})
	go func() { _, _ = peer.Write(frame) }()
	cursor := link.Reader.(*buf.InspectionReader)
	sniff := buf.New()
	defer sniff.Release()
	if err := cursor.Cache(sniff, time.Second); err != nil || !strings.Contains(string(sniff.Bytes()), string(payload)) {
		t.Fatalf("sniff replay: %q %v", sniff.Bytes(), err)
	}
	decoded := ClaimDecodedEndpoint(ctx, link.Reader)
	if decoded == nil || decoded.Ref() != root.Ref() {
		t.Fatal("DNS did not claim the supplied endpoint")
	}
	message, err := dnsproto.NewTCPReader(link.Reader).ReadMessage()
	if err != nil || string(message.Bytes()) != string(payload) {
		t.Fatalf("decoded message: %v %v", message, err)
	}
	decoded.AddUplink(uint64(message.Len()))
	message.Release()
	root.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != uint64(len(payload)) || page.Rows[0].Flow.Uplink.Incomplete {
		t.Fatalf("sniffed DNS payload included framing: %+v %v", page.Rows, err)
	}
}

func TestInspectionDeferredUDPStopBeforeClaim(t *testing.T) {
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	payload := "pending UDP input"
	destination := cnet.UDPDestination(cnet.LocalHostIP, 53)
	link := &transport.Link{Reader: buf.NewReader(strings.NewReader(payload)), Writer: buf.NewWriter(local)}
	ctx, finish := ObserveUDP(context.Background(), manager, local, destination, link)
	defer finish()
	ref := session.LogicalObservationFromContext(ctx).Exchange.Ref()
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil || mb.Len() != int32(len(payload)) {
		t.Fatalf("pre-claim input: %d %v", mb.Len(), err)
	}
	buf.ReleaseMulti(mb)
	if _, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref}); err != nil {
		t.Fatal(err)
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink.Known != uint64(len(payload)) || page.Rows[0].Reason != fs.EndReasonLocalStop {
		t.Fatalf("pre-claim exact stop lost pending input: %+v %v", page.Rows, err)
	}
}
