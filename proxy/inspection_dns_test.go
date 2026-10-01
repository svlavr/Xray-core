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

func TestInspectionSourceClaimAfterSniffReplay(t *testing.T) {
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
	root.Route(fs.OutboundRef{Tag: "dns", Serial: 1})
	go func() { _, _ = peer.Write(frame) }()
	cursor := link.Reader.(*buf.InspectionReader)
	sniff := buf.New()
	defer sniff.Release()
	if err := cursor.Cache(sniff, time.Second); err != nil || !strings.Contains(string(sniff.Bytes()), string(payload)) {
		t.Fatalf("sniff replay: %q %v", sniff.Bytes(), err)
	}
	claimed := ClaimObservedEndpoint(ctx, link.Reader, true)
	if claimed == nil || claimed.Exchange.Ref() != root.Ref() {
		t.Fatal("DNS did not claim the supplied endpoint")
	}
	message, err := dnsproto.NewTCPReader(link.Reader).ReadMessage()
	if err != nil || string(message.Bytes()) != string(payload) {
		t.Fatalf("decoded message: %v %v", message, err)
	}
	message.Release()
	root.Finish()
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != uint64(len(frame)) {
		t.Fatalf("sniffed source bytes were lost or replayed: %+v %v", page.Rows, err)
	}
}

func TestInspectionUDPStopBeforeRouteClaim(t *testing.T) {
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
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Flow.Uplink != uint64(len(payload)) {
		t.Fatalf("pre-claim exact stop lost pending input: %+v %v", page.Rows, err)
	}
}
