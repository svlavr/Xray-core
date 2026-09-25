package core_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func inspectionUDPInbound(t *testing.T, destination cnet.Destination, enabled, resolveTarget bool) (*core.Instance, fs.FlowInspection, *net.UDPAddr) {
	t.Helper()
	outbound := inspectionFreedom("direct")
	return inspectionUDPInboundThrough(t, destination, enabled, resolveTarget, outbound)
}

func inspectionUDPInboundThrough(t *testing.T, destination cnet.Destination, enabled, resolveTarget bool, outbound *core.OutboundHandlerConfig) (*core.Instance, fs.FlowInspection, *net.UDPAddr) {
	t.Helper()
	port := udp.PickPort()
	if resolveTarget {
		outbound.SenderSettings = serial.ToTypedMessage(&proxyman.SenderConfig{TargetStrategy: internet.DomainStrategy_FORCE_IP4})
	}
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  cnet.NewIPOrDomain(destination.Address),
				RewritePort:     uint32(destination.Port),
				AllowedNetworks: []cnet.Network{cnet.Network_UDP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{outbound},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	var view fs.FlowInspection
	if enabled {
		view, err = core.EnableFlowInspection(instance, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	if view != nil {
		t.Cleanup(func() {
			live, err := view.ReadLive(context.Background())
			if err != nil || len(live.Rows) == 0 {
				return
			}
			refs := make([]fs.FlowRef, 0, len(live.Rows))
			for _, row := range live.Rows {
				refs = append(refs, row.Ref)
			}
			if _, err := view.CloseFlows(context.Background(), refs); err != nil {
				t.Errorf("close live UDP associations: %v", err)
			}
		})
	}
	return instance, view, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
}

func inspectionUDPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func inspectionUDPExchange(t *testing.T, conn *net.UDPConn, inbound *net.UDPAddr, payload []byte, mask byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.WriteToUDP(payload, inbound); err != nil || n != len(payload) {
		t.Fatalf("write supplied UDP payload: %d/%d %v", n, len(payload), err)
	}
	response := make([]byte, len(payload)+1)
	n, source, err := conn.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	if source.Port != inbound.Port || !source.IP.Equal(inbound.IP) {
		t.Fatalf("response source: got %v want %v", source, inbound)
	}
	if want := transformOutboundStatsPayload(payload, mask); !bytes.Equal(response[:n], want) {
		t.Fatalf("response %x want %x", response[:n], want)
	}
}

func inspectionUDPRow(t *testing.T, view fs.FlowInspection, source cnet.Port, destination cnet.Destination, uplink, downlink uint64) fs.FlowRecord {
	t.Helper()
	var found fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range live.Rows {
			if row.Source.Port != source {
				continue
			}
			if row.Uplink.Known != uplink || row.Downlink.Known != downlink || row.Uplink.Incomplete || row.Downlink.Incomplete {
				return false
			}
			if row.Kind != fs.FlowKindUDPAssociation || row.Origin != fs.TrafficOriginUser || row.InitialDestination != destination || row.AccountingRoute.Outbound.Serial == 0 || row.AccountingRoute.Outbound.Tag != "direct" || row.Uplink.Incomplete || row.Downlink.Incomplete || len(row.Destinations) != 1 || row.Destinations[0] != destination {
				t.Fatalf("UDP logical facts: %+v", row)
			}
			found = row
			return true
		}
		return false
	})
	return found
}

func TestFlowInspectionSuppliedUDPLifecycle(t *testing.T) {
	const mask = byte(0x6d)
	destination := startOutboundStatsUDPServer(t, mask)
	_, view, inbound := inspectionUDPInbound(t, destination, true, false)
	first := inspectionUDPClient(t)
	sibling := inspectionUDPClient(t)
	firstPayload := []byte("first supplied UDP association")
	siblingPayload := []byte("sibling supplied UDP association")
	inspectionUDPExchange(t, first, inbound, firstPayload, mask)
	inspectionUDPExchange(t, sibling, inbound, siblingPayload, mask)

	firstPort := cnet.Port(first.LocalAddr().(*net.UDPAddr).Port)
	siblingPort := cnet.Port(sibling.LocalAddr().(*net.UDPAddr).Port)
	selected := inspectionUDPRow(t, view, firstPort, destination, uint64(len(firstPayload)), uint64(len(firstPayload)))
	_ = inspectionUDPRow(t, view, siblingPort, destination, uint64(len(siblingPayload)), uint64(len(siblingPayload)))
	if selected.AccountingRoute.Effective != destination {
		t.Fatalf("effective target: got %v want %v", selected.AccountingRoute.Effective, destination)
	}
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("exact UDP stop: %+v %v", outcomes, err)
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Rows {
			if row.Flow.Ref == selected.Ref {
				if row.Reason != fs.EndReasonLocalStop {
					t.Fatalf("stopped UDP terminal: %+v", row)
				}
				return true
			}
		}
		return false
	})

	replacementPayload := []byte("same source after exact stop")
	inspectionUDPExchange(t, first, inbound, replacementPayload, mask)
	replacement := inspectionUDPRow(t, view, firstPort, destination, uint64(len(replacementPayload)), uint64(len(replacementPayload)))
	if replacement.Ref == selected.Ref {
		t.Fatal("same-source datagram reused the stopped association")
	}
	outcomes, err = view.CloseFlows(context.Background(), []fs.FlowRef{selected.Ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAlreadyEnded {
		t.Fatalf("stale ref affected replacement: %+v %v", outcomes, err)
	}
	siblingExtra := []byte("sibling after exact stop")
	inspectionUDPExchange(t, sibling, inbound, siblingExtra, mask)
	_ = inspectionUDPRow(t, view, siblingPort, destination, uint64(len(siblingPayload)+len(siblingExtra)), uint64(len(siblingPayload)+len(siblingExtra)))

	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 2 {
		t.Fatalf("live replacement/sibling: %+v %v", live, err)
	}
	refs := []fs.FlowRef{live.Rows[0].Ref, live.Rows[1].Ref}
	outcomes, err = view.CloseFlows(context.Background(), refs)
	if err != nil || len(outcomes) != 2 || outcomes[0].Code != fs.CloseCodeAccepted || outcomes[1].Code != fs.CloseCodeAccepted {
		t.Fatalf("cleanup UDP associations: %+v %v", outcomes, err)
	}
	inspectionWait(t, func() bool {
		live, _ := view.ReadLive(context.Background())
		return len(live.Rows) == 0
	})
	want := uint64(len(firstPayload) + len(siblingPayload) + len(replacementPayload) + len(siblingExtra))
	inspectionTCPTotals(t, view, want)
}

func TestFlowInspectionSuppliedUDPResolvedTarget(t *testing.T) {
	const mask = byte(0x42)
	server := startOutboundStatsUDPServer(t, mask)
	requested := cnet.UDPDestination(cnet.DomainAddress("localhost"), server.Port)
	_, view, inbound := inspectionUDPInbound(t, requested, true, true)
	client := inspectionUDPClient(t)
	payload := []byte("resolved supplied UDP target")
	inspectionUDPExchange(t, client, inbound, payload, mask)
	row := inspectionUDPRow(t, view, cnet.Port(client.LocalAddr().(*net.UDPAddr).Port), requested, uint64(len(payload)), uint64(len(payload)))
	if !row.AccountingRoute.Effective.Address.Family().IsIP() || row.AccountingRoute.Effective.Port != requested.Port {
		t.Fatalf("resolved effective target: %+v", row.AccountingRoute)
	}
	out, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
	if err != nil || len(out) != 1 || out[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("close resolved association: %+v %v", out, err)
	}
}

func TestFlowInspectionSuppliedUDPDisabled(t *testing.T) {
	const mask = byte(0x31)
	destination := startOutboundStatsUDPServer(t, mask)
	instance, _, inbound := inspectionUDPInbound(t, destination, false, false)
	client := inspectionUDPClient(t)
	inspectionUDPExchange(t, client, inbound, []byte("disabled UDP inspection"), mask)
	if provider := instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider); provider.Observation() != nil {
		t.Fatal("disabled UDP traffic allocated inspection state")
	}
}

// The decoded endpoint is supplied directly so a single input batch can carry
// two destinations. The actual dispatcher, Freedom packet owner and two local
// UDP servers execute the batch; the endpoint's unencoded Write uses net.Pipe.
type inspectionUDPBatchEndpoint struct {
	net.Conn
	input *pipe.Reader
}

func (c *inspectionUDPBatchEndpoint) Close() error {
	c.input.Interrupt()
	return c.Conn.Close()
}

func TestFlowInspectionSuppliedUDPMultipleDestinations(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	inspectionUDPBatchThrough(t, instance, view, "direct")
}

func inspectionUDPBatchThrough(t *testing.T, instance *core.Instance, view fs.FlowInspection, outboundTag string) {
	t.Helper()
	destinations := []cnet.Destination{
		startOutboundStatsUDPServer(t, 0x31),
		startOutboundStatsUDPServer(t, 0x72),
	}
	input, send := pipe.New()
	local, peer := net.Pipe()
	endpoint := &inspectionUDPBatchEndpoint{Conn: local, input: input}
	t.Cleanup(func() { endpoint.Close(); peer.Close() })
	link := &transport.Link{Reader: input, Writer: &buf.SequentialWriter{Writer: endpoint}}
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	ctx, finish := proxy.ObserveUDP(ctx, instance.GetFeature(fs.ManagerType()).(fs.Manager), endpoint, destinations[0], link)
	if finish == nil {
		t.Fatal("UDP endpoint was not admitted")
	}
	dispatcher := instance.GetFeature(frouting.DispatcherType()).(frouting.Dispatcher)
	done := make(chan error, 1)
	go func() {
		err := dispatcher.DispatchLink(ctx, destinations[0], link)
		finish()
		done <- err
	}()
	payload := []byte("one native multi-destination UDP batch")
	first, second := buf.FromBytes(payload), buf.FromBytes(payload)
	first.UDP, second.UDP = &destinations[0], &destinations[1]
	if err := send.WriteMultiBuffer(buf.MultiBuffer{first, second}); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 2*len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	a := transformOutboundStatsPayload(payload, 0x31)
	b := transformOutboundStatsPayload(payload, 0x72)
	if !(bytes.Equal(got[:len(payload)], a) && bytes.Equal(got[len(payload):], b)) &&
		!(bytes.Equal(got[:len(payload)], b) && bytes.Equal(got[len(payload):], a)) {
		t.Fatal("batch destinations or packet payloads changed")
	}
	var row fs.FlowRecord
	inspectionWait(t, func() bool {
		live, err := view.ReadLive(context.Background())
		if err != nil || len(live.Rows) != 1 {
			return false
		}
		row = live.Rows[0]
		return row.Uplink.Known == uint64(len(got)) && row.Downlink.Known == uint64(len(got))
	})
	if row.Kind != fs.FlowKindUDPAssociation || row.InitialDestination != destinations[0] || len(row.Destinations) != 2 ||
		row.Destinations[0] != destinations[0] || row.Destinations[1] != destinations[1] || len(row.Routes) != 1 || row.AccountingRoute.Outbound.Tag != outboundTag {
		t.Fatalf("batch association facts: %+v", row)
	}
	totals, err := view.ReadTotals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var up, down uint64
	for _, total := range totals.Rows {
		if total.Uplink.Known != 0 || total.Downlink.Known != 0 {
			if total.Outbound.Tag != outboundTag || total.Outbound.Serial == 0 || total.Origin != fs.TrafficOriginUser || total.Uplink.Incomplete || total.Downlink.Incomplete {
				t.Fatalf("batch total attribution: %+v", total)
			}
			up += total.Uplink.Known
			down += total.Downlink.Known
		}
	}
	if up != uint64(len(got)) || down != uint64(len(got)) {
		t.Fatalf("batch totals: %d/%d want %d", up, down, len(got))
	}
	results, err := view.CloseFlows(context.Background(), []fs.FlowRef{row.Ref})
	if err != nil || len(results) != 1 || results[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("batch close: %+v %v", results, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("batch endpoint did not finish")
	}
	inspectionWait(t, func() bool {
		page, err := view.ReadTerminals(context.Background())
		return err == nil && len(page.Rows) == 1 && page.Rows[0].Flow.Uplink.Known == uint64(len(got)) && page.Rows[0].Flow.Downlink.Known == uint64(len(got))
	})
}
