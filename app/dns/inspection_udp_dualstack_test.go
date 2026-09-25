package dns

import (
	"context"
	"testing"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	fdns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type immediateObservedDispatcher struct {
	routing.Dispatcher
	server *ClassicNameServer
	calls  int
	types  []uint16
}

func (d *immediateObservedDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.calls++
	return &transport.Link{Reader: &dnsUDPBlackholeReader{done: make(chan struct{})}, Writer: &immediateObservedWriter{dispatcher: d, ctx: ctx}}, nil
}

type immediateObservedWriter struct {
	dispatcher *immediateObservedDispatcher
	ctx        context.Context
}

func (w *immediateObservedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	request := new(mdns.Msg)
	if err := request.Unpack(mb[0].Bytes()); err != nil {
		return err
	}
	w.dispatcher.types = append(w.dispatcher.types, request.Question[0].Qtype)
	response := new(mdns.Msg)
	response.SetReply(request)
	wire, err := response.Pack()
	if err != nil {
		return err
	}
	server := w.dispatcher.server
	server.RLock()
	owner := server.requests[request.Id].owner
	server.RUnlock()
	// Complete the first response before sendQuery can advance to its next item.
	// The native reader is still separately owned by the same dispatcher ray.
	server.handleResponse(w.ctx, &udp_proto.Packet{Payload: buf.FromBytes(wire)}, owner)
	return nil
}
func (*immediateObservedWriter) Interrupt() {}

func TestObservedUDPImmediateAResponsePreservesAAAAOnSameRay(t *testing.T) {
	instance, _, _ := newDNSTCPInspectionCore(t)
	dispatcher := new(immediateObservedDispatcher)
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), dispatcher, true, false, 0, nil)
	dispatcher.server = server
	t.Cleanup(func() { _ = server.Close() })
	ctx := session.ContextWithTrafficOrigin(dnsTCPTestContext(instance), session.TrafficOriginInternal)
	server.sendQuery(ctx, make(chan error, 2), "fast.test.", fdns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if len(dispatcher.types) != 2 || dispatcher.types[0] != mdns.TypeA || dispatcher.types[1] != mdns.TypeAAAA || dispatcher.calls != 1 {
		t.Fatalf("sent types=%v physical rays=%d", dispatcher.types, dispatcher.calls)
	}
}
