package outbound

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type inspectionFailDialer struct {
	internet.Dialer
	check func()
}

func (d inspectionFailDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	d.check()
	return nil, errors.New("injected dial failure")
}

func TestInspectionVMessSpecialCommandsStayUnclaimedBeforeDial(t *testing.T) {
	for _, target := range []net.Destination{
		net.TCPDestination(net.DomainAddress("v1.mux.cool"), 0),
		net.UDPDestination(net.LocalHostIP, 80),
	} {
		t.Run(target.String(), func(t *testing.T) {
			// A nil Exchange panics if the ordinary-only claim incorrectly
			// reaches this inherited observation for MUX or cone XUDP.
			observation := &session.LogicalObservation{}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
			ctx = session.ContextWithLogicalObservation(ctx, observation)
			h := &Handler{server: &protocol.ServerSpec{Destination: net.TCPDestination(net.LocalHostIP, 1)}, cone: true}
			calls := 0
			dialer := inspectionFailDialer{check: func() {
				calls++
			}}
			if err := h.Process(ctx, &transport.Link{Reader: &buf.InspectionReader{}}, dialer); err == nil || calls == 0 {
				t.Fatalf("native failed dial was not exercised: calls=%d err=%v", calls, err)
			}
		})
	}
}
