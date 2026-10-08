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

func TestInspectionVMessCarrierStaysUnclaimedBeforeDial(t *testing.T) {
	target := net.TCPDestination(net.DomainAddress("v1.mux.cool"), 0)
	// A nil Exchange panics if the carrier incorrectly claims inherited facts.
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	ctx = session.ContextWithLogicalObservation(ctx, &session.LogicalObservation{})
	h := &Handler{server: &protocol.ServerSpec{Destination: net.TCPDestination(net.LocalHostIP, 1)}, cone: true}
	calls := 0
	dialer := inspectionFailDialer{check: func() { calls++ }}
	if err := h.Process(ctx, &transport.Link{Reader: &buf.InspectionReader{}}, dialer); err == nil || calls == 0 {
		t.Fatalf("native failed dial was not exercised: calls=%d err=%v", calls, err)
	}
}
