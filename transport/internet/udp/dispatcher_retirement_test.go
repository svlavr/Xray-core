package udp

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestUDPDispatcherCloseAndWaitJoinsInputOwner(t *testing.T) {
	reader, writer := pipe.New()
	called := make(chan struct{}, 1)
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		return &transport.Link{Reader: reader, Writer: writer}, nil
	}}, func(_ context.Context, packet *protocoludp.Packet) {
		packet.Payload.Release()
		called <- struct{}{}
	})
	payload := buf.New()
	payload.WriteString("query")
	d.Dispatch(context.Background(), net.UDPDestination(net.LocalHostIP, 53), payload)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("input owner did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.CloseAndWait(ctx); err != nil {
		t.Fatalf("close and wait: %v", err)
	}
	if err := d.CloseAndWait(ctx); err != nil {
		t.Fatalf("repeated close and wait: %v", err)
	}
}
