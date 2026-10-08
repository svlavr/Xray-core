package udp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestUDPDispatcherRemoveRayCancelsBlockedCallback(t *testing.T) {
	reader, writer := pipe.New()
	t.Cleanup(reader.Interrupt)
	t.Cleanup(writer.Interrupt)
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	callbackReturned := make(chan struct{})
	rayReturned := make(chan struct{})
	var dispatches atomic.Int32
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		dispatches.Add(1)
		return &transport.Link{Reader: reader, Writer: writer}, nil
	}}, func(ctx context.Context, packet *protocoludp.Packet) {
		packet.Payload.Release()
		entered <- ctx
		<-release
		close(callbackReturned)
	})
	d.callClose = func() error { close(rayReturned); return nil }
	destination := net.UDPDestination(net.LocalHostIP, 53)
	first := buf.New()
	first.WriteString("first")
	d.Dispatch(context.Background(), destination, first)
	var rayCtx context.Context
	select {
	case rayCtx = <-entered:
	case <-time.After(time.Second):
		t.Fatal("native input callback did not start")
	}
	queued := buf.New()
	queued.WriteString("queued")
	d.Dispatch(context.Background(), destination, queued)
	removed := make(chan struct{})
	go func() { d.RemoveRay(); close(removed) }()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("RemoveRay waited for the blocked callback")
	}
	select {
	case <-rayCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("RemoveRay did not cancel the native ray")
	}
	select {
	case <-callbackReturned:
		t.Fatal("blocked callback returned before release")
	default:
	}
	rejected := buf.New()
	rejected.WriteString("after-close")
	d.Dispatch(context.Background(), destination, rejected)
	if dispatches.Load() != 1 || !rejected.IsEmpty() {
		t.Fatal("closed dispatcher admitted a ray or retained a rejected packet")
	}
	if !queued.IsEmpty() {
		t.Fatal("native pipe retained the queued packet after interruption")
	}
	close(release)
	select {
	case <-callbackReturned:
	case <-time.After(time.Second):
		t.Fatal("released callback did not return")
	}
	select {
	case <-rayReturned:
	case <-time.After(time.Second):
		t.Fatal("native input owner did not retire")
	}
}
