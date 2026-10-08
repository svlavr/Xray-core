package udp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type lifecycleDispatcher struct {
	routing.Dispatcher
	dispatch func(context.Context, net.Destination) (*transport.Link, error)
}

func (d lifecycleDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.dispatch(ctx, dest)
}

func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UDP owner did not return")
	}
}

func TestUDPDispatcherReleasesUndispatchedPayload(t *testing.T) {
	for _, mode := range []string{"rejected", "closed", "missing-writer"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := pipe.New()
			t.Cleanup(reader.Interrupt)
			t.Cleanup(writer.Interrupt)
			var calls int
			d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
				calls++
				if mode == "rejected" {
					return nil, errors.New("rejected UDP ray")
				}
				return &transport.Link{Reader: reader}, nil
			}}, func(_ context.Context, packet *protocoludp.Packet) { packet.Payload.Release() })
			done := make(chan struct{})
			d.callClose = func() error { close(done); return nil }
			t.Cleanup(func() {
				d.RemoveRay()
				if mode == "missing-writer" {
					lifecycleWait(t, done)
				}
			})
			if mode == "closed" {
				d.RemoveRay()
			}
			payload := buf.New()
			payload.WriteString("caller transfers ownership")
			t.Cleanup(payload.Release)
			d.Dispatch(context.Background(), net.UDPDestination(net.LocalHostIP, 53), payload)
			if !payload.IsEmpty() {
				t.Fatal("dispatcher retained an untransferred packet")
			}
			if mode == "closed" && calls != 0 {
				t.Fatal("closed dispatcher admitted another ray")
			}
		})
	}
}

type lifecycleResultReader struct {
	mb  buf.MultiBuffer
	err error
}

func (r *lifecycleResultReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, r.err
}
