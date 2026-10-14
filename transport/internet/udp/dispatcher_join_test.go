package udp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestDNSUDPDispatcherCloseJoinsNativeReader(t *testing.T) {
	reader, writer := pipe.New()
	t.Cleanup(reader.Interrupt)
	t.Cleanup(writer.Interrupt)
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	returned := make(chan struct{})
	dispatches := 0
	d := NewDispatcher(lifecycleDispatcher{dispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		dispatches++
		return &transport.Link{Reader: reader, Writer: writer}, nil
	}}, func(ctx context.Context, packet *protocoludp.Packet) {
		packet.Payload.Release()
		entered <- ctx
		<-release
		close(returned)
	})
	destination := net.UDPDestination(net.LocalHostIP, 53)
	request := buf.New()
	request.WriteString("request")
	t.Cleanup(request.Release)
	d.Dispatch(internet.ContextWithMUTransport(context.Background()), destination, request)
	var ray context.Context
	select {
	case ray = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native callback did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case <-ray.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel native reader")
	}
	select {
	case err := <-closed:
		t.Fatalf("close returned before native reader: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not join released native reader")
	}
	select {
	case <-returned:
	default:
		t.Fatal("close preceded callback completion")
	}
	if !request.IsEmpty() {
		t.Fatal("joined callback retained its managed payload")
	}
	// FromBytes is unmanaged: Release intentionally leaves its bytes intact.
	// Use a managed packet to witness actual rejected-payload release.
	late := buf.New()
	late.WriteString("late")
	t.Cleanup(late.Release)
	d.Dispatch(context.Background(), destination, late)
	if dispatches != 1 {
		t.Fatal("closed dispatcher admitted another native ray")
	}
	if !late.IsEmpty() {
		t.Fatal("closed dispatcher retained late managed payload")
	}
}
