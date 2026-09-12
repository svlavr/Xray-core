package udp_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestOneDispatchLinkCarriesChangingPacketDestinations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024))

	go func() {
		for {
			data, err := uplinkReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			err = downlinkWriter.WriteMultiBuffer(data)
			common.Must(err)
		}
	}()

	var count uint32
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&count, 1)
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	destinations := []net.Destination{
		net.UDPDestination(net.LocalHostIP, 53),
		net.UDPDestination(net.ParseAddress("127.0.0.2"), 5353),
		net.UDPDestination(net.DomainAddress("example.com"), 443),
	}

	var msgCount uint32
	sources := make(chan net.Destination, 6)
	dispatcher := NewDispatcher(td, func(ctx context.Context, packet *udp.Packet) {
		atomic.AddUint32(&msgCount, 1)
		sources <- packet.Source
	})
	defer dispatcher.CloseAndWait()

	for i := 0; i < 6; i++ {
		destination := destinations[i%len(destinations)]
		payload := buf.New()
		payload.WriteString("abcd")
		payload.UDP = &destination
		dispatcher.Dispatch(ctx, destination, payload)
	}

	for i := 0; i < 6; i++ {
		select {
		case source := <-sources:
			if source != destinations[i%len(destinations)] {
				t.Fatalf("packet %d source = %s, want %s", i, source, destinations[i%len(destinations)])
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out after %d UDP callbacks", i)
		}
	}
	cancel()

	if v := atomic.LoadUint32(&count); v != 1 {
		t.Error("count: ", v)
	}
	if v := atomic.LoadUint32(&msgCount); v != 6 {
		t.Error("msgCount: ", v)
	}
}

func TestDispatcherCloseAndWaitUnblocksInputAndRejectsLatePayload(t *testing.T) {
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	t.Cleanup(func() {
		common.Interrupt(downlinkWriter)
		common.Interrupt(uplinkReader)
	})
	dispatched := make(chan struct{}, 1)
	router := &TestDispatcher{OnDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		dispatched <- struct{}{}
		return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
	}}
	dispatcher := NewDispatcher(router, func(context.Context, *udp.Packet) {})
	destination := net.UDPDestination(net.LocalHostIP, 53)
	payload := buf.FromBytes([]byte("query"))
	payload.UDP = &destination
	dispatcher.Dispatch(context.Background(), destination, payload)
	<-dispatched
	closed := make(chan error, 1)
	go func() { closed <- dispatcher.CloseAndWait() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseAndWait did not join blocked handleInput")
	}
	late := buf.FromBytes([]byte("late"))
	late.UDP = &destination
	dispatcher.Dispatch(context.Background(), destination, late)
}

func TestDispatcherCloseCancelsOpeningOutsideStateLock(t *testing.T) {
	entered := make(chan struct{})
	router := &TestDispatcher{OnDispatch: func(ctx context.Context, _ net.Destination) (*transport.Link, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	dispatcher := NewDispatcher(router, func(context.Context, *udp.Packet) {})
	destination := net.UDPDestination(net.LocalHostIP, 53)
	dispatchDone := make(chan struct{})
	go func() {
		payload := buf.FromBytes([]byte("query"))
		payload.UDP = &destination
		dispatcher.Dispatch(context.Background(), destination, payload)
		close(dispatchDone)
	}()
	<-entered
	if err := dispatcher.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("CloseAndWait did not cancel and join opening Dispatch")
	}
}
