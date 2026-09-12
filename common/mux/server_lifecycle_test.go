package mux

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newLifecycleLinkPair() (*transport.Link, *transport.Link) {
	options := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(options)
	downlinkReader, downlinkWriter := pipe.New(options)
	return &transport.Link{Reader: uplinkReader, Writer: downlinkWriter},
		&transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
}

type lifecycleTestDispatcher struct {
	onDispatch func(context.Context, net.Destination) (*transport.Link, error)
}

func (d *lifecycleTestDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	return d.onDispatch(ctx, destination)
}

func (*lifecycleTestDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (*lifecycleTestDispatcher) Start() error { return nil }
func (*lifecycleTestDispatcher) Close() error { return nil }
func (*lifecycleTestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestServerWorkerCloseAndWaitJoinsSessionHandler(t *testing.T) {
	websiteUplink, websiteDownlink := newLifecycleLinkPair()
	defer common.Interrupt(websiteUplink.Reader)
	defer common.Interrupt(websiteUplink.Writer)
	defer common.Interrupt(websiteDownlink.Reader)
	defer common.Interrupt(websiteDownlink.Writer)

	dispatched := make(chan struct{})
	dispatcher := &lifecycleTestDispatcher{onDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		close(dispatched)
		return websiteDownlink, nil
	}}
	serverLink, clientLink := newLifecycleLinkPair()
	worker, err := NewServerWorker(context.Background(), dispatcher, serverLink)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientWorker(*clientLink, ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	requestLink, requestPeer := newLifecycleLinkPair()
	defer common.Interrupt(requestLink.Reader)
	defer common.Interrupt(requestLink.Writer)
	defer common.Interrupt(requestPeer.Reader)
	defer common.Interrupt(requestPeer.Writer)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.test"), 443),
	}})
	if !client.Dispatch(ctx, requestLink) {
		t.Fatal("client dispatch failed")
	}
	if err := requestPeer.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("server session was not dispatched")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- worker.CloseAndWait() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServerWorker CloseAndWait did not join session handler")
	}
	if !worker.Closed() {
		t.Fatal("ServerWorker did not remain closed after receipt")
	}
}

func TestServerCloseJoinsDispatchWorker(t *testing.T) {
	websiteUplink, websiteDownlink := newLifecycleLinkPair()
	defer common.Interrupt(websiteUplink.Reader)
	defer common.Interrupt(websiteUplink.Writer)
	defer common.Interrupt(websiteDownlink.Reader)
	defer common.Interrupt(websiteDownlink.Writer)

	dispatched := make(chan struct{})
	dispatcher := &lifecycleTestDispatcher{onDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
		close(dispatched)
		return websiteDownlink, nil
	}}
	server := &Server{
		dispatcher: dispatcher,
		workers:    make(map[*ServerWorker]struct{}),
		closeDone:  make(chan struct{}),
	}
	clientLink, err := server.Dispatch(context.Background(), net.TCPDestination(muxCoolAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientWorker(*clientLink, ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	requestLink, requestPeer := newLifecycleLinkPair()
	defer common.Interrupt(requestLink.Reader)
	defer common.Interrupt(requestLink.Writer)
	defer common.Interrupt(requestPeer.Reader)
	defer common.Interrupt(requestPeer.Writer)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.test"), 443),
	}})
	if !client.Dispatch(ctx, requestLink) {
		t.Fatal("client dispatch failed")
	}
	if err := requestPeer.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("server session was not dispatched")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close did not join Dispatch-created worker")
	}
	server.mu.Lock()
	remaining := len(server.workers)
	sealed := server.sealed
	server.mu.Unlock()
	if !sealed || remaining != 0 {
		t.Fatalf("server close state: sealed=%v workers=%d", sealed, remaining)
	}
	if _, err := server.Dispatch(context.Background(), net.TCPDestination(muxCoolAddress, 0)); err == nil {
		t.Fatal("closed server admitted a new mux worker")
	}
}

func TestServerCloseRacesWorkerConstruction(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		dispatcher := &lifecycleTestDispatcher{onDispatch: func(context.Context, net.Destination) (*transport.Link, error) {
			link, peer := newLifecycleLinkPair()
			common.Interrupt(peer.Reader)
			common.Interrupt(peer.Writer)
			return link, nil
		}}
		server := &Server{
			dispatcher: dispatcher,
			workers:    make(map[*ServerWorker]struct{}),
			closeDone:  make(chan struct{}),
		}
		start := make(chan struct{})
		dispatchDone := make(chan struct{})
		go func() {
			defer close(dispatchDone)
			<-start
			link, _ := server.Dispatch(context.Background(), net.TCPDestination(muxCoolAddress, 0))
			if link != nil {
				common.Interrupt(link.Reader)
				common.Interrupt(link.Writer)
			}
		}()
		closeDone := make(chan struct{})
		go func() {
			defer close(closeDone)
			<-start
			_ = server.Close()
		}()
		close(start)
		select {
		case <-dispatchDone:
		case <-time.After(time.Second):
			t.Fatal("Dispatch did not finish")
		}
		select {
		case <-closeDone:
		case <-time.After(time.Second):
			t.Fatal("Close did not finish")
		}
		server.mu.Lock()
		remaining := len(server.workers)
		sealed := server.sealed
		server.mu.Unlock()
		if !sealed || remaining != 0 {
			t.Fatalf("iteration %d: sealed=%v workers=%d", iteration, sealed, remaining)
		}
	}
}
