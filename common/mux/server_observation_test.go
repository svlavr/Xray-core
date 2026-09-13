package mux

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type ordinaryObservationDispatcher struct {
	routing.Dispatcher
	ordinary int
}

func (d *ordinaryObservationDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	d.ordinary++
	return nil
}

type userObservationDispatcher struct {
	ordinaryObservationDispatcher
	user int
}

func (d *userObservationDispatcher) DispatchUserLink(context.Context, net.Destination, *transport.Link) error {
	d.user++
	return nil
}

func TestUserDispatchPreservesCarrierHandling(t *testing.T) {
	d := new(userObservationDispatcher)
	s := &Server{dispatcher: d}
	link := func() *transport.Link {
		return &transport.Link{Reader: buf.NewReader(strings.NewReader("")), Writer: buf.Discard}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.DispatchUserLink(ctx, net.TCPDestination(net.LocalHostIP, 80), link()); err != nil {
		t.Fatal(err)
	}
	if d.user != 1 || d.ordinary != 0 {
		t.Fatal("explicit USER admission lost")
	}
	// EOF finishes native carrier processing. The carrier must never reach
	// either underlying dispatch API as an ordinary user TCP destination.
	if err := s.DispatchUserLink(ctx, net.TCPDestination(muxCoolAddress, muxCoolPort), link()); err != nil {
		t.Fatal(err)
	}
	if d.user != 1 || d.ordinary != 0 {
		t.Fatal("carrier forwarded as USER")
	}
	if ctx.Err() != nil {
		t.Fatal("native carrier handling did not finish on EOF")
	}
	plain := new(ordinaryObservationDispatcher)
	s.dispatcher = plain
	if err := s.DispatchUserLink(ctx, net.TCPDestination(net.LocalHostIP, 80), link()); err != nil {
		t.Fatal(err)
	}
	if plain.ordinary != 1 {
		t.Fatal("ordinary dispatcher compatibility lost")
	}
}
