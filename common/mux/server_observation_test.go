package mux

import (
	"bytes"
	"context"
	stdnet "net"
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

func (d *userObservationDispatcher) DispatchUserStream(_ context.Context, _ net.Destination, stream routing.UserStream) error {
	d.user++
	buf.ReleaseMulti(stream.Retained)
	_ = stream.Connection.Close()
	return nil
}

type userStreamConn struct{ bytes.Buffer }

func (*userStreamConn) Close() error                     { return nil }
func (*userStreamConn) LocalAddr() stdnet.Addr           { return userStreamAddr("local") }
func (*userStreamConn) RemoteAddr() stdnet.Addr          { return userStreamAddr("remote") }
func (*userStreamConn) SetDeadline(time.Time) error      { return nil }
func (*userStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*userStreamConn) SetWriteDeadline(time.Time) error { return nil }

type userStreamAddr string

func (a userStreamAddr) Network() string { return string(a) }
func (a userStreamAddr) String() string  { return string(a) }

func TestUserDispatchPreservesCarrierHandling(t *testing.T) {
	d := new(userObservationDispatcher)
	s := &Server{dispatcher: d}
	stream := func() routing.UserStream {
		return routing.UserStream{Connection: new(userStreamConn)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.DispatchUserStream(ctx, net.TCPDestination(net.LocalHostIP, 80), stream()); err != nil {
		t.Fatal(err)
	}
	if d.user != 1 || d.ordinary != 0 {
		t.Fatal("explicit USER admission lost")
	}
	// EOF finishes native carrier processing. The carrier must never reach
	// either underlying dispatch API as an ordinary user TCP destination.
	if err := s.DispatchUserStream(ctx, net.TCPDestination(muxCoolAddress, muxCoolPort), stream()); err != nil {
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
	if err := s.DispatchUserStream(ctx, net.TCPDestination(net.LocalHostIP, 80), stream()); err != nil {
		t.Fatal(err)
	}
	if plain.ordinary != 1 {
		t.Fatal("ordinary dispatcher compatibility lost")
	}
}
