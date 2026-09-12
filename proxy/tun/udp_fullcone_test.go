package tun

import (
	"errors"
	stdnet "net"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestUDPFullConeReusesSourceAndRetainsPacketTargets(t *testing.T) {
	connections := make(chan *udpConn, 2)
	handler := newUdpConnectionHandler(func(conn stdnet.Conn, _ xnet.Destination) { connections <- conn.(*udpConn) }, func([]byte, xnet.Destination, xnet.Destination) error { return nil })
	src := xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234)
	first := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	second := xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 5353)
	handler.HandlePacket(src, first, []byte("one"))
	conn := <-connections
	handler.HandlePacket(src, second, []byte("two"))
	if conn.dst != first {
		t.Fatalf("first destination changed: got %v want %v", conn.dst, first)
	}
	for _, want := range []xnet.Destination{first, second} {
		mb, err := conn.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(mb) != 1 || mb[0].UDP == nil || *mb[0].UDP != want {
			t.Fatalf("packet target = %+v, want %v", mb, want)
		}
		buf.ReleaseMulti(mb)
	}
	_ = conn.Close()
}

func TestUDPFullConeStaleCloseCannotRemoveReplacement(t *testing.T) {
	connections := make(chan *udpConn, 2)
	handler := newUdpConnectionHandler(func(conn stdnet.Conn, _ xnet.Destination) { connections <- conn.(*udpConn) }, func([]byte, xnet.Destination, xnet.Destination) error { return nil })
	src := xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234)
	first := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	replacementDest := xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 5353)
	handler.HandlePacket(src, first, []byte("old"))
	old := <-connections
	_ = old.Close()
	handler.HandlePacket(src, replacementDest, []byte("new"))
	replacement := <-connections
	_ = old.Close()
	handler.RLock()
	current := handler.udpConns[src]
	handler.RUnlock()
	if current != replacement {
		t.Fatalf("stale close removed replacement: got %p want %p", current, replacement)
	}
	mb, err := replacement.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(mb)
	_ = replacement.Close()
}

func TestUDPFullConeWriteMultiBufferPropagatesResult(t *testing.T) {
	var writes int
	writeErr := errors.New("write failed")
	handler := newUdpConnectionHandler(nil, func([]byte, xnet.Destination, xnet.Destination) error {
		writes++
		if writes == 2 {
			return writeErr
		}
		return nil
	})
	conn := &udpConn{handler: handler, src: xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234), dst: xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)}
	if err := conn.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ok"))}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("error"))}); !errors.Is(err, writeErr) {
		t.Fatalf("WriteMultiBuffer error = %v, want %v", err, writeErr)
	}
}

func TestUDPFullConeConcurrentFeedAndClose(t *testing.T) {
	connections := make(chan *udpConn, 1)
	handler := newUdpConnectionHandler(func(conn stdnet.Conn, _ xnet.Destination) { connections <- conn.(*udpConn) }, func([]byte, xnet.Destination, xnet.Destination) error { return nil })
	src := xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234)
	dst := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	handler.HandlePacket(src, dst, []byte("first"))
	first := <-connections
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); handler.HandlePacket(src, dst, []byte("feed")) }()
	go func() { defer wg.Done(); _ = first.Close() }()
	wg.Wait()
}
