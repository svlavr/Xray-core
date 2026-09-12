package wireguard

import (
	"errors"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestUDPManagerReusesSourceAndRetainsPacketTargets(t *testing.T) {
	connections := make(chan *udpConn, 2)
	manager := &udpManager{m: make(map[string]*udpConn), handler: func(conn stdnet.Conn, _ xnet.Destination) { connections <- conn.(*udpConn) }}
	src := xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234)
	first := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	second := xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 5353)
	manager.feed(src, first, []byte("one"))
	conn := <-connections
	manager.feed(src, second, []byte("two"))
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

func TestUDPManagerStaleCloseCannotRemoveReplacement(t *testing.T) {
	connections := make(chan *udpConn, 2)
	manager := &udpManager{m: make(map[string]*udpConn), handler: func(conn stdnet.Conn, _ xnet.Destination) { connections <- conn.(*udpConn) }}
	src := xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234)
	first := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	replacementDest := xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 5353)
	manager.feed(src, first, []byte("old"))
	old := <-connections
	_ = old.Close()
	manager.feed(src, replacementDest, []byte("new"))
	replacement := <-connections
	_ = old.Close()
	manager.mutex.RLock()
	current := manager.m[src.NetAddr()]
	manager.mutex.RUnlock()
	if current != replacement || replacement.closed {
		t.Fatalf("stale close removed or closed replacement: current=%p replacement=%p closed=%v", current, replacement, replacement.closed)
	}
	mb, err := replacement.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(mb)
	_ = replacement.Close()
}

func TestUDPConnWriteMultiBufferPropagatesResult(t *testing.T) {
	var writes int
	writeErr := errors.New("write failed")
	conn := &udpConn{
		src: xnet.UDPDestination(xnet.ParseAddress("10.0.0.2"), 1234),
		dst: xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53),
		writeFunc: func([]byte, xnet.Destination, xnet.Destination) error {
			writes++
			if writes == 2 {
				return writeErr
			}
			return nil
		},
	}
	if err := conn.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ok"))}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("error"))}); !errors.Is(err, writeErr) {
		t.Fatalf("WriteMultiBuffer error = %v, want %v", err, writeErr)
	}
}
