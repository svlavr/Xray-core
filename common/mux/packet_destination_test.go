package mux

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestPacketDestinationRetainsDecodedValue(t *testing.T) {
	dest := net.UDPDestination(net.LocalHostIP, 1000)
	original := dest
	mb, err := NewPacketReader(bytes.NewReader([]byte{0, 1, 42}), &dest).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	dest.Port = 2000
	if *mb[0].UDP != original {
		t.Fatalf("retained packet changed: %v", mb[0].UDP)
	}
	mb[0].UDP.Port = 3000
	if dest.Port != 2000 {
		t.Fatal("packet mutation changed frame metadata")
	}
}
