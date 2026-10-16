package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestNetTUNUDPRejectsWritesAfterClose(t *testing.T) {
	dev, tnet, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.2")}, nil, 1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	destination := netip.MustParseAddrPort("10.66.0.1:53")
	first, err := tnet.DialContext(context.Background(), "udp", destination.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := first.Write([]byte("closed")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed virtual socket accepted write: %d %v", n, err)
	}
	second, err := tnet.DialContext(context.Background(), "udp", destination.String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if n, err := second.Write([]byte("sibling")); n != 7 || err != nil {
		t.Fatalf("socket close retired shared stack: %d %v", n, err)
	}
}

func TestNetTUNCloseDiscardsPendingPacketsAndRejectsAdmission(t *testing.T) {
	device, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.2")}, nil, 1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.(*netTun)
	if err := dev.WritePacket([]byte("pending"), nil); err != nil {
		t.Fatal(err)
	}
	packet := <-dev.packets
	dev.packets <- packet
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if !packet.IsEmpty() || len(dev.packets) != 0 {
		t.Fatal("retired device retained pooled packet")
	}
	for range 128 {
		if err := dev.WritePacket([]byte("closed"), nil); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("retired device accepted packet: %v", err)
		}
	}
}
