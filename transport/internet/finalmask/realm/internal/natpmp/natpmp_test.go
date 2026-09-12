package natpmp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestAddAndDeleteWireGrant(t *testing.T) {
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := make(chan []byte, 2)
	go func() {
		for range 2 {
			b := make([]byte, 32)
			n, a, e := s.ReadFromUDP(b)
			if e != nil {
				return
			}
			got <- append([]byte(nil), b[:n]...)
			r := make([]byte, 16)
			r[1] = b[1] | 0x80
			copy(r[8:10], b[4:6])
			binary.BigEndian.PutUint16(r[10:], 4321)
			if binary.BigEndian.Uint32(b[8:]) != 0 {
				binary.BigEndian.PutUint32(r[12:], 60)
			}
			_, _ = s.WriteToUDP(r, a)
		}
	}()
	c := newClient(s.LocalAddr().(*net.UDPAddr))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if r, err := c.AddPortMappingContext(ctx, "udp", 1234, 4321, 60); err != nil || r.InternalPort != 1234 || r.MappedExternalPort != 4321 || r.PortMappingLifetimeInSeconds != 60 {
		t.Fatalf("add %#v %v", r, err)
	}
	if _, err := c.AddPortMappingContext(ctx, "udp", 1234, 0, 0); err != nil {
		t.Fatal(err)
	}
	addReq := <-got
	deleteReq := <-got
	if binary.BigEndian.Uint32(addReq[8:]) != 60 {
		t.Fatal("add request lifetime")
	}
	if binary.BigEndian.Uint16(deleteReq[6:8]) != 0 || binary.BigEndian.Uint32(deleteReq[8:]) != 0 {
		t.Fatal("delete request did not clear external port and lifetime")
	}
}

func TestRPCCancellationClosesOwnedSocket(t *testing.T) {
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	received := make(chan struct{})
	go func() {
		buf := make([]byte, 32)
		if _, _, err := s.ReadFromUDP(buf); err == nil {
			close(received)
		}
	}()
	c := newClient(s.LocalAddr().(*net.UDPAddr))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.GetExternalAddressContext(ctx)
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("request not received")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock RPC")
	}
}
