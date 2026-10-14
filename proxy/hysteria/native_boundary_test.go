package hysteria

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

func nativeBoundaryBuffer(t *testing.T, payload []byte, destination *net.Destination) *buf.Buffer {
	t.Helper()
	b := buf.New()
	if _, err := b.Write(payload); err != nil {
		b.Release()
		t.Fatal(err)
	}
	b.UDP = destination
	return b
}

func TestHysteriaNativeFrameAdmission(t *testing.T) {
	controlled := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginControlledMeasurement)
	if session.LogicalObservationFromContext(controlled) != nil || !internet.MUSelected(controlled) {
		t.Fatal("CONTROLLED must select native admission without creating Exchange")
	}
	for _, addr := range []string{"127.0.0.1:9", "127.0.0.1:54321", "[2001:db8::1]:9000"} {
		t.Run(addr, func(t *testing.T) {
			destination, err := net.ParseDestination("udp:" + addr)
			if err != nil {
				t.Fatal(err)
			}
			nativeAddr := destination.NetAddr()
			limit := buf.Size - (&UDPMessage{Addr: nativeAddr}).HeaderSize()
			for _, mode := range []string{"controlled-without-exchange", "explicit-receipt", "native-unselected"} {
				t.Run(mode, func(t *testing.T) {
					calls := 0
					var wire []byte
					writer := &UDPWriter{addr: "unused.invalid:1", writer: udpWriterFunc(func(p []byte) (int, error) {
						calls++
						wire = bytes.Clone(p)
						return len(p), nil
					})}
					if mode == "controlled-without-exchange" {
						writer.selected = internet.MUSelected(controlled)
					} else if mode == "explicit-receipt" {
						writer.WithWriterReceipt(measurementReceipt(t))
					}
					payload := bytes.Repeat([]byte{0x51}, limit)
					fit := nativeBoundaryBuffer(t, payload, &destination)
					if err := writer.WriteMultiBuffer(buf.MultiBuffer{fit}); err != nil {
						t.Fatal(err)
					}
					message, err := ParseUDPMessage(wire)
					if err != nil || calls != 1 || len(wire) != buf.Size || message.Addr != nativeAddr || !bytes.Equal(message.Data, payload) || fit.Cap() != 0 {
						t.Fatalf("native exact frame: writes%d bytes%d managed%d error%v", calls, len(wire), fit.Cap(), err)
					}
					over := nativeBoundaryBuffer(t, bytes.Repeat([]byte{0x73}, limit+1), &destination)
					pending := nativeBoundaryBuffer(t, []byte("pending"), &destination)
					if mode == "native-unselected" {
						err := writer.WriteMultiBuffer(buf.MultiBuffer{over})
						if err != nil || calls != 1 || over.Cap() != 0 {
							t.Fatalf("original native default oversize changed: writes%d managed%d err%v", calls, over.Cap(), err)
						}
						pending.Release()
					} else {
						err := writer.WriteMultiBuffer(buf.MultiBuffer{over, pending})
						if !errors.Is(err, buf.ErrBufferFull) || calls != 1 || over.Cap() != 0 || pending.Cap() != 0 {
							t.Fatalf("selected oversize output/error/custody: writes%d managed%d/%d err%v", calls, over.Cap(), pending.Cap(), err)
						}
					}
					complete, err := writer.sendMessage(&UDPMessage{Addr: nativeAddr, FragCount: 1, Data: bytes.Repeat([]byte{0x17}, limit+1)})
					if complete || calls != 1 || (mode == "native-unselected" && err != nil) || (mode != "native-unselected" && !errors.Is(err, buf.ErrBufferFull)) {
						t.Fatalf("oversize complete-frame fact: complete%v writes%d error%v", complete, calls, err)
					}
				})
			}
		})
	}
}

func TestHysteriaSelectedImpossibleFragmentAdmission(t *testing.T) {
	controlled := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginControlledMeasurement)
	for _, mode := range []string{"controlled-without-exchange", "explicit-receipt"} {
		for _, budget := range []string{"no-payload-room", "over255"} {
			t.Run(mode+"/"+budget, func(t *testing.T) {
				addr := "127.0.0.1:9000"
				header := (&UDPMessage{Addr: addr}).HeaderSize()
				maxSize := header - 1
				if budget == "over255" {
					maxSize = header + 1
				}
				want := &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxSize)}
				calls := 0
				writer := &UDPWriter{addr: addr, writer: udpWriterFunc(func([]byte) (int, error) {
					calls++
					return 0, want
				})}
				if mode == "controlled-without-exchange" {
					writer.selected = internet.MUSelected(controlled)
				} else {
					writer.WithWriterReceipt(measurementReceipt(t))
				}
				first := nativeBoundaryBuffer(t, bytes.Repeat([]byte{0x31}, 256), nil)
				pending := nativeBoundaryBuffer(t, []byte("pending"), nil)
				err := writer.WriteMultiBuffer(buf.MultiBuffer{first, pending})
				if !errors.Is(err, want) || calls != 1 || first.Cap() != 0 || pending.Cap() != 0 {
					t.Fatalf("selected fragment representation: writes%d managed%d/%d err%v", calls, first.Cap(), pending.Cap(), err)
				}
			})
		}
	}
}
