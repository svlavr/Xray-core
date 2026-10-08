package shadowsocks_2022

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func measurementPacketCodecs(t *testing.T, name string) (*ClientUDPSession, *UDPCodec) {
	t.Helper()
	method, err := GetCipherMethod(name)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x37}, method.KeySaltLength)
	client, err := NewUDPPacketCodec(method, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewClientSession()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewUDPServerCodec(method, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return session, server
}

func TestMeasurementPacketClientSizeLimits(t *testing.T) {
	for _, method := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				address net.Address
				limit   int
			}{
				{"ipv4", net.ParseAddress("192.0.2.1"), 8142},
				{"ipv6", net.ParseAddress("2001:db8::1"), 8130},
			} {
				t.Run(tc.name, func(t *testing.T) {
					limit := tc.limit
					if method == MethodChaCha20Poly1305 {
						limit -= 24
					}
					session, server := measurementPacketCodecs(t, method)
					dest := net.UDPDestination(tc.address, 9000) // No DNS padding.
					for _, size := range []int{limit - 1, limit, limit + 1} {
						payload := bytes.Repeat([]byte{0xc5}, size)
						packet, err := session.EncodePacket(dest, payload)
						if size > limit {
							if !errors.Is(err, ErrPacketTooLarge) || packet != nil {
								t.Fatalf("oversize client packet: size=%d err=%v", size, err)
							}
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
						decoded, decodeErr := server.DecodePacket(packet.Bytes())
						wireSize := packet.Len()
						packet.Release()
						if decodeErr != nil || int(wireSize) != size+buf.Size-limit || decoded.Destination != dest || !bytes.Equal(decoded.Payload, payload) {
							t.Fatalf("client boundary: size=%d wire=%d decoded=%d dest=%v err=%v", size, wireSize, len(decoded.Payload), decoded.Destination, decodeErr)
						}
					}
				})
			}
		})
	}
}

type measurementPacketWriter struct {
	calls int
	err   error
}

func TestMeasurementPacketServerDirectionalLimits(t *testing.T) {
	for _, method := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		for _, address := range []net.Address{net.ParseAddress("192.0.2.1"), net.ParseAddress("2001:db8::1")} {
			t.Run(method+"/"+address.String(), func(t *testing.T) {
				receiveLimit, plainLimit := 8134, 8166
				if method == MethodChaCha20Poly1305 {
					receiveLimit, plainLimit = 8110, 8150
				}
				if address.Family().IsIPv6() {
					receiveLimit -= 12
					plainLimit -= 12
				}
				for _, size := range []int{receiveLimit - 1, receiveLimit, receiveLimit + 1, plainLimit, plainLimit + 1} {
					session, server := measurementPacketCodecs(t, method)
					dest := net.UDPDestination(address, 9000)
					request, err := session.EncodePacket(dest, []byte("establish-client-session"))
					if err != nil {
						t.Fatal(err)
					}
					_, err = server.DecodePacket(request.Bytes())
					request.Release()
					if err != nil {
						t.Fatal(err)
					}
					payload := bytes.Repeat([]byte{0xc5}, size)
					packet, err := server.EncodeServerPacket(session.ClientSessionID(), dest, payload)
					if size > plainLimit {
						if !errors.Is(err, buf.ErrBufferFull) || packet != nil {
							t.Fatalf("server plaintext oversize%d: bytes%d err%v", size, len(packet), err)
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if size == plainLimit {
						decoded, err := session.DecodePacket(packet)
						if err != nil || decoded.Destination != dest || !bytes.Equal(decoded.Payload, payload) {
							t.Fatalf("server codec lost valid payload%d: %v", size, err)
						}
						continue
					}
					mb, err := (&UDPReader{Reader: &measurementPacketReader{data: packet, err: io.EOF}, Session: session}).ReadMultiBuffer()
					if !errors.Is(err, io.EOF) {
						buf.ReleaseMulti(mb)
						t.Fatalf("server boundary%d native error: %v", size, err)
					}
					if size <= receiveLimit {
						if len(mb) != 1 || mb[0].UDP == nil || *mb[0].UDP != dest || !bytes.Equal(mb[0].Bytes(), payload) {
							buf.ReleaseMulti(mb)
							t.Fatalf("server receive boundary%d lost payload", size)
						}
					} else if len(mb) != 0 {
						buf.ReleaseMulti(mb)
						t.Fatalf("truncated encrypted reply%d became valid", size)
					}
					buf.ReleaseMulti(mb)
				}
			})
		}
	}
}

func (w *measurementPacketWriter) Write(p []byte) (int, error) {
	w.calls++
	return len(p) - 1, w.err
}

func TestMeasurementPacketWriteFailure(t *testing.T) {
	native := errors.New("native encrypted packet write failure")
	for _, tc := range []struct {
		name      string
		err, want error
	}{
		{"short-write", nil, io.ErrShortWrite},
		{"partial-native-error", native, native},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, _ := measurementPacketCodecs(t, MethodAES128GCM)
			wire := &measurementPacketWriter{err: tc.err}
			w := &UDPWriter{Writer: wire, Destination: net.UDPDestination(net.LocalHostIP, 9), Session: session}
			first, pending := buf.New(), buf.New()
			first.Write([]byte("first"))
			pending.Write([]byte("pending"))
			err := w.WriteMultiBuffer(buf.MultiBuffer{first, pending})
			if !errors.Is(err, tc.want) || wire.calls != 1 || first.Cap() != 0 || pending.Cap() != 0 {
				t.Fatalf("encrypted packet failure: calls=%d first=%d pending=%d err=%v", wire.calls, first.Cap(), pending.Cap(), err)
			}
		})
	}
}

type measurementPacketReader struct {
	data  []byte
	err   error
	calls int
}

type measurementPacketSequence struct{ packets [][]byte }

func (r *measurementPacketSequence) Read(p []byte) (int, error) {
	if len(r.packets) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.packets[0])
	r.packets = r.packets[1:]
	return n, nil
}

func TestMeasurementPacketMalformedThenValid(t *testing.T) {
	for _, method := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(method, func(t *testing.T) {
			session, server := measurementPacketCodecs(t, method)
			dest := net.UDPDestination(net.ParseAddress("2001:db8::2"), 9000)
			packet, err := session.EncodePacket(dest, []byte("establish"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = server.DecodePacket(packet.Bytes())
			packet.Release()
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("recovered")
			reply, err := server.EncodeServerPacket(session.ClientSessionID(), dest, payload)
			if err != nil {
				t.Fatal(err)
			}
			wire := &measurementPacketSequence{packets: [][]byte{{1, 2, 3}, reply}}
			mb, err := (&UDPReader{Reader: wire, Session: session}).ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if err != nil || len(mb) != 1 || mb[0].UDP == nil || *mb[0].UDP != dest || !bytes.Equal(mb[0].Bytes(), payload) || len(wire.packets) != 0 {
				t.Fatalf("malformed recovery: %v %v", mb, err)
			}
		})
	}
}

func (r *measurementPacketReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 1 {
		return 0, io.EOF
	}
	return copy(p, r.data), r.err
}

func TestMeasurementPacketReadDataAndError(t *testing.T) {
	for _, method := range []string{MethodAES128GCM, MethodChaCha20Poly1305} {
		t.Run(method, func(t *testing.T) {
			session, server := measurementPacketCodecs(t, method)
			dest := net.UDPDestination(net.ParseAddress("2001:db8::2"), 9000)
			payload := []byte("data accompanying native read failure")
			request, err := session.EncodePacket(dest, payload)
			if err != nil {
				t.Fatal(err)
			}
			_, err = server.DecodePacket(request.Bytes())
			request.Release()
			if err != nil {
				t.Fatal(err)
			}
			reply, err := server.EncodeServerPacket(session.ClientSessionID(), dest, payload)
			if err != nil {
				t.Fatal(err)
			}
			native := errors.New("native packet read failure")
			wire := &measurementPacketReader{data: reply, err: native}
			r := &UDPReader{Reader: wire, Session: session}
			mb, err := r.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if !errors.Is(err, native) || wire.calls != 1 || len(mb) != 1 || mb[0].UDP == nil || *mb[0].UDP != dest || !bytes.Equal(mb[0].Bytes(), payload) {
				t.Fatalf("packet data/error: buffers=%d calls=%d err=%v", len(mb), wire.calls, err)
			}
		})
	}
	t.Run("malformed-with-error", func(t *testing.T) {
		session, _ := measurementPacketCodecs(t, MethodAES128GCM)
		native := errors.New("native malformed packet error")
		wire := &measurementPacketReader{data: []byte{1, 2, 3}, err: native}
		mb, err := (&UDPReader{Reader: wire, Session: session}).ReadMultiBuffer()
		defer buf.ReleaseMulti(mb)
		if !errors.Is(err, native) || len(mb) != 0 || wire.calls != 1 {
			t.Fatalf("malformed packet lost terminal error: buffers=%d calls=%d err=%v", len(mb), wire.calls, err)
		}
	})
}
