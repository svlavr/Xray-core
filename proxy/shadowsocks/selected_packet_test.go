package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

type selectedPacketCapture struct{ packets [][]byte }

func (c *selectedPacketCapture) Write(p []byte) (int, error) {
	c.packets = append(c.packets, bytes.Clone(p))
	return len(p), nil
}

func selectedPacketBuffer(t *testing.T, payload []byte, destination *net.Destination) *buf.Buffer {
	t.Helper()
	b := buf.New()
	if _, err := b.Write(payload); err != nil {
		b.Release()
		t.Fatal(err)
	}
	b.UDP = destination
	return b
}

func TestSelectedUDPPacketCapacityDestinationAndScalarCache(t *testing.T) {
	for _, cipherType := range []CipherType{CipherType_AES_128_GCM, CipherType_AES_256_GCM, CipherType_CHACHA20_POLY1305, CipherType_XCHACHA20_POLY1305} {
		t.Run(cipherType.String(), func(t *testing.T) {
			value, err := (&Account{CipherType: cipherType, Password: "selected-packet-fixture"}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			account := value.(*MemoryAccount)
			aead := account.Cipher.(*AEADCipher)
			originalFactory := aead.AEADAuthCreator
			overhead := originalFactory(account.Key).Overhead()
			constructions := 0
			aead.AEADAuthCreator = func(key []byte) cipher.AEAD {
				constructions++
				return originalFactory(key)
			}
			user := &protocol.MemoryUser{Account: account}
			ipv4 := net.UDPDestination(net.ParseAddress("192.0.2.1"), 9000)
			ipv6 := net.UDPDestination(net.ParseAddress("2001:db8::1"), 9001)
			limit4 := int(buf.Size-account.Cipher.IVSize()) - overhead - 7
			limit6 := int(buf.Size-account.Cipher.IVSize()) - overhead - 19
			payloads := [][]byte{bytes.Repeat([]byte{0x31}, limit4), bytes.Repeat([]byte{0x52}, limit6), []byte("changed back to ipv4")}
			capture := new(selectedPacketCapture)
			writer := &UDPWriter{Writer: capture, Request: &protocol.RequestHeader{User: user, Address: ipv4.Address, Port: ipv4.Port}, selected: true}
			mb := buf.MultiBuffer{selectedPacketBuffer(t, payloads[0], nil), selectedPacketBuffer(t, payloads[1], &ipv6), selectedPacketBuffer(t, payloads[2], &ipv4)}
			owned := append(buf.MultiBuffer(nil), mb...)
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			if len(capture.packets) != 3 || constructions != 4 {
				t.Fatalf("three native encrypted packets require one overhead query plus three actual packet ciphers: packets=%d constructions=%d", len(capture.packets), constructions)
			}
			if writer.packetOverhead != overhead {
				t.Fatalf("cached scalar overhead: got%d want%d", writer.packetOverhead, overhead)
			}
			for _, b := range owned {
				if b.Cap() != 0 {
					t.Fatal("successful selected packet retained managed input")
				}
			}
			validator := new(Validator)
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			for i, wire := range capture.packets {
				encoded := selectedPacketBuffer(t, wire, nil)
				request, decoded, err := DecodeUDPPacket(validator, encoded)
				if err != nil {
					encoded.Release()
					t.Fatal(err)
				}
				want := ipv4
				if i == 1 {
					want = ipv6
				}
				if request.Destination() != want || !bytes.Equal(decoded.Bytes(), payloads[i]) {
					decoded.Release()
					t.Fatalf("native packet%d payload/destination changed: destination=%v want%v", i, request.Destination(), want)
				}
				decoded.Release()
			}

			// The cached user is unchanged, but the actual IPv6 address consumes
			// more wire space than the writer's original IPv4 request.
			before := constructions
			over := selectedPacketBuffer(t, bytes.Repeat([]byte{0x63}, limit6+1), &ipv6)
			pending := selectedPacketBuffer(t, []byte("pending"), &ipv4)
			empty := selectedPacketBuffer(t, nil, nil)
			err = writer.WriteMultiBuffer(buf.MultiBuffer{over, pending, empty})
			if !errors.Is(err, buf.ErrBufferFull) || len(capture.packets) != 3 || constructions != before {
				t.Fatalf("selected overflow wrote or reconstructed cipher: packets=%d constructions=%d before%d err=%v", len(capture.packets), constructions, before, err)
			}
			if over.Cap() != 0 || pending.Cap() != 0 || empty.Cap() != 0 {
				t.Fatal("selected overflow retained owned batch")
			}

			freshCapture := new(selectedPacketCapture)
			fresh := &UDPWriter{Writer: freshCapture, Request: writer.Request, selected: true}
			firstOverflow := selectedPacketBuffer(t, bytes.Repeat([]byte{0x75}, limit4+1), nil)
			tail := selectedPacketBuffer(t, []byte("fresh pending"), &ipv6)
			before = constructions
			err = fresh.WriteMultiBuffer(buf.MultiBuffer{firstOverflow, tail})
			if !errors.Is(err, buf.ErrBufferFull) || len(freshCapture.packets) != 0 || constructions != before+1 || firstOverflow.Cap() != 0 || tail.Cap() != 0 {
				t.Fatalf("first selected overflow did not stop before encryption/output and release its batch: packets=%d constructions=%d before%d err=%v", len(freshCapture.packets), constructions, before, err)
			}
		})
	}
}
