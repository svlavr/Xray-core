package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"
	"time"

	cnet "github.com/xtls/xray-core/common/net"
	"lukechampine.com/blake3"
)

func TestInspectionSS2022PacketCodecResults(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, err := GetCipherMethod(name)
			if err != nil {
				t.Fatal(err)
			}
			key := make([]byte, method.KeySaltLength)
			client, err := inspectionClientSession(method, [][]byte{key})
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewUDPServerCodec(method, key, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			dest := cnet.UDPDestination(cnet.LocalHostIP, 8080)
			wire, err := client.EncodePacket(dest, []byte("request"))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := server.DecodePacket(bytes.Clone(wire.Bytes()))
			wire.Release()
			if err != nil || string(decoded.Payload) != "request" || decoded.Destination != dest {
				t.Fatalf("request: %+v %v", decoded, err)
			}
			response, err := server.EncodeServerPacket(decoded.SessionID, dest, []byte("response"))
			if err != nil {
				t.Fatal(err)
			}
			answer, err := client.DecodePacket(response)
			if err != nil || string(answer.Payload) != "response" || answer.Destination != dest {
				t.Fatalf("response: %+v %v", answer, err)
			}
		})
	}
}

func TestSS2022MultiUserUDPIdentityHeader(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	master, user := []byte("0123456789abcdef"), []byte("fedcba9876543210")
	client, err := inspectionClientSession(method, [][]byte{master, user})
	if err != nil {
		t.Fatal(err)
	}
	destination := cnet.UDPDestination(cnet.LocalHostIP, 8080)
	wire, err := client.EncodePacket(destination, []byte("packet"))
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Release()
	packet := wire.Bytes()
	block, _ := method.NewBlock(master)
	var raw [16]byte
	block.Decrypt(raw[:], packet[:16])
	if got := binary.BigEndian.Uint64(raw[:8]); got != client.clientSessionID {
		t.Fatalf("session: %x", got)
	}
	identityBlock, _ := aes.NewCipher(master)
	var hash [16]byte
	identityBlock.Decrypt(hash[:], packet[16:32])
	for i := range hash {
		hash[i] ^= raw[i]
	}
	if hash != DeriveUserPSKHash(user) {
		t.Fatal("user identity header mismatch")
	}
	server, err := NewUDPServerCodec(method, user, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bodyKey := DeriveSessionSubKey(user, raw[:8], method.KeySaltLength)
	aead, _ := method.NewAEAD(bodyKey)
	plain, err := aead.Open(nil, raw[4:16], packet[32:], nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := parsePlainUDPPacket(client.clientSessionID, 0, plain)
	if err != nil || string(decoded.Payload) != "packet" {
		t.Fatalf("body: %+v %v", decoded, err)
	}
	session := server.sessions.GetOrCreate(decoded.SessionID)
	if err := session.EnsureServerState(method, user); err != nil {
		t.Fatal(err)
	}
	response, err := session.EncodeServerPacket(method, decoded.SessionID, destination, []byte("answer"))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := client.DecodePacket(response)
	if err != nil || string(answer.Payload) != "answer" || answer.Destination != destination {
		t.Fatalf("native multi-user response: %+v %v", answer, err)
	}
}

func TestSS2022UDPIdentityChainWire(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	keys := [][]byte{[]byte("0123456789abcdef"), []byte("fedcba9876543210"), []byte("ABCDEF0123456789")}
	client, err := inspectionClientSession(method, keys)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := client.EncodePacket(cnet.UDPDestination(cnet.LocalHostIP, 8080), []byte("chain"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	wire := packet.Bytes()
	if len(wire) < 3*AESBlockSize {
		t.Fatal("missing identity headers")
	}
	first, _ := aes.NewCipher(keys[0])
	var raw [AESBlockSize]byte
	first.Decrypt(raw[:], wire[:AESBlockSize])
	if binary.BigEndian.Uint64(raw[:8]) != client.clientSessionID || binary.BigEndian.Uint64(raw[8:]) != 0 {
		t.Fatal("first header mismatch")
	}
	for hop := 0; hop < 2; hop++ {
		block, _ := aes.NewCipher(keys[hop])
		hash := blake3.Sum512(keys[hop+1])
		var expected [AESBlockSize]byte
		for j := range expected {
			expected[j] = hash[j] ^ raw[j]
		}
		block.Encrypt(expected[:], expected[:])
		if got := wire[(hop+1)*AESBlockSize : (hop+2)*AESBlockSize]; !bytes.Equal(got, expected[:]) {
			t.Fatalf("hop %d identity: %x want %x", hop, got, expected)
		}
	}
}

func inspectionClientSession(method *CipherMethod, keys [][]byte) (*ClientUDPSession, error) {
	codec, err := NewUDPPacketCodec(method, keys)
	if err != nil {
		return nil, err
	}
	return codec.NewClientSession()
}
