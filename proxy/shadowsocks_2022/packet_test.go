package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"lukechampine.com/blake3"
)

func TestInspectionSS2022PacketCodecResults(t *testing.T) {
	for _, methodName := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		for _, outcome := range []string{"complete", "zero-error", "partial-error", "complete-error", "short-nil"} {
			t.Run(methodName+"/"+outcome, func(t *testing.T) {
				method, err := GetCipherMethod(methodName)
				if err != nil {
					t.Fatal(err)
				}
				key := make([]byte, method.KeySaltLength)
				client, err := NewUDPPacketCodec(method, key)
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewUDPServerCodec(method, key, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				destination := cnet.UDPDestination(cnet.LocalHostIP, 8080)
				wire, err := client.EncodeClientPacket(destination, []byte("request"))
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := server.DecodePacket(bytes.Clone(wire.Bytes()))
				wire.Release()
				if err != nil || string(decoded.Payload) != "request" || decoded.Destination != destination {
					t.Fatalf("decoded: %+v %v", decoded, err)
				}
				manager := new(appstats.Manager)
				view, err := manager.EnableInspection(fs.ObservationOptions{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { manager.Close() })
				flow := manager.Observation().Begin(cnet.Network_UDP, fs.TrafficOriginUser, cnet.Destination{}, destination, nil)
				flow.Route(fs.OutboundRef{Tag: "direct", Serial: 1})
				flow.BindRoute()
				flow.PacketDestination(decoded.Destination)
				flow.AddUplink(uint64(len(decoded.Payload)))
				response, err := server.EncodeServerPacket(decoded.SessionID, destination, []byte("response"))
				if err != nil {
					t.Fatal(err)
				}
				written, writeErr := len(response), error(nil)
				switch outcome {
				case "zero-error":
					written, writeErr = 0, io.ErrUnexpectedEOF
				case "partial-error":
					written, writeErr = 1, io.ErrUnexpectedEOF
				case "complete-error":
					writeErr = io.ErrUnexpectedEOF
				case "short-nil":
					written = 1
				}
				if writeErr == nil {
					proxy.RecordPacketWrite(flow, 8, len(response), written)
				}
				row := inspectionLive(t, view)
				want := uint64(0)
				if outcome == "complete" {
					want = 8
				}
				if row.Uplink != 7 || row.Downlink != want || row.LatestDestination != destination {
					t.Fatalf("packet result: %+v", row)
				}
			})
		}
	}
}

func TestSS2022MultiUserUDPIdentityHeader(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	master, user := []byte("0123456789abcdef"), []byte("fedcba9876543210")
	client, err := NewUDPPacketCodec(method, user, master)
	if err != nil {
		t.Fatal(err)
	}
	destination := cnet.UDPDestination(cnet.LocalHostIP, 8080)
	wire, err := client.EncodeClientPacket(destination, []byte("packet"))
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
	decoded, err := parsePlainUDPPacket(client.clientSessionID, 1, plain)
	if err != nil || string(decoded.Payload) != "packet" {
		t.Fatalf("body: %+v %v", decoded, err)
	}
	session := server.sessions.GetOrCreate(decoded.SessionID, decoded.SessionID)
	userBlock, _ := method.NewBlock(user)
	if err := session.EnsureServerState(method, userBlock, nil, user); err != nil {
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
	client, err := NewUDPPacketCodec(method, keys[2], keys[0], keys[1])
	if err != nil {
		t.Fatal(err)
	}
	packet, err := client.EncodeClientPacket(cnet.UDPDestination(cnet.LocalHostIP, 8080), []byte("chain"))
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
	if binary.BigEndian.Uint64(raw[:8]) != client.clientSessionID || binary.BigEndian.Uint64(raw[8:]) != 1 {
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

func TestSS2022NativeUDPWriterShortResult(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	codec, err := NewUDPPacketCodec(method, make([]byte, method.KeySaltLength))
	if err != nil {
		t.Fatal(err)
	}
	writer := &UDPWriter{
		Writer:      inspectionWriteFunc(func([]byte) (int, error) { return 1, nil }),
		Destination: cnet.UDPDestination(cnet.LocalHostIP, 8080),
		Codec:       codec,
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != io.ErrShortWrite {
		t.Fatalf("short packet write: %v", err)
	}
}

func TestSS2022PacketMetadataIsolation(t *testing.T) {
	base := session.ContextWithInbound(context.Background(), &session.Inbound{Name: "parent"})
	base = session.ContextWithOutbounds(base, []*session.Outbound{{Tag: "parent"}})
	base = session.ContextWithContent(base, &session.Content{Attributes: map[string]string{"test": "parent"}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := packetSessionContext(base)
			session.InboundFromContext(ctx).Name = "child"
			session.OutboundsFromContext(ctx)[0].Tag = "child"
			session.ContentFromContext(ctx).Attributes["test"] = "child"
		}()
	}
	wg.Wait()
	if session.InboundFromContext(base).Name != "parent" || session.OutboundsFromContext(base)[0].Tag != "parent" || session.ContentFromContext(base).Attributes["test"] != "parent" {
		t.Fatal("shared packet metadata mutated")
	}
}
