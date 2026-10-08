package shadowsocks

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func inspectionPacketRequest(t *testing.T) *protocol.RequestHeader {
	t.Helper()
	account, err := (&Account{CipherType: CipherType_AES_128_GCM, Password: "inspection-test-only"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.RequestHeader{Command: protocol.RequestCommandUDP, User: &protocol.MemoryUser{Account: account}, Address: net.LocalHostIP, Port: 53}
}

func TestInspectionShadowsocksUDPOversizedEncoding(t *testing.T) {
	for _, size := range []int{buf.Size, buf.Size - 16 - 7 - 8} {
		packet, err := EncodeUDPPacket(inspectionPacketRequest(t), make([]byte, size))
		if packet != nil {
			packet.Release()
			t.Fatal("oversized packet was encoded")
		}
		if err == nil {
			t.Fatal("oversized packet did not report an error")
		}
	}
	request := inspectionPacketRequest(t)
	payload := bytes.Repeat([]byte{0x19}, buf.Size-16-7-16)
	packet, err := EncodeUDPPacket(request, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	if packet.Len() != buf.Size {
		t.Fatalf("boundary packet length: %d", packet.Len())
	}
	validator := new(Validator)
	if err := validator.Add(request.User); err != nil {
		t.Fatal(err)
	}
	decoded, body, err := DecodeUDPPacket(validator, packet)
	if err != nil || decoded.Destination() != request.Destination() || !bytes.Equal(body.Bytes(), payload) {
		t.Fatalf("maximum valid packet changed: %v", err)
	}
}
