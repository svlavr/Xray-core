package measurement

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestPacketAdapterFirstReplyKeepsNativeErrorAndReleasesRemainder(t *testing.T) {
	native := errors.New("native terminal batch error")
	visitor := errors.New("reply qualification error")
	for _, visitErr := range []error{nil, visitor} {
		first, remainder := buf.New(), buf.New()
		first.WriteString("first")
		remainder.WriteString("remainder")
		dest := xnet.UDPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 9)
		first.UDP = &dest
		remainderDest := xnet.UDPDestination(xnet.IPAddress([]byte{198, 51, 100, 8}), 10)
		remainder.UDP = &remainderDest
		batch := buf.MultiBuffer{first, remainder}
		conn := &udpTestConn{read: func() (buf.MultiBuffer, error) {
			return batch, native
		}}
		calls := 0
		hadData, nativeErr, qualificationErr := readPacketBatch(conn, nil, func(packet []byte, source netip.AddrPort) error {
			calls++
			if string(packet) != "first" || source != netip.MustParseAddrPort("127.0.0.1:9") {
				t.Fatalf("first packet/source lost: %q %v", packet, source)
			}
			return visitErr
		}, true)
		if !hadData || !errors.Is(nativeErr, native) || !errors.Is(qualificationErr, visitErr) || calls != 1 {
			t.Fatalf("hadData=%t native=%v qualification=%v visits=%d", hadData, nativeErr, qualificationErr, calls)
		}
		for _, b := range batch {
			if b != nil {
				t.Fatal("native packet batch retained a buffer slot")
			}
		}
		for _, b := range []*buf.Buffer{first, remainder} {
			if b.Len() != 0 || b.UDP != nil {
				t.Fatal("unvisited native packet batch member was not released")
			}
		}
	}
}

func TestPacketAdapterDoesNotInventMissingSource(t *testing.T) {
	packet := buf.New()
	packet.WriteString("raw")
	batch := buf.MultiBuffer{packet}
	conn := &udpTestConn{read: func() (buf.MultiBuffer, error) {
		return batch, nil
	}}
	calls := 0
	hadData, nativeErr, visitErr := readPacketBatch(conn, nil, func(data []byte, source netip.AddrPort) error {
		calls++
		if string(data) != "raw" || source.IsValid() {
			t.Fatalf("missing source synthesized from destination: %q %v", data, source)
		}
		return nil
	}, true)
	if !hadData || nativeErr != nil || visitErr != nil || calls != 1 {
		t.Fatalf("missing-source packet facts: data=%t native=%v visitor=%v calls=%d", hadData, nativeErr, visitErr, calls)
	}
	if packet.Len() != 0 || packet.UDP != nil || batch[0] != nil {
		t.Fatal("missing-source native packet buffer was not released or cleared")
	}
}
