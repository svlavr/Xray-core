package mux_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestMeasurementPacketDestinationSurvivesFrameReuse(t *testing.T) {
	first := xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 1111)
	second := xnet.UDPDestination(xnet.ParseAddress("192.0.2.2"), 2222)
	var metadata mux.FrameMetadata
	metadata.Target = first
	r := mux.NewPacketReader(bytes.NewReader([]byte{0, 3, 'o', 'n', 'e'}), &metadata.Target)
	packet, err := r.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(packet)
	// fetchOutput reuses metadata while this packet waits in its output pipe.
	metadata.Target = second
	next, err := mux.NewPacketReader(bytes.NewReader([]byte{0, 3, 't', 'w', 'o'}), &metadata.Target).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(next)
	if len(packet) != 1 || packet[0].UDP == nil || *packet[0].UDP != first || string(packet[0].Bytes()) != "one" || len(next) != 1 || next[0].UDP == nil || *next[0].UDP != second || string(next[0].Bytes()) != "two" {
		t.Fatal("queued packet destination changed with the next frame")
	}
	metadata.Target.Network = xnet.Network_Unknown
	if packet[0].UDP.Network != xnet.Network_UDP || next[0].UDP.Network != xnet.Network_UDP {
		t.Fatal("queued packet lost its UDP network with frame reuse")
	}
}

func TestMeasurementPacketReaderWithoutUDPMetadata(t *testing.T) {
	tcp := xnet.TCPDestination(xnet.LocalHostIP, 1234)
	for _, destination := range []*xnet.Destination{nil, &tcp} {
		packet, err := mux.NewPacketReader(bytes.NewReader([]byte{0, 1, 'x'}), destination).ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) != 1 || packet[0].UDP != nil || string(packet[0].Bytes()) != "x" {
			t.Error("non-UDP packet acquired invented source metadata")
		}
		buf.ReleaseMulti(packet)
	}
}
