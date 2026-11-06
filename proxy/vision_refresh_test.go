package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/vless"
)

func TestVisionDirectHandoffUsesGoTLSBuffers(t *testing.T) {
	for _, uplink := range []bool{true, false} {
		t.Run(map[bool]string{true: "uplink", false: "downlink"}[uplink], func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			// Exercise the selected Go toolchain's real TLS buffer layout. This
			// fixture supplies decoded buffers without performing a TLS handshake.
			conn := tls.Client(left, &tls.Config{})
			input, rawInput := vless.AccessTLSBuffers(conn)
			input.Reset([]byte("input"))
			if *rawInput == nil {
				*rawInput = new(bytes.Buffer)
			}
			(*rawInput).WriteString("raw")
			ownerInput, ownerRawInput := vless.AccessTLSBuffers(conn)
			if ownerInput != input || *ownerRawInput != *rawInput {
				t.Fatal("TLS buffer helper detached storage from its owner")
			}

			uuid := bytes.Repeat([]byte{0xaa}, 16)
			paddingUUID := append([]byte(nil), uuid...)
			wire := XtlsPadding(buf.FromBytes([]byte("decoded")), CommandPaddingDirect, &paddingUUID, false, context.Background(), measurementVisionSeed)
			lower := &visionSwappingInput{mb: buf.MultiBuffer{wire}, swap: func() {}}
			state := NewTrafficState(uuid)
			reader := NewVisionReader(lower, state, uplink, context.Background(), left, input, rawInput, nil)
			mb, err := reader.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if mb.String() != "decodedinputraw" || err != io.EOF {
				t.Fatalf("handoff changed payload or terminal result: %q, %v", mb.String(), err)
			}
			if ownerInput.Len() != 0 || (*ownerRawInput).Len() != 0 || reader.input != nil || reader.rawInput != nil {
				t.Fatal("handoff did not drain owner buffers and release Vision references")
			}
			if uplink && !state.Inbound.UplinkReaderDirectCopy || !uplink && !state.Outbound.DownlinkReaderDirectCopy {
				t.Fatal("handoff did not select native direct copy")
			}
		})
	}
}
