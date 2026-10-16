package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type visionSwappingInput struct {
	mb   buf.MultiBuffer
	swap func()
}

func (r *visionSwappingInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.swap()
	mb := r.mb
	r.mb = nil
	return mb, io.EOF
}

func TestVisionDirectHandoffFollowsReplacedRawInput(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaced", true: "released"}[empty], func(t *testing.T) {
			uuid := bytes.Repeat([]byte{0xaa}, 16)
			paddingUUID := append([]byte(nil), uuid...)
			wire := XtlsPadding(buf.FromBytes([]byte("decoded")), CommandPaddingDirect, &paddingUUID, false, context.Background(), measurementVisionSeed)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			input := bytes.NewReader([]byte("input"))
			stale := bytes.NewBufferString("stale")
			raw := stale
			lower := &visionSwappingInput{mb: buf.MultiBuffer{wire}, swap: func() {
				if empty {
					raw = nil
				} else {
					raw = bytes.NewBufferString("raw")
				}
			}}
			reader := NewVisionReader(lower, NewTrafficState(uuid), true, context.Background(), left, input, nil, nil)
			reader.BindRawInputPointer(&raw)
			// REALITY may return the previous buffer to its pool before direct handoff.
			mb, _ := reader.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			want := "decodedinput"
			if !empty {
				want += "raw"
			}
			if mb.String() != want || stale.String() != "stale" || input.Len() != 0 {
				t.Fatalf("handoff changed byte ownership: got %q want %q stale %q", mb.String(), want, stale.String())
			}
			if reader.rawInputPointer != nil || reader.rawInput != nil || reader.input != nil || !reader.trafficState.Inbound.UplinkReaderDirectCopy {
				t.Fatal("handoff retained TLS buffers or did not select direct copy")
			}
		})
	}
}
