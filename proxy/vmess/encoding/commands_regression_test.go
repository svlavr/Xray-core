package encoding

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
)

type commandWriteProbe struct{ calls int }

func (w *commandWriteProbe) Write([]byte) (int, error) {
	w.calls++
	return 0, errors.New("rejected command must not write")
}

func TestResponseCommandRejectionPreservesErrorOrderAndIO(t *testing.T) {
	var typedNil *struct{}
	for _, command := range []any{nil, typedNil, struct{}{}, []byte("command")} {
		writer := new(commandWriteProbe)
		if err := MarshalCommand(command, writer); err != ErrUnknownCommand || writer.calls != 0 {
			t.Fatalf("marshal rejection: error=%v writes=%d", err, writer.calls)
		}
	}
	valid := make([]byte, 5)
	valid[4] = 0x42
	binary.BigEndian.PutUint32(valid, Authenticate(valid[4:]))
	invalid := bytes.Clone(valid)
	invalid[0] ^= 1
	for id := range 256 {
		for length := range 5 {
			if command, err := UnmarshalCommand(byte(id), valid[:length]); err != ErrInsufficientLength || command != nil {
				t.Fatalf("short command id=%d length=%d: %v %v", id, length, command, err)
			}
		}
		if command, err := UnmarshalCommand(byte(id), invalid); err != ErrInvalidAuth || command != nil {
			t.Fatalf("invalid authentication id=%d: %v %v", id, command, err)
		}
		if command, err := UnmarshalCommand(byte(id), valid); err != ErrUnknownCommand || command != nil {
			t.Fatalf("unknown authenticated command id=%d: %v %v", id, command, err)
		}
	}
}

func TestResponseCommandRejectionPreservesHeaderAndBodyFraming(t *testing.T) {
	client := NewClientSession(context.Background(), 0)
	payload := []byte("body immediately after the response header")
	request := &protocol.RequestHeader{
		Command: protocol.RequestCommandTCP, Security: protocol.SecurityType_AES128_GCM,
		Option: protocol.RequestOptionChunkStream,
	}
	var expectedWire []byte
	for _, command := range []any{nil, struct{}{}, (*struct{})(nil)} {
		server := &ServerSession{
			requestBodyKey: client.requestBodyKey, requestBodyIV: client.requestBodyIV,
			responseHeader: client.responseHeader,
		}
		var wire bytes.Buffer
		server.EncodeResponseHeader(&protocol.ResponseHeader{Option: 0x80, Command: command}, &wire)
		writer, err := server.EncodeResponseBody(request, &wire)
		if err != nil {
			t.Fatal(err)
		}
		packet := buf.New()
		_, _ = packet.Write(payload)
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
		if expectedWire == nil {
			expectedWire = bytes.Clone(wire.Bytes())
		} else if !bytes.Equal(wire.Bytes(), expectedWire) {
			t.Fatal("rejected command changed native response wire bytes")
		}
		header, err := client.DecodeResponseHeader(&wire)
		if err != nil || header.Command != nil || header.Option != 0x80 {
			t.Fatalf("response header: %+v %v", header, err)
		}
		reader, err := client.DecodeResponseBody(request, &wire)
		if err != nil {
			t.Fatal(err)
		}
		body, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(body)
			t.Fatal(err)
		}
		var got []byte
		for _, part := range body {
			got = append(got, part.Bytes()...)
		}
		buf.ReleaseMulti(body)
		if !bytes.Equal(got, payload) || wire.Len() != 0 {
			t.Fatalf("response body alignment: %q trailing=%d", got, wire.Len())
		}
	}
}
