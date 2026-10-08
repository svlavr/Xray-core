package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	crypto "github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
)

type authenticationSealFailure struct {
	crypto.Authenticator
	calls, failAt int
}

func (a *authenticationSealFailure) Seal(dst, payload []byte) ([]byte, error) {
	a.calls++
	if a.calls == a.failAt {
		return nil, errors.New("test seal failure")
	}
	return a.Authenticator.Seal(dst, payload)
}

func inspectionAuthenticationAuth() *crypto.AEADAuthenticator {
	return &crypto.AEADAuthenticator{AEAD: crypto.NewAesGcm(make([]byte, 16)), NonceGenerator: crypto.GenerateStaticBytes(make([]byte, 12))}
}

func TestAuthenticationSealFailureKeepsOlderBufferedFrame(t *testing.T) {
	var wire bytes.Buffer
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: &wire})
	defer buf.DiscardBufferedWriter(buffered)
	writer := crypto.NewAuthenticationWriter(&authenticationSealFailure{Authenticator: inspectionAuthenticationAuth(), failAt: 3}, crypto.PlainChunkSizeParser{}, buffered, protocol.TransferTypeStream, nil)
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("kept"))); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte("d"), buf.Size+7))); err == nil {
		t.Fatal("seal failure was lost")
	}
	if wire.Len() != 0 {
		t.Fatal("buffered response was emitted before flush")
	}
	if err := buffered.Flush(); err != nil {
		t.Fatal(err)
	}
	reader := crypto.NewAuthenticationReader(inspectionAuthenticationAuth(), crypto.PlainChunkSizeParser{}, &wire, protocol.TransferTypeStream, nil)
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if got := string(mb[0].Bytes()); got != "kept" {
		t.Fatalf("earlier buffered frame = %q", got)
	}
}

func TestAuthenticationPacketOversizeKeepsValidPacket(t *testing.T) {
	var wire bytes.Buffer
	writer := crypto.NewAuthenticationWriter(inspectionAuthenticationAuth(), crypto.PlainChunkSizeParser{}, &wire, protocol.TransferTypePacket, nil)
	packets := buf.MergeBytes(nil, []byte("ok"))
	oversized := buf.New()
	oversized.Extend(buf.Size)
	packets = append(packets, oversized)
	if err := writer.WriteMultiBuffer(packets); err != nil {
		t.Fatal(err)
	}
	reader := crypto.NewAuthenticationReader(inspectionAuthenticationAuth(), crypto.PlainChunkSizeParser{}, &wire, protocol.TransferTypePacket, nil)
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || string(mb[0].Bytes()) != "ok" {
		t.Fatalf("valid packet changed: %+v", mb)
	}
}
