package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	crypto "github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	fs "github.com/xtls/xray-core/features/stats"
)

type authenticationOutput struct {
	bytes.Buffer
	limit  int
	fail   error
	writes []int
}

func (w *authenticationOutput) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	n := len(p)
	if w.limit >= 0 {
		n = min(n, w.limit-w.Len())
	}
	if n < 0 {
		n = 0
	}
	w.Buffer.Write(p[:n])
	if w.limit >= 0 && w.Len() >= w.limit {
		return n, w.fail
	}
	return n, nil
}

func authenticationFlow(t *testing.T) (fs.Exchange, fs.FlowInspection) {
	t.Helper()
	manager := new(appstats.Manager)
	view, err := manager.EnableInspection(fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.Close() })
	flow := manager.Observation().Begin(fs.FlowKindTCP, fs.TrafficOriginUser, net.Destination{}, net.Destination{}, nil)
	flow.Route(fs.RouteStep{Selection: fs.SelectionDefault, Outbound: fs.OutboundRef{Tag: "direct", Serial: 1}})
	flow.BindRoute()
	return flow, view
}

func authenticationFact(t *testing.T, view fs.FlowInspection) fs.ByteFact {
	t.Helper()
	live, err := view.ReadLive(context.Background())
	if err != nil || len(live.Rows) != 1 {
		t.Fatalf("codec live facts: %+v %v", live, err)
	}
	return live.Rows[0].Downlink
}

func authenticationAuth() *crypto.AEADAuthenticator {
	return &crypto.AEADAuthenticator{AEAD: crypto.NewAesGcm(make([]byte, 16)), NonceGenerator: crypto.GenerateStaticBytes(make([]byte, 12))}
}

func authenticationWriter(output *authenticationOutput, vector bool, transfer protocol.TransferType) (*crypto.AuthenticationWriter, *buf.BufferedWriter) {
	var lower buf.Writer = &buf.SequentialWriter{Writer: output}
	if vector {
		lower = &buf.BufferToBytesWriter{Writer: output}
	}
	buffered := buf.NewBufferedWriter(lower)
	buffered.Write([]byte("header!"))
	return crypto.NewAuthenticationWriter(authenticationAuth(), crypto.PlainChunkSizeParser{}, buffered, transfer, nil), buffered
}

func TestInspectionAuthenticationPartialFrames(t *testing.T) {
	const header = 7
	const chunkPayload = buf.Size - 16 - 2
	payload := bytes.Repeat([]byte("p"), 2*chunkPayload+7)
	const total = header + 2*buf.Size + 7 + 16 + 2
	for _, vector := range []bool{false, true} {
		for _, limit := range []int{0, header - 1, header, header + 1, header + buf.Size, header + buf.Size + 1, total - 1, total} {
			t.Run(strconv.FormatBool(vector)+"/"+strconv.Itoa(limit), func(t *testing.T) {
				flow, view := authenticationFlow(t)
				output := &authenticationOutput{limit: limit, fail: io.ErrUnexpectedEOF}
				native, buffered := authenticationWriter(output, vector, protocol.TransferTypeStream)
				writer, finish := crypto.ObserveAuthenticationWriter(native, flow)
				if finish == nil {
					t.Fatal("native codec receipt unavailable")
				}
				err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload))
				if err == nil {
					err = buffered.SetBuffered(false)
				}
				if err == nil {
					t.Fatal("injected writer failure was lost")
				}
				finish()
				fact := authenticationFact(t, view)
				known := uint64(0)
				incomplete := true
				if limit >= total-1 {
					known = uint64(len(payload))
					incomplete = false
				}
				if fact.Known != known || fact.Incomplete != incomplete {
					t.Fatalf("limit %d, codec result %+v", limit, fact)
				}
				if output.Len() != limit {
					t.Fatalf("accepted wire length: %d want %d", output.Len(), limit)
				}
			})
		}
	}
}

func TestInspectionAuthenticationBufferingAndNativeBatch(t *testing.T) {
	for _, vector := range []bool{false, true} {
		flow, view := authenticationFlow(t)
		output := &authenticationOutput{limit: -1}
		native, buffered := authenticationWriter(output, vector, protocol.TransferTypeStream)
		writer, finish := crypto.ObserveAuthenticationWriter(native, flow)
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("first"))); err != nil {
			t.Fatal(err)
		}
		if fact := authenticationFact(t, view); fact.Known != 5 || output.Len() != 0 {
			t.Fatalf("buffered payload credited: %+v", fact)
		}
		if err := buffered.SetBuffered(false); err != nil {
			t.Fatal(err)
		}
		more := bytes.Repeat([]byte("m"), 3*buf.Size)
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, more)); err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteMultiBuffer(nil); err != nil {
			t.Fatal(err)
		}
		finish()
		if fact := authenticationFact(t, view); fact.Known != uint64(5+len(more)) || fact.Incomplete {
			t.Fatalf("codec payload/framing: %+v", fact)
		}
		control := &authenticationOutput{limit: -1}
		plain, plainBuffer := authenticationWriter(control, vector, protocol.TransferTypeStream)
		unchanged, cleanup := crypto.ObserveAuthenticationWriter(plain, nil)
		if unchanged != plain || cleanup != nil {
			t.Fatal("disabled codec identity changed")
		}
		plain.WriteMultiBuffer(buf.MergeBytes(nil, []byte("first")))
		plainBuffer.SetBuffered(false)
		plain.WriteMultiBuffer(buf.MergeBytes(nil, more))
		plain.WriteMultiBuffer(nil)
		if !bytes.Equal(control.Bytes(), output.Bytes()) || !slices.Equal(control.writes, output.writes) {
			t.Fatalf("native wire bytes/batch shape changed: %v / %v", control.writes, output.writes)
		}
	}
}

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

func TestInspectionAuthenticationSealFailureKeepsOlderBuffer(t *testing.T) {
	flow, view := authenticationFlow(t)
	output := &authenticationOutput{limit: -1}
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: output})
	native := crypto.NewAuthenticationWriter(&authenticationSealFailure{Authenticator: authenticationAuth(), failAt: 3}, crypto.PlainChunkSizeParser{}, buffered, protocol.TransferTypeStream, nil)
	writer, finish := crypto.ObserveAuthenticationWriter(native, flow)
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("kept"))); err != nil {
		t.Fatal(err)
	}
	discarded := bytes.Repeat([]byte("d"), buf.Size+7)
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, discarded)); err == nil {
		t.Fatal("seal failure was lost")
	}
	if err := buffered.Flush(); err != nil {
		t.Fatal(err)
	}
	finish()
	if fact := authenticationFact(t, view); fact.Known != 4 || fact.Incomplete {
		t.Fatalf("rollback erased older frame: %+v", fact)
	}
}

func TestInspectionAuthenticationPacketDropsAndAbandon(t *testing.T) {
	flow, view := authenticationFlow(t)
	output := &authenticationOutput{limit: -1}
	native, buffered := authenticationWriter(output, false, protocol.TransferTypePacket)
	writer, finish := crypto.ObserveAuthenticationWriter(native, flow)
	mb := buf.MergeBytes(nil, []byte("ok"))
	oversized := buf.New()
	oversized.Extend(buf.Size)
	mb = append(mb, oversized)
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if err := buffered.SetBuffered(false); err != nil {
		t.Fatal(err)
	}
	finish()
	if fact := authenticationFact(t, view); fact.Known != 2 || fact.Incomplete {
		t.Fatalf("packet seal drop: %+v", fact)
	}
	other, otherView := authenticationFlow(t)
	abandoned := &authenticationOutput{limit: -1}
	prepared, abandonedBuffer := authenticationWriter(abandoned, false, protocol.TransferTypeStream)
	observed, release := crypto.ObserveAuthenticationWriter(prepared, other)
	observed.WriteMultiBuffer(buf.MergeBytes(nil, []byte("abandoned")))
	release()
	if err := abandonedBuffer.Flush(); err != nil {
		t.Fatal(err)
	}
	if abandoned.Len() != 0 {
		t.Fatal("cleanup emitted a native-abandoned response")
	}
	if fact := authenticationFact(t, otherView); fact.Known != 9 || fact.Incomplete {
		t.Fatalf("abandoned mapping: %+v", fact)
	}
}

func TestInspectionAuthenticationFailedFlushContinuation(t *testing.T) {
	flow, view := authenticationFlow(t)
	output := &authenticationOutput{limit: 8, fail: io.ErrUnexpectedEOF}
	native, buffered := authenticationWriter(output, false, protocol.TransferTypeStream)
	writer, finish := crypto.ObserveAuthenticationWriter(native, flow)
	writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("old")))
	if err := buffered.Flush(); err == nil {
		t.Fatal("flush failure was lost")
	}
	output.limit = -1
	writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("new")))
	if err := buffered.SetBuffered(false); err != nil {
		t.Fatal(err)
	}
	finish()
	if fact := authenticationFact(t, view); fact.Known != 6 || fact.Incomplete {
		t.Fatalf("stale failed-frame mapping: %+v", fact)
	}
}

type opaqueAuthenticationOutput struct{ io.Writer }

func (opaqueAuthenticationOutput) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func TestInspectionAuthenticationUnavailableAndZeroProgress(t *testing.T) {
	flow, view := authenticationFlow(t)
	native := crypto.NewAuthenticationWriter(authenticationAuth(), crypto.PlainChunkSizeParser{}, opaqueAuthenticationOutput{Writer: io.Discard}, protocol.TransferTypeStream, nil)
	writer, finish := crypto.ObserveAuthenticationWriter(native, flow)
	if writer == native || finish == nil {
		t.Fatal("decoded codec owner was not observed")
	}
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("accepted"))); err != nil {
		t.Fatal(err)
	}
	finish()
	if fact := authenticationFact(t, view); fact.Known != 8 || fact.Incomplete {
		t.Fatalf("decoded operation result: %+v", fact)
	}
	other, otherView := authenticationFlow(t)
	output := &authenticationOutput{limit: 0, fail: io.ErrUnexpectedEOF}
	prepared, buffered := authenticationWriter(output, false, protocol.TransferTypeStream)
	observed, release := crypto.ObserveAuthenticationWriter(prepared, other)
	if err := observed.WriteMultiBuffer(buf.MergeBytes(nil, []byte("pending"))); err != nil {
		t.Fatal(err)
	}
	if err := buffered.Flush(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("zero progress result: %v", err)
	}
	release()
	if fact := authenticationFact(t, otherView); fact.Known != 7 || fact.Incomplete {
		t.Fatalf("zero acceptance mapping: %+v", fact)
	}
}
