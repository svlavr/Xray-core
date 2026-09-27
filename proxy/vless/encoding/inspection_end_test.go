package encoding

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

type inspectionEndReader struct {
	buffer buf.MultiBuffer
	err    error
}

func (r *inspectionEndReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := r.buffer, r.err
	r.buffer, r.err = nil, io.EOF
	return buffer, err
}

type inspectionTimeoutError struct{}

func (inspectionTimeoutError) Error() string { return "inspection timeout" }
func (inspectionTimeoutError) Timeout() bool { return true }

type inspectionEndWriter struct{ err error }

func (w inspectionEndWriter) Write(p []byte) (int, error) { return 0, w.err }

func inspectionTerminal(t *testing.T, flow fs.Exchange, view fs.FlowInspection) fs.TerminalRecord {
	t.Helper()
	flow.Finish()
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal page: %+v %v", page, err)
	}
	if page.Rows[0].Flow.State != fs.FlowStateEnded {
		t.Fatalf("flow did not end: %+v", page.Rows[0])
	}
	return page.Rows[0]
}

func inspectionActivityTimer(t *testing.T) *signal.ActivityTimer {
	t.Helper()
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	t.Cleanup(func() { timer.SetTimeout(0) })
	return timer
}

func TestInspectionXtlsReadNativeResults(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "read-error", err: io.ErrUnexpectedEOF},
		{name: "timeout", err: inspectionTimeoutError{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow, view := inspectionPacketFlow(t)
			err := XtlsRead(&inspectionEndReader{err: test.err}, buf.NewWriter(io.Discard), inspectionActivityTimer(t), nil, proxy.NewTrafficState(nil), false, context.Background())
			if (test.err == io.EOF) != (err == nil) {
				t.Fatalf("XtlsRead error = %v", err)
			}
			if got := inspectionTerminal(t, flow, view); got.Flow.Downlink.Known != 0 {
				t.Fatalf("read result invented bytes: %+v", got)
			}
		})
	}
}

func TestInspectionXtlsReadWriterCauseAndLocalStop(t *testing.T) {
	t.Run("writer", func(t *testing.T) {
		flow, view := inspectionPacketFlow(t)
		writer := buf.AttachWriterReceipt(buf.NewWriter(inspectionEndWriter{err: io.ErrClosedPipe}), flow)
		err := XtlsRead(&inspectionEndReader{buffer: buf.MultiBuffer{buf.FromBytes([]byte("response"))}}, writer, inspectionActivityTimer(t), nil, proxy.NewTrafficState(nil), false, context.Background())
		if err == nil {
			t.Fatal("writer failure was lost")
		}
		if got := inspectionTerminal(t, flow, view); got.Flow.Downlink.Known != 0 {
			t.Fatalf("failed opaque write invented bytes: %+v", got)
		}
	})

	t.Run("local-stop", func(t *testing.T) {
		flow, view := inspectionPacketFlow(t)
		outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
		if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("stop: %+v %v", outcomes, err)
		}
		if err := XtlsRead(&inspectionEndReader{err: io.ErrUnexpectedEOF}, buf.NewWriter(io.Discard), inspectionActivityTimer(t), nil, proxy.NewTrafficState(nil), false, context.Background()); err == nil {
			t.Fatal("source failure was lost")
		}
		inspectionTerminal(t, flow, view)
	})
}

func TestInspectionXtlsReadRawFallbackResults(t *testing.T) {
	for _, test := range []struct {
		name      string
		writerErr error
		attached  bool
		localStop bool
		wantBytes uint64
	}{
		{name: "attached-EOF", attached: true, wantBytes: uint64(len("raw response"))},
		{name: "exact-exchange-EOF"},
		{name: "attached-writer", writerErr: io.ErrClosedPipe, attached: true},
		{name: "unattached-writer", writerErr: io.ErrClosedPipe},
		{name: "exact-exchange-local-stop", localStop: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow, view := inspectionPacketFlow(t)
			if test.localStop {
				outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
				if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
					t.Fatalf("stop: %+v %v", outcomes, err)
				}
			}
			source, peer := net.Pipe()
			t.Cleanup(func() { source.Close(); peer.Close() })
			go func() {
				_, _ = peer.Write([]byte("raw response"))
				_ = peer.Close()
			}()
			var output io.Writer = io.Discard
			if test.writerErr != nil {
				output = inspectionEndWriter{err: test.writerErr}
			}
			writer := buf.NewWriter(output)
			if test.attached {
				writer = buf.AttachWriterReceipt(writer, flow)
			}
			state := proxy.NewTrafficState(nil)
			state.Outbound.DownlinkReaderDirectCopy = true
			err := XtlsRead(buf.NewReader(bytes.NewReader(nil)), writer, inspectionActivityTimer(t), source, state, false, context.Background())
			if (test.writerErr == nil) != (err == nil) {
				t.Fatalf("raw fallback error = %v", err)
			}
			if got := inspectionTerminal(t, flow, view); got.Flow.Downlink.Known != test.wantBytes {
				t.Fatalf("raw fallback counted bytes: %+v want %d", got, test.wantBytes)
			}
		})
	}
}
