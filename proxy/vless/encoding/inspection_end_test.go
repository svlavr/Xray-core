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

func inspectionTerminalReason(t *testing.T, flow fs.Exchange, view fs.FlowInspection) fs.EndReason {
	t.Helper()
	flow.Finish()
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("terminal page: %+v %v", page, err)
	}
	return page.Rows[0].Reason
}

func inspectionActivityTimer(t *testing.T) *signal.ActivityTimer {
	t.Helper()
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour)
	t.Cleanup(func() { timer.SetTimeout(0) })
	return timer
}

func TestInspectionXtlsReadEndReasons(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want fs.EndReason
	}{
		{name: "EOF", err: io.EOF, want: fs.EndReasonEOF},
		{name: "read-error", err: io.ErrUnexpectedEOF, want: fs.EndReasonReadError},
		{name: "timeout", err: inspectionTimeoutError{}, want: fs.EndReasonTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow, view := inspectionPacketFlow(t)
			err := XtlsRead(&inspectionEndReader{err: test.err}, buf.NewWriter(io.Discard), inspectionActivityTimer(t), nil, proxy.NewTrafficState(nil), false, context.Background(), flow)
			if (test.err == io.EOF) != (err == nil) {
				t.Fatalf("XtlsRead error = %v", err)
			}
			if got := inspectionTerminalReason(t, flow, view); got != test.want {
				t.Fatalf("end reason = %v, want %v", got, test.want)
			}
		})
	}
}

func TestInspectionXtlsReadWriterCauseAndLocalStop(t *testing.T) {
	t.Run("writer", func(t *testing.T) {
		flow, view := inspectionPacketFlow(t)
		writer := buf.AttachWriterReceipt(buf.NewWriter(inspectionEndWriter{err: io.ErrClosedPipe}), flow)
		err := XtlsRead(&inspectionEndReader{buffer: buf.MultiBuffer{buf.FromBytes([]byte("response"))}}, writer, inspectionActivityTimer(t), nil, proxy.NewTrafficState(nil), false, context.Background(), flow)
		if err == nil {
			t.Fatal("writer failure was lost")
		}
		if got := inspectionTerminalReason(t, flow, view); got != fs.EndReasonWriteError {
			t.Fatalf("end reason = %v, want write error", got)
		}
	})

	t.Run("local-stop", func(t *testing.T) {
		flow, view := inspectionPacketFlow(t)
		outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{flow.Ref()})
		if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
			t.Fatalf("stop: %+v %v", outcomes, err)
		}
		if err := XtlsRead(&inspectionEndReader{err: io.ErrUnexpectedEOF}, buf.NewWriter(io.Discard), inspectionActivityTimer(t), nil, proxy.NewTrafficState(nil), false, context.Background(), flow); err == nil {
			t.Fatal("source failure was lost")
		}
		if got := inspectionTerminalReason(t, flow, view); got != fs.EndReasonLocalStop {
			t.Fatalf("end reason = %v, want local stop", got)
		}
	})
}

func TestInspectionXtlsReadRawFallbackEndReasons(t *testing.T) {
	for _, test := range []struct {
		name      string
		writerErr error
		attached  bool
		localStop bool
		want      fs.EndReason
	}{
		{name: "attached-EOF", attached: true, want: fs.EndReasonEOF},
		{name: "exact-exchange-EOF", want: fs.EndReasonEOF},
		{name: "attached-writer", writerErr: io.ErrClosedPipe, attached: true, want: fs.EndReasonWriteError},
		{name: "unattached-writer-unknown", writerErr: io.ErrClosedPipe, want: fs.EndReasonUnknown},
		{name: "exact-exchange-local-stop", localStop: true, want: fs.EndReasonLocalStop},
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
			err := XtlsRead(buf.NewReader(bytes.NewReader(nil)), writer, inspectionActivityTimer(t), source, state, false, context.Background(), flow)
			if (test.writerErr == nil) != (err == nil) {
				t.Fatalf("raw fallback error = %v", err)
			}
			if got := inspectionTerminalReason(t, flow, view); got != test.want {
				t.Fatalf("end reason = %v, want %v", got, test.want)
			}
		})
	}
}
