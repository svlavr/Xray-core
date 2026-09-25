//go:build linux || android

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/sys/unix"
)

func rawSpliceContext(t *testing.T, dst net.Conn, ready int) (context.Context, *session.Inbound, *signal.ActivityTimer) {
	t.Helper()
	inbound := &session.Inbound{Conn: dst, CanSpliceCopy: ready}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	timer := signal.CancelAfterInactivity(ctx, func() {}, time.Hour)
	t.Cleanup(func() { timer.SetTimeout(0) })
	return ctx, inbound, timer
}

type rawSpliceReadyWriter struct {
	io.Writer
	inbound *session.Inbound
}

func (w rawSpliceReadyWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n == len(p) {
		w.inbound.CanSpliceCopy = 1
	}
	return n, err
}

// The readiness transition is owned by the completed prefix write, like the
// native Vision boundary. This proves ordering at the shared raw seam, not a
// complete Vision protocol integration.
func TestRawSpliceCallerReadyPrefix(t *testing.T) {
	sourceWriter, sourceReader := newRawTCPPair(t)
	destinationWriter, destinationReader := newRawTCPPair(t)
	ctx, inbound, timer := rawSpliceContext(t, destinationWriter, 2)
	exchange := &rawSpliceTestExchange{added: make(chan uint64, 8)}
	writer := buf.AttachWriterReceipt(&buf.BufferToBytesWriter{Writer: rawSpliceReadyWriter{Writer: destinationWriter, inbound: inbound}}, exchange)
	result := make(chan error, 1)
	go func() { result <- CopyRawConnIfExist(ctx, sourceReader, destinationWriter, writer, timer, nil) }()
	prefix, raw := []byte("retained-prefix"), []byte("then-native-raw")
	for _, payload := range [][]byte{prefix, raw} {
		if _, err := sourceWriter.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := destinationReader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(destinationReader, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("ordered prefix changed: %q", got)
		}
		select {
		case <-exchange.added:
		case <-time.After(2 * time.Second):
			t.Fatal("no pre-EOF receipt")
		}
	}
	if err := sourceWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw caller did not end")
	}
	if exchange.downlink.Load() != uint64(len(prefix)+len(raw)) {
		t.Fatal("retained prefix was lost or counted twice")
	}
	if got := stats.EndReason(exchange.reason.Load()); got != stats.EndReasonEOF {
		t.Fatalf("raw splice end reason = %v, want EOF", got)
	}
}

func TestRawSpliceCallerOmitsPipeResidue(t *testing.T) {
	sourceWriter, sourceReader := newRawTCPPair(t)
	destinationWriter, _ := newRawTCPPair(t)
	if err := destinationWriter.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := destinationWriter.SetWriteDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	ctx, _, timer := rawSpliceContext(t, destinationWriter, 1)
	exchange := new(rawSpliceTestExchange)
	payload := bytes.Repeat([]byte{0x65}, 8<<20)
	sent := make(chan error, 1)
	go func() {
		_, err := io.Copy(sourceWriter, bytes.NewReader(payload))
		sourceWriter.CloseWrite()
		sent <- err
	}()
	writer := buf.NewWriter(destinationWriter)
	writer = buf.AttachWriterReceipt(writer, exchange)
	err := CopyRawConnIfExist(ctx, sourceReader, destinationWriter, writer, timer, nil)
	if err == nil || exchange.downlink.Load() == 0 {
		t.Fatalf("accepted=%d err=%v", exchange.downlink.Load(), err)
	}
	if err = sourceReader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	remaining, err := io.ReadAll(sourceReader)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-sent; err != nil {
		t.Fatal(err)
	}
	if exchange.downlink.Load()+uint64(len(remaining)) >= uint64(len(payload)) {
		t.Fatal("caller unexpectedly reconstructed pipe residue")
	}
}

func TestRawSpliceCallerReadvFallback(t *testing.T) {
	source, peer := net.Pipe()
	t.Cleanup(func() { source.Close(); peer.Close() })
	destinationWriter, destinationReader := newRawTCPPair(t)
	ctx, _, timer := rawSpliceContext(t, destinationWriter, 1)
	exchange := new(rawSpliceTestExchange)
	payload := []byte("unsupported-raw-source-readv-fallback")
	go func() { peer.Write(payload); peer.Close() }()
	done := make(chan error, 1)
	writer := buf.NewWriter(destinationWriter)
	writer = buf.AttachWriterReceipt(writer, exchange)
	go func() {
		done <- CopyRawConnIfExist(ctx, source, destinationWriter, writer, timer, nil)
	}()
	destinationReader.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(destinationReader, got); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback did not finish")
	}
	if !bytes.Equal(got, payload) || exchange.downlink.Load() != uint64(len(payload)) {
		t.Fatal("fallback lost, dropped or doubled payload")
	}
	if got := stats.EndReason(exchange.reason.Load()); got != stats.EndReasonEOF {
		t.Fatalf("readv fallback end reason = %v, want EOF", got)
	}
}

func TestRawSplicePipeSetupFallback(t *testing.T) {
	const marker = "XRAY_TEST_RAW_SPLICE_NOFILE"
	if os.Getenv(marker) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRawSplicePipeSetupFallback$")
		cmd.Env = append(os.Environ(), marker+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated descriptor-limit check: %v\n%s", err, out)
		}
		return
	}
	sourceWriter, sourceReader := newRawTCPPair(t)
	destinationWriter, _ := newRawTCPPair(t)
	payload := []byte("not-consumed-by-failed-pipe-setup")
	if _, err := sourceWriter.Write(payload); err != nil {
		t.Fatal(err)
	}
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 0, Max: old.Max}); err != nil {
		t.Fatal(err)
	}
	n, handled, err := copySpliceProgress(destinationWriter, sourceReader, &rawCopyReceipt{})
	if restoreErr := unix.Setrlimit(unix.RLIMIT_NOFILE, &old); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if n != 0 || handled || !errors.Is(err, unix.EMFILE) {
		t.Fatalf("setup fallback n=%d handled=%v err=%v", n, handled, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sourceReader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("failed setup consumed input")
	}
}

// This benchmark measures the raw transfer and existing counters only. Socket
// setup, logical admission/binding, final publication and snapshots are outside
// its timer; it is not an end-to-end core or retained-memory measurement.
func BenchmarkRawCopyProgress(b *testing.B) {
	for _, size := range []int{64 << 10, 2 << 20} {
		for _, observed := range []bool{false, true} {
			name := map[int]string{64 << 10: "64KiB", 2 << 20: "2MiB"}[size] + map[bool]string{false: "/native", true: "/observed"}[observed]
			b.Run(name, func(b *testing.B) {
				b.StopTimer()
				payload := bytes.Repeat([]byte{0x5a}, size)
				manager, _ := appstats.NewManager(context.Background(), &appstats.Config{})
				b.Cleanup(func() { manager.Close() })
				if _, err := manager.EnableInspection(stats.ObservationOptions{}); err != nil {
					b.Fatal(err)
				}
				readCounter, writeCounter, userCounter := new(rawSpliceTestCounter), new(rawSpliceTestCounter), new(rawSpliceTestCounter)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					sw, sr := newRawTCPPair(b)
					dw, dr := newRawTCPPair(b)
					deadline := time.Now().Add(5 * time.Second)
					for _, conn := range []*net.TCPConn{sw, sr, dw, dr} {
						if err := conn.SetDeadline(deadline); err != nil {
							b.Fatal(err)
						}
					}
					sent, received := make(chan error, 1), make(chan error, 1)
					scratch := make([]byte, 32<<10)
					go func() { _, err := sw.Write(payload); sw.CloseWrite(); sent <- err }()
					go func() {
						remaining := size
						for remaining > 0 {
							n, err := dr.Read(scratch[:min(remaining, len(scratch))])
							remaining -= n
							if err != nil {
								received <- err
								return
							}
						}
						received <- nil
					}()
					var flow stats.Exchange
					if observed {
						flow = manager.Observation().Begin(stats.FlowKindTCP, stats.TrafficOriginUser, xnet.Destination{}, xnet.Destination{}, nil)
						flow.Route(stats.RouteStep{Selection: stats.SelectionDefault, Outbound: stats.OutboundRef{Serial: 1}})
						flow.BindRoute()
					}
					b.StartTimer()
					var n int64
					var err error
					if observed {
						var handled bool
						n, handled, err = copySpliceProgress(dw, sr, &rawCopyReceipt{exchange: flow, readCounter: readCounter, writeCounter: writeCounter, userCounter: userCounter})
						if !handled {
							b.Fatal("benchmark missed native splice")
						}
					} else {
						n, err = dw.ReadFrom(sr)
						readCounter.Add(n)
						writeCounter.Add(n)
						userCounter.Add(n)
					}
					b.StopTimer()
					if err != nil || n != int64(size) {
						b.Fatalf("copy n=%d err=%v", n, err)
					}
					if err = <-sent; err != nil {
						b.Fatal(err)
					}
					if err = <-received; err != nil {
						b.Fatal(err)
					}
					if flow != nil {
						flow.SetEndReason(stats.EndReasonEOF)
						flow.Finish()
					}
					sw.Close()
					sr.Close()
					dw.Close()
					dr.Close()
				}
				for _, counter := range []*rawSpliceTestCounter{readCounter, writeCounter, userCounter} {
					if counter.Value() != int64(size)*int64(b.N) {
						b.Fatal("benchmark counter mismatch")
					}
				}
			})
		}
	}
}
