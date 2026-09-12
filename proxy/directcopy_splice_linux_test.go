//go:build linux

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
)

type atomicDirectCopyProgress struct {
	bytes atomic.Uint64
	calls atomic.Uint64
}

type wrappedDirectCopyConn struct {
	*net.TCPConn
}

func (p *atomicDirectCopyProgress) Progress(delta uint64) {
	p.bytes.Add(delta)
	p.calls.Add(1)
}

func TestCopyRawConnSpliceUsesBoundedTCPReadFrom(t *testing.T) {
	const payloadSize = 3*directCopySpliceQuantum + 17
	progress := new(atomicDirectCopyProgress)
	written, received, err := runDirectCopyTCPTransfer(payloadSize, func(writer *net.TCPConn, reader *net.TCPConn) (int64, error) {
		written, direct, copyErr := copyRawConnSplice(writer, reader, progress)
		if !direct {
			t.Fatal("real TCP transfer unexpectedly used generic fallback")
		}
		return written, copyErr
	})
	if err != nil || written != payloadSize || received != payloadSize {
		t.Fatalf("real TCP direct copy changed payload or result: written=%d received=%d err=%v", written, received, err)
	}
	if progress.bytes.Load() != payloadSize || progress.calls.Load() == 0 {
		t.Fatalf("real TCP progress was not exact and bounded: bytes=%d calls=%d", progress.bytes.Load(), progress.calls.Load())
	}
}

func TestCopyRawConnSplicePreservesReadDeadline(t *testing.T) {
	reader, readerPeer := newDirectCopyTCPPair(t)
	writer, writerPeer := newDirectCopyTCPPair(t)
	defer reader.Close()
	defer readerPeer.Close()
	defer writer.Close()
	defer writerPeer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, writerPeer)
		close(readDone)
	}()

	written, direct, err := copyRawConnSplice(writer, reader, new(atomicDirectCopyProgress))
	if !direct {
		t.Fatal("deadline path unexpectedly used generic fallback")
	}
	if written != 0 {
		t.Fatalf("deadline path fabricated bytes: %d", written)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read deadline was not preserved: %v", err)
	}
	var operationErr *net.OpError
	if !errors.As(err, &operationErr) || operationErr.Op != "readfrom" {
		t.Fatalf("read deadline lost the stock ReadFrom error envelope: %v", err)
	}
	_ = writer.CloseWrite()
	<-readDone
}

func TestCopyRawConnSplicePreservesWriteDeadlineAndPartialCount(t *testing.T) {
	reader, readerPeer := newDirectCopyTCPPair(t)
	writer, writerPeer := newDirectCopyTCPPair(t)
	defer reader.Close()
	defer readerPeer.Close()
	defer writer.Close()
	defer writerPeer.Close()
	if err := writer.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	sourceDone := make(chan error, 1)
	go func() {
		_, err := io.CopyN(readerPeer, zeroDirectCopyReader{}, 64<<20)
		sourceDone <- err
	}()

	progress := new(atomicDirectCopyProgress)
	written, direct, err := copyRawConnSplice(writer, reader, progress)
	_ = reader.Close()
	<-sourceDone
	var netErr net.Error
	if !direct || !errors.As(err, &netErr) || !netErr.Timeout() || written == 0 {
		t.Fatalf("write deadline was not preserved with partial direct-copy proof: direct=%v written=%d err=%v", direct, written, err)
	}
	if progress.bytes.Load() != uint64(written) {
		t.Fatalf("write deadline lost its exact destination boundary: progress=%d written=%d", progress.bytes.Load(), written)
	}
	var operationErr *net.OpError
	if !errors.As(err, &operationErr) || operationErr.Op != "readfrom" {
		t.Fatalf("write deadline lost the stock ReadFrom error envelope: %v", err)
	}
}

func TestCopyRawConnSplicePublishesProgressBeforeEOF(t *testing.T) {
	reader, readerPeer := newDirectCopyTCPPair(t)
	writer, writerPeer := newDirectCopyTCPPair(t)
	defer reader.Close()
	defer readerPeer.Close()
	defer writer.Close()
	defer writerPeer.Close()
	progress := new(atomicDirectCopyProgress)
	copyDone := make(chan struct {
		written int64
		direct  bool
		err     error
	}, 1)
	go func() {
		written, direct, err := copyRawConnSplice(writer, reader, progress)
		copyDone <- struct {
			written int64
			direct  bool
			err     error
		}{written: written, direct: direct, err: err}
	}()
	receivedDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, writerPeer)
		receivedDone <- err
	}()

	const writeSize = 64 << 10
	if written, err := io.CopyN(readerPeer, zeroDirectCopyReader{}, writeSize); err != nil || written != writeSize {
		t.Fatalf("failed to feed live-progress payload: written=%d err=%v", written, err)
	}
	payloadSize := int64(writeSize)
	deadline := time.Now().Add(2 * time.Second)
	for progress.bytes.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := progress.bytes.Load(); got == 0 || got > uint64(payloadSize) {
		t.Fatalf("direct-copy progress was not published before EOF: got=%d payload=%d", got, payloadSize)
	}
	if err := readerPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := <-copyDone
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if receiveErr := <-receivedDone; receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if result.err != nil || !result.direct || result.written != payloadSize || progress.bytes.Load() != uint64(payloadSize) {
		t.Fatalf("live-progress transfer did not finish exactly: result=%+v progress=%d", result, progress.bytes.Load())
	}
}

func TestCopyRawConnIfExistPublishesProvenKernelProgress(t *testing.T) {
	const payloadSize = 2*directCopySpliceQuantum + 31
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:source:1", "", flow_observation.ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "out", "freedom", "tcp:source:1", "", true, flow_observation.CarrierProofNotApplicable)
	ctx := flow_observation.ContextWithHandle(context.Background(), handle)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{CanSpliceCopy: 1})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	timerContext, cancelTimer := context.WithCancel(context.Background())
	defer cancelTimer()
	timer := signal.CancelAfterInactivity(timerContext, cancelTimer, time.Hour)
	defer timer.SetTimeout(0)

	written, received, copyErr := runDirectCopyTCPTransfer(payloadSize, func(writer *net.TCPConn, reader *net.TCPConn) (int64, error) {
		returnValue := CopyRawConnIfExist(ctx, reader, writer, buf.NewWriter(writer), timer, nil)
		if returnValue != nil {
			return 0, returnValue
		}
		return payloadSize, nil
	})
	if copyErr != nil || written != payloadSize || received != payloadSize {
		t.Fatalf("integrated direct copy changed payload or result: written=%d received=%d err=%v", written, received, copyErr)
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 {
		t.Fatalf("unexpected flow records: %+v", snapshot.Records)
	}
	var kernel *flow_observation.ByteObservation
	for index := range snapshot.Records[0].ByteObservations {
		observation := &snapshot.Records[0].ByteObservations[index]
		if observation.Direction == flow_observation.DirectionDownlink && observation.ByteScope == flow_observation.ByteScopeKernelDirectCopyAccepted {
			kernel = observation
			break
		}
	}
	if kernel == nil || kernel.State != flow_observation.ByteObservationStateProven || kernel.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: payloadSize}) {
		t.Fatalf("integrated kernel progress was not proven and exact: coverage=%+v observations=%+v lifecycle=%+v", snapshot.AccountingCoverage, snapshot.Records[0].ByteObservations, handle.LogicalRoot().View())
	}
}

func TestCopyRawConnIfExistLeavesGenericReadFromFallbackTypedIncomplete(t *testing.T) {
	const payloadSize = directCopySpliceQuantum + 19
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:source:1", "", flow_observation.ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "out", "freedom", "tcp:source:1", "", true, flow_observation.CarrierProofNotApplicable)
	ctx := flow_observation.ContextWithHandle(context.Background(), handle)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{CanSpliceCopy: 1})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	timerContext, cancelTimer := context.WithCancel(context.Background())
	defer cancelTimer()
	timer := signal.CancelAfterInactivity(timerContext, cancelTimer, time.Hour)
	defer timer.SetTimeout(0)

	written, received, copyErr := runDirectCopyTCPTransfer(payloadSize, func(writer *net.TCPConn, reader *net.TCPConn) (int64, error) {
		returnValue := CopyRawConnIfExist(ctx, &wrappedDirectCopyConn{TCPConn: reader}, writer, buf.NewWriter(writer), timer, nil)
		if returnValue != nil {
			return 0, returnValue
		}
		return payloadSize, nil
	})
	if copyErr != nil || written != payloadSize || received != payloadSize {
		t.Fatalf("generic ReadFrom fallback changed traffic: written=%d received=%d err=%v", written, received, copyErr)
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 {
		t.Fatalf("unexpected flow records: %+v", snapshot.Records)
	}
	var kernel *flow_observation.ByteObservation
	for index := range snapshot.Records[0].ByteObservations {
		observation := &snapshot.Records[0].ByteObservations[index]
		if observation.Direction == flow_observation.DirectionDownlink && observation.ByteScope == flow_observation.ByteScopeKernelDirectCopyAccepted {
			kernel = observation
			break
		}
	}
	if kernel == nil || kernel.State != flow_observation.ByteObservationStateF2Required || kernel.ObservedBytes.Known {
		t.Fatalf("generic fallback was mislabeled as kernel direct-copy bytes: %+v", snapshot.Records[0].ByteObservations)
	}
}

func TestCopyRawConnSpliceFirstEINVALUsesUntouchedStockFallback(t *testing.T) {
	const payloadSize = directCopySpliceQuantum + 19
	registry, registryErr := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if registryErr != nil {
		t.Fatal(registryErr)
	}
	defer registry.Close()
	handle := registry.AdmitTCP(context.Background(), "", "tcp:source:1", "", flow_observation.ByteScopeLogicalLinkAccepted)
	handle.SelectRoot("", "out", "freedom", "tcp:source:1", "", true, flow_observation.CarrierProofNotApplicable)
	operation := handle.BeginDeferredBytePath(flow_observation.DirectionDownlink, flow_observation.ByteScopeKernelDirectCopyAccepted)
	var injected atomic.Bool
	written, received, err := runDirectCopyTCPTransfer(payloadSize, func(writer *net.TCPConn, reader *net.TCPConn) (int64, error) {
		written, direct, copyErr := copyRawConnSpliceWith(writer, reader, operation, func(rfd int, roff *int64, wfd int, woff *int64, length int, flags int) (int64, error) {
			if injected.CompareAndSwap(false, true) {
				return 0, syscall.EINVAL
			}
			return systemDirectCopySplice(rfd, roff, wfd, woff, length, flags)
		})
		if direct {
			t.Fatal("zero-byte first EINVAL was mislabeled as direct copy")
		}
		operation.RequireF2()
		operation.Complete(0)
		return written, copyErr
	})
	if err != nil || written != payloadSize || received != payloadSize {
		t.Fatalf("first-EINVAL fallback changed payload or result: written=%d received=%d err=%v", written, received, err)
	}
	snapshot := registry.Snapshot()
	observation := findDirectCopyObservation(snapshot.Records[0].ByteObservations)
	if observation == nil || observation.State != flow_observation.ByteObservationStateF2Required || observation.ObservedBytes.Known || snapshot.AccountingCoverage.State != flow_observation.AccountingCoverageComplete {
		t.Fatalf("first-EINVAL fallback fabricated or lost telemetry state: coverage=%+v observations=%+v", snapshot.AccountingCoverage, snapshot.Records[0].ByteObservations)
	}
}

func TestCopyRawConnSplicePartialPumpErrorNeverFallsBack(t *testing.T) {
	const payloadSize = 32 << 10
	progress := new(atomicDirectCopyProgress)
	var calls atomic.Uint64
	written, received, err := runDirectCopyTCPTransfer(payloadSize, func(writer *net.TCPConn, reader *net.TCPConn) (int64, error) {
		written, direct, copyErr := copyRawConnSpliceWith(writer, reader, progress, func(rfd int, roff *int64, wfd int, woff *int64, length int, flags int) (int64, error) {
			if calls.Add(1) == 2 {
				if length > 4096 {
					length = 4096
				}
				accepted, spliceErr := systemDirectCopySplice(rfd, roff, wfd, woff, length, flags)
				if spliceErr != nil {
					return accepted, spliceErr
				}
				return accepted, syscall.EPIPE
			}
			return systemDirectCopySplice(rfd, roff, wfd, woff, length, flags)
		})
		if !direct {
			t.Fatal("partial destination acceptance switched to generic fallback")
		}
		return written, copyErr
	})
	if !errors.Is(err, syscall.EPIPE) || written == 0 || written >= payloadSize || received != written {
		t.Fatalf("partial pump error lost its exact boundary: written=%d received=%d err=%v", written, received, err)
	}
	if progress.bytes.Load() != uint64(written) || progress.calls.Load() != 1 {
		t.Fatalf("partial pump error progress was not exact: bytes=%d calls=%d written=%d", progress.bytes.Load(), progress.calls.Load(), written)
	}
}

func findDirectCopyObservation(observations []flow_observation.ByteObservation) *flow_observation.ByteObservation {
	for index := range observations {
		observation := &observations[index]
		if observation.Direction == flow_observation.DirectionDownlink && observation.ByteScope == flow_observation.ByteScopeKernelDirectCopyAccepted {
			return observation
		}
	}
	return nil
}

func BenchmarkDirectCopySpliceQuantum(b *testing.B) {
	const payloadSize = 256 << 20
	benchmarks := []struct {
		name     string
		quantum  int64
		progress bool
	}{
		{name: "stock"},
		{name: "direct", quantum: directCopySpliceQuantum, progress: true},
		{name: "direct-flow", quantum: directCopySpliceQuantum, progress: true},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.SetBytes(payloadSize)
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				var progress directCopyProgress
				var operation *flow_observation.ByteOperation
				var registry *flow_observation.Registry
				if benchmark.name == "direct-flow" {
					var registryErr error
					registry, registryErr = flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 16, MaxSeries: 16, MaxEvents: 16})
					if registryErr != nil {
						b.Fatal(registryErr)
					}
					handle := registry.AdmitTCP(context.Background(), "", "tcp:source:1", "", flow_observation.ByteScopeLogicalLinkAccepted)
					handle.SelectRoot("", "out", "freedom", "tcp:source:1", "", true, flow_observation.CarrierProofNotApplicable)
					operation = handle.BeginDeferredBytePath(flow_observation.DirectionDownlink, flow_observation.ByteScopeKernelDirectCopyAccepted)
					progress = operation
				} else if benchmark.progress {
					progress = new(atomicDirectCopyProgress)
				}
				written, received, err := runDirectCopyTCPTransfer(payloadSize, func(writer *net.TCPConn, reader *net.TCPConn) (int64, error) {
					if benchmark.quantum == 0 {
						return writer.ReadFrom(reader)
					}
					written, direct, copyErr := copyRawConnSplice(writer, reader, progress)
					if !direct {
						b.Fatal("benchmark unexpectedly used generic fallback")
					}
					return written, copyErr
				})
				if err != nil || written != payloadSize || received != payloadSize {
					b.Fatalf("transfer failed: written=%d received=%d err=%v", written, received, err)
				}
				if operation != nil {
					operation.Complete(0)
					registry.Close()
				}
			}
		})
	}
}

func runDirectCopyTCPTransfer(size int64, copyFn func(*net.TCPConn, *net.TCPConn) (int64, error)) (int64, int64, error) {
	reader, readerPeer, err := directCopyTCPPair()
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()
	defer readerPeer.Close()
	writer, writerPeer, err := directCopyTCPPair()
	if err != nil {
		return 0, 0, err
	}
	defer writer.Close()
	defer writerPeer.Close()

	sourceDone := make(chan error, 1)
	go func() {
		_, copyErr := io.CopyN(readerPeer, zeroDirectCopyReader{}, size)
		closeErr := readerPeer.CloseWrite()
		if copyErr != nil {
			sourceDone <- copyErr
			return
		}
		sourceDone <- closeErr
	}()
	receivedDone := make(chan struct {
		bytes int64
		err   error
	}, 1)
	go func() {
		received, copyErr := io.Copy(io.Discard, writerPeer)
		receivedDone <- struct {
			bytes int64
			err   error
		}{bytes: received, err: copyErr}
	}()

	written, copyErr := copyFn(writer, reader)
	closeErr := writer.CloseWrite()
	sourceErr := <-sourceDone
	received := <-receivedDone
	return written, received.bytes, errors.Join(copyErr, closeErr, sourceErr, received.err)
}

func newDirectCopyTCPPair(t testing.TB) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	first, second, err := directCopyTCPPair()
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func directCopyTCPPair() (*net.TCPConn, *net.TCPConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	accepted := make(chan struct {
		conn *net.TCPConn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- struct {
			conn *net.TCPConn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, err
	}
	result := <-accepted
	if result.err != nil {
		peer.Close()
		return nil, nil, result.err
	}
	return result.conn, peer, nil
}

type zeroDirectCopyReader struct{}

func (zeroDirectCopyReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}
