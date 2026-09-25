//go:build linux || android

package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
)

type rawSpliceTestCounter struct {
	value atomic.Int64
}

func (c *rawSpliceTestCounter) Value() int64      { return c.value.Load() }
func (c *rawSpliceTestCounter) Set(v int64) int64 { return c.value.Swap(v) }
func (c *rawSpliceTestCounter) Add(v int64) int64 { return c.value.Add(v) }

type rawSpliceTestExchange struct {
	downlink atomic.Uint64
	reason   atomic.Uint32
	added    chan uint64
}

func (*rawSpliceTestExchange) ExcludeCarrier() bool { return false }

func (e *rawSpliceTestExchange) Ref() stats.FlowRef                          { return stats.FlowRef{} }
func (e *rawSpliceTestExchange) NewLeg() stats.Exchange                      { return nil }
func (e *rawSpliceTestExchange) Rebind(stats.RuntimeID, stats.TrafficOrigin) {}
func (e *rawSpliceTestExchange) Route(stats.RouteStep)                       {}
func (e *rawSpliceTestExchange) BindRoute()                                  {}
func (e *rawSpliceTestExchange) PacketDestination(xnet.Destination)          {}
func (e *rawSpliceTestExchange) Unassign()                                   {}
func (e *rawSpliceTestExchange) Effective(xnet.Destination)                  {}
func (e *rawSpliceTestExchange) SetSource(xnet.Destination)                  {}
func (e *rawSpliceTestExchange) AddUplink(uint64)                            {}
func (e *rawSpliceTestExchange) MarkUplinkIncomplete()                       {}
func (e *rawSpliceTestExchange) MarkDownlinkIncomplete()                     {}
func (e *rawSpliceTestExchange) Enter() bool                                 { return true }
func (e *rawSpliceTestExchange) Leave()                                      {}
func (e *rawSpliceTestExchange) Finish()                                     {}
func (e *rawSpliceTestExchange) SetEndReason(reason stats.EndReason)         { e.reason.Store(uint32(reason)) }

func (e *rawSpliceTestExchange) AddDownlink(n uint64) {
	e.downlink.Add(n)
	if e.added != nil {
		select {
		case e.added <- n:
		default:
		}
	}
}

type rawSpliceResult struct {
	written int64
	handled bool
	err     error
}

func TestRawSpliceTCPProgressAndCounters(t *testing.T) {
	sourceWriter, sourceReader := newRawTCPPair(t)
	destinationWriter, destinationReader := newRawTCPPair(t)
	exchange := &rawSpliceTestExchange{added: make(chan uint64, 4)}
	readCounter := new(rawSpliceTestCounter)
	writeCounter := new(rawSpliceTestCounter)
	userCounter := new(rawSpliceTestCounter)
	receipt := &rawCopyReceipt{
		exchange:     exchange,
		readCounter:  readCounter,
		writeCounter: writeCounter,
		userCounter:  userCounter,
	}
	result := make(chan rawSpliceResult, 1)
	go func() {
		written, handled, err := copySpliceProgress(destinationWriter, sourceReader, receipt)
		result <- rawSpliceResult{written: written, handled: handled, err: err}
	}()

	first := []byte("progress-before-source-eof")
	if _, err := sourceWriter.Write(first); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(first))
	if err := destinationReader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(destinationReader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first destination prefix = %q", got)
	}
	select {
	case n := <-exchange.added:
		if n == 0 {
			t.Fatal("zero progress receipt")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no receipt before source EOF")
	}
	select {
	case completed := <-result:
		t.Fatalf("copy completed before source EOF: %+v", completed)
	default:
	}

	second := []byte("-and-final-prefix")
	if _, err := sourceWriter.Write(second); err != nil {
		t.Fatal(err)
	}
	if err := sourceWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(second))
	if _, err := io.ReadFull(destinationReader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("second destination prefix = %q", got)
	}
	completed := waitRawSpliceResult(t, result)
	want := int64(len(first) + len(second))
	if !completed.handled || completed.err != nil || completed.written != want {
		t.Fatalf("copy result = %+v, want handled bytes=%d", completed, want)
	}
	assertRawSpliceReceipts(t, want, exchange, readCounter, writeCounter, userCounter)
}

func TestRawSpliceUnixAndPipeCleanup(t *testing.T) {
	sourceWriter, sourceReader := newRawUnixPair(t)
	destinationWriter, destinationReader := newRawTCPPair(t)
	before := rawSpliceFDCount(t)
	payload := bytes.Repeat([]byte("unix-stream-"), 8192)
	writeDone := make(chan error, 1)
	go func() {
		_, err := sourceWriter.Write(payload)
		if closeErr := sourceWriter.CloseWrite(); err == nil {
			err = closeErr
		}
		writeDone <- err
	}()

	exchange := new(rawSpliceTestExchange)
	counter := new(rawSpliceTestCounter)
	result := make(chan rawSpliceResult, 1)
	go func() {
		written, handled, err := copySpliceProgress(destinationWriter, sourceReader, &rawCopyReceipt{
			exchange: exchange, readCounter: counter, writeCounter: counter, userCounter: counter,
		})
		result <- rawSpliceResult{written: written, handled: handled, err: err}
	}()
	if err := destinationReader.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(destinationReader, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	completed := waitRawSpliceResult(t, result)
	if !completed.handled || completed.err != nil || completed.written != int64(len(payload)) || !bytes.Equal(got, payload) {
		t.Fatalf("unix copy result=%+v equal=%v", completed, bytes.Equal(got, payload))
	}
	if after := rawSpliceFDCount(t); after != before {
		t.Fatalf("pipe descriptors leaked: before=%d after=%d", before, after)
	}
}

func TestRawSpliceUnsupportedDoesNotConsume(t *testing.T) {
	source, sourcePeer := net.Pipe()
	t.Cleanup(func() { source.Close() })
	t.Cleanup(func() { sourcePeer.Close() })
	destinationWriter, _ := newRawTCPPair(t)
	payload := []byte("fallback-owned-prefix")
	writeDone := make(chan error, 1)
	go func() {
		_, err := sourcePeer.Write(payload)
		writeDone <- err
	}()

	written, handled, err := copySpliceProgress(destinationWriter, source, &rawCopyReceipt{})
	if written != 0 || handled || err != nil {
		t.Fatalf("unsupported result = written=%d handled=%v err=%v", written, handled, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(source, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("fallback data changed: %q", got)
	}
}

func TestRawSpliceDeadlinePreservesPositivePrefix(t *testing.T) {
	sourceWriter, sourceReader := newRawTCPPair(t)
	destinationWriter, _ := newRawTCPPair(t)
	if err := destinationWriter.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := destinationWriter.SetWriteDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 8<<20)
	writeDone := make(chan rawSpliceResult, 1)
	go func() {
		n, err := io.Copy(sourceWriter, bytes.NewReader(payload))
		if closeErr := sourceWriter.CloseWrite(); err == nil {
			err = closeErr
		}
		writeDone <- rawSpliceResult{written: n, err: err}
	}()
	exchange := new(rawSpliceTestExchange)
	readCounter := new(rawSpliceTestCounter)
	writeCounter := new(rawSpliceTestCounter)
	userCounter := new(rawSpliceTestCounter)
	receipt := &rawCopyReceipt{
		exchange: exchange, readCounter: readCounter, writeCounter: writeCounter, userCounter: userCounter,
	}
	before := rawSpliceFDCount(t)
	written, handled, err := copySpliceProgress(destinationWriter, sourceReader, receipt)
	if after := rawSpliceFDCount(t); after != before {
		t.Fatalf("failed splice leaked pipe descriptors: before=%d after=%d", before, after)
	}
	if !handled || err == nil || written <= 0 {
		t.Fatalf("deadline result = written=%d handled=%v err=%v", written, handled, err)
	}
	var timeout interface{ Timeout() bool }
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("deadline error is not observable as timeout: %T %v", err, err)
	}
	if got := stats.EndReason(exchange.reason.Load()); got != stats.EndReasonTimeout {
		t.Fatalf("end reason = %v, want timeout", got)
	}
	assertRawSpliceReceipts(t, written, exchange, readCounter, writeCounter, userCounter)
	if err := sourceReader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	remaining, readErr := io.ReadAll(sourceReader)
	if readErr != nil {
		t.Fatal(readErr)
	}
	select {
	case sourceResult := <-writeDone:
		if sourceResult.err != nil || sourceResult.written != int64(len(payload)) {
			t.Fatalf("source write = %+v", sourceResult)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("source writer did not unblock after copy failure")
	}
	if got := written + int64(len(remaining)); got >= int64(len(payload)) {
		t.Fatalf("splice failure did not consume any uncredited pipe residue: accepted=%d unread=%d payload=%d", written, len(remaining), len(payload))
	}
}

func newRawTCPPair(t testing.TB) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accept := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accept <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var server *net.TCPConn
	select {
	case server = <-accept:
	case err := <-acceptErr:
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	listener.Close()
	t.Cleanup(func() { client.Close() })
	t.Cleanup(func() { server.Close() })
	return client, server
}

func newRawUnixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "splice.sock")
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	accept := make(chan *net.UnixConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			acceptErr <- err
			return
		}
		accept <- conn
	}()
	client, err := net.DialUnix("unix", nil, address)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var server *net.UnixConn
	select {
	case server = <-accept:
	case err := <-acceptErr:
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	listener.Close()
	t.Cleanup(func() { client.Close() })
	t.Cleanup(func() { server.Close() })
	return client, server
}

func waitRawSpliceResult(t *testing.T, result <-chan rawSpliceResult) rawSpliceResult {
	t.Helper()
	select {
	case completed := <-result:
		return completed
	case <-time.After(3 * time.Second):
		t.Fatal("raw splice did not complete")
		return rawSpliceResult{}
	}
}

func assertRawSpliceReceipts(t *testing.T, want int64, exchange *rawSpliceTestExchange, counters ...*rawSpliceTestCounter) {
	t.Helper()
	if got := exchange.downlink.Load(); got != uint64(want) {
		t.Fatalf("exchange bytes = %d, want %d", got, want)
	}
	for i, counter := range counters {
		if got := counter.Value(); got != want {
			t.Fatalf("counter %d = %d, want %d", i, got, want)
		}
	}
}

func rawSpliceFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
