//go:build linux || android

package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type rawSpliceTestCounter struct {
	value atomic.Int64
}

func (c *rawSpliceTestCounter) Value() int64      { return c.value.Load() }
func (c *rawSpliceTestCounter) Set(v int64) int64 { return c.value.Swap(v) }
func (c *rawSpliceTestCounter) Add(v int64) int64 { return c.value.Add(v) }

type rawSpliceTestExchange struct {
	downlink atomic.Uint64
	added    chan uint64
}

func (*rawSpliceTestExchange) ExcludeCarrier() bool { return false }

func (e *rawSpliceTestExchange) Ref() stats.FlowRef                          { return stats.FlowRef{} }
func (e *rawSpliceTestExchange) NewLeg() stats.Exchange                      { return nil }
func (e *rawSpliceTestExchange) Rebind(stats.RuntimeID, stats.TrafficOrigin) {}
func (e *rawSpliceTestExchange) Route(stats.OutboundRef)                     {}
func (e *rawSpliceTestExchange) PacketDestination(xnet.Destination)          {}
func (e *rawSpliceTestExchange) RecordPacketInput(xnet.Destination, uint64)  {}
func (e *rawSpliceTestExchange) Unassign()                                   {}
func (e *rawSpliceTestExchange) Effective(xnet.Destination)                  {}
func (e *rawSpliceTestExchange) SetSource(xnet.Destination)                  {}
func (e *rawSpliceTestExchange) AddUplink(uint64)                            {}
func (e *rawSpliceTestExchange) AddSelectedUplink(uint64)                    {}
func (e *rawSpliceTestExchange) Enter() bool                                 { return true }
func (e *rawSpliceTestExchange) Leave()                                      {}
func (e *rawSpliceTestExchange) Finish()                                     {}

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
	err     error
}

func TestRawSpliceTCPProgressAndCounters(t *testing.T) {
	sourceWriter, sourceReader := newRawTCPPair(t)
	destinationWriter, destinationReader := newRawTCPPair(t)
	exchange := &rawSpliceTestExchange{added: make(chan uint64, 4)}
	readCounter := new(rawSpliceTestCounter)
	writeCounter := new(rawSpliceTestCounter)
	userCounter := new(rawSpliceTestCounter)
	ctx, _, timer := rawSpliceContext(t, destinationWriter, 1)
	writer := rawSpliceObservedWriter(destinationWriter, exchange, writeCounter, userCounter)
	result := make(chan rawSpliceResult, 1)
	go func() {
		err := CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: sourceReader, ReadCounter: readCounter}, destinationWriter, writer, timer, nil)
		result <- rawSpliceResult{err: err}
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
	if completed.err != nil {
		t.Fatalf("copy result = %+v, want bytes=%d", completed, want)
	}
	assertRawSpliceReceipts(t, want, exchange, readCounter, writeCounter, userCounter)
}

func TestRawSpliceUnixSourceEOF(t *testing.T) {
	sourceWriter, sourceReader := newRawUnixPair(t)
	destinationWriter, destinationReader := newRawTCPPair(t)
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
	readCounter, writeCounter, userCounter := new(rawSpliceTestCounter), new(rawSpliceTestCounter), new(rawSpliceTestCounter)
	ctx, _, timer := rawSpliceContext(t, destinationWriter, 1)
	writer := rawSpliceObservedWriter(destinationWriter, exchange, writeCounter, userCounter)
	result := make(chan rawSpliceResult, 1)
	go func() {
		err := CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: sourceReader, ReadCounter: readCounter}, destinationWriter, writer, timer, nil)
		result <- rawSpliceResult{err: err}
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
	if completed.err != nil || exchange.downlink.Load() != uint64(len(payload)) || !bytes.Equal(got, payload) {
		t.Fatalf("unix copy result=%+v equal=%v", completed, bytes.Equal(got, payload))
	}
	assertRawSpliceReceipts(t, int64(len(payload)), exchange, readCounter, writeCounter, userCounter)
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
	ctx, _, timer := rawSpliceContext(t, destinationWriter, 1)
	writer := rawSpliceObservedWriter(destinationWriter, exchange, writeCounter, userCounter)
	err := CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: sourceReader, ReadCounter: readCounter}, destinationWriter, writer, timer, nil)
	written := int64(exchange.downlink.Load())
	if err == nil || written <= 0 {
		t.Fatalf("deadline result = written=%d err=%v", written, err)
	}
	var timeout interface{ Timeout() bool }
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("deadline error is not observable as timeout: %T %v", err, err)
	}
	assertRawSpliceReceipts(t, written, exchange, writeCounter)
	// Native buffered input and USER counters describe consumed/offered bytes,
	// while the receipt and destination counter describe actual accepted writes.
	consumed := readCounter.Value()
	if consumed <= written || userCounter.Value() != consumed {
		t.Fatalf("partial copy accepted=%d consumed=%d offered=%d", written, consumed, userCounter.Value())
	}
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
	if got := consumed + int64(len(remaining)); got != int64(len(payload)) {
		t.Fatalf("consumed/unread custody: consumed=%d unread=%d payload=%d", consumed, len(remaining), len(payload))
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

// Each native counter retains its own role; only completed transfers make
// consumed input, offered USER bytes and accepted destination bytes equal.
func rawSpliceObservedWriter(dst net.Conn, exchange stats.Exchange, writeCounter, userCounter stats.Counter) buf.Writer {
	writer := buf.NewWriter(&stat.CounterConnection{Connection: dst, WriteCounter: writeCounter})
	return &dispatcher.SizeStatWriter{Writer: buf.AttachWriterReceipt(writer, exchange), Counter: userCounter}
}
