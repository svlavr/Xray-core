package mux

import (
	"errors"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

type clientCarrierProbe struct {
	mu       sync.Mutex
	reads    []uint64
	writes   []uint64
	writeErr error
	commits  int
	aborts   int
	quiesced int
}

func (p *clientCarrierProbe) AttachTo(session.MuxClientSessionObservation) {}
func (p *clientCarrierProbe) Read(n uint64) {
	p.mu.Lock()
	p.reads = append(p.reads, n)
	p.mu.Unlock()
}

func (p *clientCarrierProbe) Write(n uint64, err error) {
	p.mu.Lock()
	p.writes = append(p.writes, n)
	p.writeErr = err
	p.mu.Unlock()
}

func (p *clientCarrierProbe) Commit() {
	p.mu.Lock()
	p.commits++
	p.mu.Unlock()
}

func (p *clientCarrierProbe) Abort() {
	p.mu.Lock()
	p.aborts++
	p.mu.Unlock()
}

func (p *clientCarrierProbe) WorkerQuiesced() {
	p.mu.Lock()
	p.quiesced++
	p.mu.Unlock()
}

func (p *clientCarrierProbe) ClientFrameObservation() session.MuxClientCarrierFrameObservation {
	return p
}

type clientCarrierReader struct {
	b   buf.MultiBuffer
	err error
}

func (r *clientCarrierReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := r.b
	r.b = nil
	return b, r.err
}

func TestObservedClientCarrierReaderCountsReturnedBytesWithError(t *testing.T) {
	p := new(clientCarrierProbe)
	b := buf.New()
	b.Write([]byte("encoded-downlink"))
	n := uint64(b.Len())
	errWant := errors.New("read ended with bytes")
	got, err := (observedClientCarrierReader{Reader: &clientCarrierReader{b: buf.MultiBuffer{b}, err: errWant}, observation: p}).ReadMultiBuffer()
	defer buf.ReleaseMulti(got)
	if !errors.Is(err, errWant) {
		t.Fatalf("stock read error changed: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reads) != 1 || p.reads[0] != n {
		t.Fatalf("returned bytes not observed exactly: %+v", p.reads)
	}
}

func TestObservedClientCarrierWriterPreservesUnknownPrefixError(t *testing.T) {
	p := new(clientCarrierProbe)
	b := buf.New()
	b.Write([]byte("encoded-uplink"))
	n := uint64(b.Len())
	errWant := errors.New("unknown accepted prefix")
	if err := (observedClientCarrierWriter{Writer: carrierWriter{err: errWant}, observation: p}).WriteMultiBuffer(buf.MultiBuffer{b}); !errors.Is(err, errWant) {
		t.Fatalf("stock write error changed: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.writes) != 1 || p.writes[0] != n || !errors.Is(p.writeErr, errWant) {
		t.Fatalf("unknown-prefix write was not reported: writes=%v err=%v", p.writes, p.writeErr)
	}
}

func TestClientWriterCloseReportsDiscardedEndFrameError(t *testing.T) {
	errWant := errors.New("discarded client end frame")
	underlying := &prefixErrorWriter{err: errWant}
	probe := new(clientCarrierProbe)
	writer := NewWriter(9, net.TCPDestination(net.DomainAddress("example.com"), 443), observedClientCarrierWriter{Writer: underlying, observation: probe}, protocol.TransferTypeStream, [8]byte{}, nil)
	if err := writer.Close(); err != nil {
		t.Fatalf("stock Writer.Close error behavior changed: %v", err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if underlying.consumed.Load() != 1 || len(probe.writes) != 1 || probe.writes[0] == 0 || !errors.Is(probe.writeErr, errWant) {
		t.Fatalf("discarded client End-frame error was not observed: writes=%v err=%v", probe.writes, probe.writeErr)
	}
}
