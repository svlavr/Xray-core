package mux

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
)

type carrierProbe struct {
	reads, writes []uint64
	writeErr      error
}

func (p *carrierProbe) Read(n uint64)             { p.reads = append(p.reads, n) }
func (p *carrierProbe) Write(n uint64, err error) { p.writes = append(p.writes, n); p.writeErr = err }
func (*carrierProbe) Reserve()                    {}
func (*carrierProbe) Release()                    {}
func (*carrierProbe) ReaderExited()               {}
func (*carrierProbe) MonitorCompleted()           {}
func (*carrierProbe) UplinkSealed()               {}
func (*carrierProbe) DownlinkSealed()             {}

type carrierWriter struct{ err error }

func (w carrierWriter) WriteMultiBuffer(buf.MultiBuffer) error { return w.err }

func TestObservedServerCarrierWriterReportsExactAttemptOnlyOnSuccessfulWrite(t *testing.T) {
	p := &carrierProbe{}
	b := buf.New()
	b.Write([]byte("encoded-frame"))
	n := uint64(b.Len())
	if err := (observedServerCarrierWriter{Writer: carrierWriter{}, observation: p}).WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	if len(p.writes) != 1 || p.writes[0] != n || p.writeErr != nil {
		t.Fatalf("wrong successful observation: %+v", p)
	}
	b = buf.New()
	b.Write([]byte("end"))
	errWant := errors.New("discarded end")
	if err := (observedServerCarrierWriter{Writer: carrierWriter{errWant}, observation: p}).WriteMultiBuffer(buf.MultiBuffer{b}); !errors.Is(err, errWant) {
		t.Fatalf("stock error changed: %v", err)
	}
	if !errors.Is(p.writeErr, errWant) {
		t.Fatalf("writer error not observed: %+v", p)
	}
}

type prefixErrorWriter struct {
	err      error
	consumed atomic.Uint64
}

func (w *prefixErrorWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.Len() != 0 {
		w.consumed.Store(1)
	}
	buf.ReleaseMulti(mb)
	return w.err
}

func TestResponseWriterClosePreservesDiscardedErrorAndReportsUnknownPrefix(t *testing.T) {
	errWant := errors.New("end frame prefix unknown")
	underlying := &prefixErrorWriter{err: errWant}
	probe := &carrierProbe{}
	writer := NewResponseWriter(7, observedServerCarrierWriter{Writer: underlying, observation: probe}, protocol.TransferTypeStream)
	if err := writer.Close(); err != nil {
		t.Fatalf("stock Writer.Close error behavior changed: %v", err)
	}
	if underlying.consumed.Load() != 1 {
		t.Fatal("test writer did not consume its unknown prefix")
	}
	if !errors.Is(probe.writeErr, errWant) || len(probe.writes) != 1 || probe.writes[0] == 0 {
		t.Fatalf("discarded End-frame error was not observed: %+v", probe)
	}
}
