package mux

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
)

type observedServerCarrierReader struct {
	buf.Reader
	observation session.MuxCarrierFrameObservation
}

func (r observedServerCarrierReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, e := r.Reader.ReadMultiBuffer()
	if r.observation != nil {
		r.observation.Read(uint64(b.Len()))
	}
	return b, e
}

func (r observedServerCarrierReader) Interrupt() { common.Interrupt(r.Reader) }
func (r observedServerCarrierReader) Close() error {
	return common.Close(r.Reader)
}

type observedServerCarrierWriter struct {
	buf.Writer
	observation session.MuxCarrierFrameObservation
}

func (w observedServerCarrierWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	n := uint64(b.Len())
	e := w.Writer.WriteMultiBuffer(b)
	if w.observation != nil {
		w.observation.Write(n, e)
	}
	return e
}

func (w observedServerCarrierWriter) Interrupt() { common.Interrupt(w.Writer) }
func (w observedServerCarrierWriter) Close() error {
	return common.Close(w.Writer)
}
