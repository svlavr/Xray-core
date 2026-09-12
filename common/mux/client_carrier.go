package mux

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
)

// observedClientCarrierReader counts bytes returned by the encoded frame reader,
// including a non-nil error. It never changes the reader result.
type observedClientCarrierReader struct {
	buf.Reader
	observation session.MuxClientCarrierFrameObservation
}

func (r observedClientCarrierReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, e := r.Reader.ReadMultiBuffer()
	if r.observation != nil {
		r.observation.Read(uint64(b.Len()))
	}
	return b, e
}
func (r observedClientCarrierReader) Interrupt()   { common.Interrupt(r.Reader) }
func (r observedClientCarrierReader) Close() error { return common.Close(r.Reader) }

// observedClientCarrierWriter counts only a successful encoded uplink write.
type observedClientCarrierWriter struct {
	buf.Writer
	observation session.MuxClientCarrierFrameObservation
}

func (w observedClientCarrierWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	n := uint64(b.Len())
	e := w.Writer.WriteMultiBuffer(b)
	if w.observation != nil {
		w.observation.Write(n, e)
	}
	return e
}
func (w observedClientCarrierWriter) Interrupt()   { common.Interrupt(w.Writer) }
func (w observedClientCarrierWriter) Close() error { return common.Close(w.Writer) }
