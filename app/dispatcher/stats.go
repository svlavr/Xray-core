package dispatcher

import (
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

// WriteMultiBufferStop retains native offered-byte accounting.
func (w *SizeStatWriter) WriteMultiBufferStop(mb buf.MultiBuffer, stop <-chan struct{}) error {
	w.Counter.Add(int64(mb.Len()))
	if writer, ok := w.Writer.(interface {
		WriteMultiBufferStop(buf.MultiBuffer, <-chan struct{}) error
	}); ok {
		return writer.WriteMultiBufferStop(mb, stop)
	}
	buf.ReleaseMulti(mb)
	return io.ErrClosedPipe
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
