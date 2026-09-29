package pipe

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// WithWriterReceipt reports the pipe's native accepted/drop decision.
func (w *Writer) WithWriterReceipt(receipt stats.Exchange) buf.Writer {
	return &inspectionWriter{Writer: w, receipt: receipt}
}

type inspectionWriter struct {
	*Writer
	receipt stats.Exchange
}

func (w *inspectionWriter) WriterReceipt() stats.Exchange { return w.receipt }

func (w *inspectionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	size := uint64(mb.Len())
	accepted, err := w.pipe.writeMultiBufferResult(mb, nil)
	if accepted {
		w.receipt.AddDownlink(size)
	}
	return err
}
