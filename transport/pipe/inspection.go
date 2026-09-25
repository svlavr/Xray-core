package pipe

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// WriteMultiBufferResult exposes the native queue admission result to the MUX
// frame owner without attaching a lower logical receipt.
func (w *Writer) WriteMultiBufferResult(mb buf.MultiBuffer) (bool, error) {
	return w.pipe.writeMultiBufferResult(mb, nil)
}

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
	if err != nil {
		w.receipt.SetEndReason(stats.EndReasonWriteError)
	}
	return err
}
