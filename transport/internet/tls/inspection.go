package tls

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// WithWriterReceipt preserves this TLS writer's compact-then-scalar path and
// connection ownership while retaining each actual plaintext Write result.
func (c *Conn) WithWriterReceipt(receipt stats.Exchange) buf.Writer {
	return &inspectionWriter{Conn: c, receipt: receipt}
}

type inspectionWriter struct {
	*Conn
	receipt stats.Exchange
}

func (w *inspectionWriter) Write(p []byte) (int, error) {
	return buf.WriteBytesWithReceipt(w.Conn, p, w.receipt)
}

func (w *inspectionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	size := uint64(mb.Len())
	err := w.Conn.WriteMultiBuffer(mb)
	buf.RecordBufferOperation(w.receipt, size, err)
	return err
}

func (w *inspectionWriter) WriterReceipt() stats.Exchange {
	return buf.OriginalWriterReceipt(w.receipt)
}
