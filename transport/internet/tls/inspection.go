package tls

import (
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// WithWriterReceipt preserves this TLS writer's compact-then-scalar path and
// connection ownership while retaining each actual plaintext Write result.
func (c *Conn) WithWriterReceipt(receipt stats.Exchange) buf.Writer {
	return &inspectionWriter{Conn: c, writer: buf.AttachWriterReceipt(&buf.SequentialWriter{Writer: c}, receipt)}
}

type inspectionWriter struct {
	*Conn
	writer buf.Writer
}

func (w *inspectionWriter) Write(p []byte) (int, error) {
	return w.writer.(io.Writer).Write(p)
}

func (w *inspectionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(buf.Compact(mb))
}

func (w *inspectionWriter) WriterReceipt() stats.Exchange { return buf.WriterReceipt(w.writer) }
