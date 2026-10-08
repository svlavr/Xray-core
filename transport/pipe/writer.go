package pipe

import (
	"context"

	"github.com/xtls/xray-core/common/buf"
)

// Writer is a buf.Writer that writes data into a pipe.
type Writer struct {
	pipe *pipe
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.pipe.WriteMultiBuffer(mb)
}

// WriteMultiBufferContext cancels only this write. A canceled unqueued batch is
// released; successful enqueue transfers custody even if cancellation follows.
func (w *Writer) WriteMultiBufferContext(ctx context.Context, mb buf.MultiBuffer) error {
	return w.pipe.writeMultiBuffer(mb, ctx)
}

// Close implements io.Closer. After the pipe is closed, writing to the pipe will return io.ErrClosedPipe, while reading will return io.EOF.
func (w *Writer) Close() error {
	return w.pipe.Close()
}

func (w *Writer) Len() int32 {
	return w.pipe.Len()
}

// Interrupt implements common.Interruptible.
func (w *Writer) Interrupt() {
	w.pipe.Interrupt()
}
