package dispatcher

import (
	"context"
	"errors"

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

// WriteMultiBufferContext preserves the native offered-byte counter while
// forwarding cancellation to the actual returned-link pipe owner.
func (w *SizeStatWriter) WriteMultiBufferContext(ctx context.Context, mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	if writer, ok := w.Writer.(interface {
		WriteMultiBufferContext(context.Context, buf.MultiBuffer) error
	}); ok {
		return writer.WriteMultiBufferContext(ctx, mb)
	}
	buf.ReleaseMulti(mb)
	return errors.New("writer does not support cancellation")
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
