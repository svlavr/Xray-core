package dispatcher

import (
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

// BeginRawCopy preserves legacy user stats when native copy bypasses this
// wrapper on stock DispatchLink paths.
func (w *SizeStatWriter) BeginRawCopy() func(int64) {
	finish := buf.BeginRawCopy(w.Writer)
	return func(n int64) {
		w.Counter.Add(n)
		if finish != nil {
			finish(n)
		}
	}
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
