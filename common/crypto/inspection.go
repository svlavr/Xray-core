package crypto

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type inspectionAuthenticationWriter struct {
	*AuthenticationWriter
	receipt stats.Exchange
}

func (w *inspectionAuthenticationWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.AuthenticationWriter.writeMultiBuffer(mb, w.receipt)
}

// ObserveAuthenticationWriter binds decoded operation results after the native
// header/IV was prepared and before any body write. The returned cleanup must
// run after the response owner's last native write/flush. It discards buffered
// output without emitting it.
// Nil observation preserves the native writer identity and allocates nothing.
func ObserveAuthenticationWriter(writer buf.Writer, flow stats.Exchange) (buf.Writer, func()) {
	if flow == nil {
		return writer, nil
	}
	w, ok := writer.(*AuthenticationWriter)
	if !ok {
		flow.MarkDownlinkIncomplete()
		return writer, nil
	}
	return &inspectionAuthenticationWriter{AuthenticationWriter: w, receipt: flow}, func() {
		if buffered, ok := w.writer.(*buf.BufferedWriter); ok {
			buf.DiscardBufferedWriter(buffered)
		}
	}
}
