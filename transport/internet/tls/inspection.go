package tls

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// WithWriterReceipt binds decoded writes before this connection's exclusive
// body use. The native compact-then-scalar path retains each actual result.
func (c *Conn) WithWriterReceipt(receipt stats.Exchange) buf.Writer {
	c.receipt = receipt
	return c
}

func (c *Conn) WriterReceipt() stats.Exchange {
	return buf.OriginalWriterReceipt(c.receipt)
}
