package buf

import (
	"io"

	"github.com/xtls/xray-core/features/stats"
)

// inspectionPrefixReceipt removes framing that was already buffered before an
// endpoint receipt was attached. BufferedWriter serializes this state with its
// existing mutex. Only bytes reported by a native result consume it.
type inspectionPrefixReceipt struct {
	stats.Exchange
	remaining uint64
}

func (r *inspectionPrefixReceipt) AddDownlink(n uint64) {
	if n <= r.remaining {
		r.remaining -= n
		return
	}
	n -= r.remaining
	r.remaining = 0
	r.Exchange.AddDownlink(n)
}

func discardFailedPrefix(receipt stats.Exchange) {
	if prefixed, ok := receipt.(*inspectionPrefixReceipt); ok {
		// BufferedWriter discarded the failed buffer. Its unaccepted header
		// tail cannot be subtracted from the next independent payload write.
		prefixed.remaining = 0
	}
}

// RecordBufferOperation credits only a completed decoded batch and clears a
// discarded framing prefix after a failed native write.
func RecordBufferOperation(receipt stats.Exchange, size uint64, err error) {
	if err == nil {
		if size != 0 {
			receipt.AddDownlink(size)
		}
		return
	}
	discardFailedPrefix(receipt)
}

// WriteBytesWithReceipt records the actual scalar result, including positive
// progress returned with an error, and clears a failed framing prefix.
func WriteBytesWithReceipt(writer io.Writer, payload []byte, receipt stats.Exchange) (int, error) {
	n, err := writer.Write(payload)
	if n > 0 {
		receipt.AddDownlink(uint64(n))
	}
	if err != nil {
		discardFailedPrefix(receipt)
	}
	return n, err
}

// AttachWriterReceipt binds opt-in accounting before an exclusively owned
// endpoint writer is used. Unsupported writers keep their identity and add no
// byte facts. For BufferedWriter, pre-binding buffered bytes must be framing,
// and every later operation must be decoded payload.
func AttachWriterReceipt(writer Writer, receipt stats.Exchange) Writer {
	bound, _ := AttachWriterReceiptWithStatus(writer, receipt)
	return bound
}

// AttachWriterReceiptWithStatus reports whether the endpoint writer accepted
// the receipt. A selected consumer may account for an unsupported writer itself.
func AttachWriterReceiptWithStatus(writer Writer, receipt stats.Exchange) (Writer, bool) {
	if buffered, ok := writer.(*BufferedWriter); ok {
		buffered.Lock()
		defer buffered.Unlock()

		return writer, attachBufferedWriterReceipt(buffered, receipt)
	}
	return attachWriterReceipt(writer, receipt)
}

// The caller holds the existing buffered-writer mutex.
func attachBufferedWriterReceipt(buffered *BufferedWriter, receipt stats.Exchange) bool {
	if buffered.buffer != nil && !buffered.buffer.IsEmpty() {
		receipt = &inspectionPrefixReceipt{Exchange: receipt, remaining: uint64(buffered.buffer.Len())}
	}
	var attached bool
	buffered.writer, attached = attachWriterReceipt(buffered.writer, receipt)
	return attached
}

func attachWriterReceipt(writer Writer, receipt stats.Exchange) (Writer, bool) {
	switch w := writer.(type) {
	case *BufferToBytesWriter:
		w.receipt = receipt
		return w, true
	case *SequentialWriter:
		w.receipt = receipt
		return w, true
	case interface{ WithWriterReceipt(stats.Exchange) Writer }:
		return w.WithWriterReceipt(receipt), true
	default:
		return writer, false
	}
}

// WriterReceipt returns only a receipt bound to this actual endpoint writer.
// It must not be inferred from an inherited execution context.
func WriterReceipt(writer Writer) stats.Exchange {
	switch w := writer.(type) {
	case *BufferToBytesWriter:
		return OriginalWriterReceipt(w.receipt)
	case *SequentialWriter:
		return OriginalWriterReceipt(w.receipt)
	case *BufferedWriter:
		w.Lock()
		defer w.Unlock()
		return WriterReceipt(w.writer)
	case interface{ WriterReceipt() stats.Exchange }:
		return w.WriterReceipt()
	default:
		return nil
	}
}

// OriginalWriterReceipt removes only the local buffered-framing prefix layer.
func OriginalWriterReceipt(receipt stats.Exchange) stats.Exchange {
	if prefixed, ok := receipt.(*inspectionPrefixReceipt); ok {
		return prefixed.Exchange
	}
	return receipt
}

// DiscardBufferedWriter releases a response buffer abandoned by its sole writer
// owner. It performs no flush or endpoint close and must follow the last native
// write/flush attempt; it is not a concurrent cancellation operation.
func DiscardBufferedWriter(writer *BufferedWriter) {
	writer.Lock()
	defer writer.Unlock()
	writer.buffer.Release()
	writer.buffer = nil
}
