package buf

import (
	"io"

	"github.com/xtls/xray-core/features/stats"
)

// RecordBufferOperation credits only a completed decoded batch.
func RecordBufferOperation(receipt stats.Exchange, size uint64, err error) {
	if err == nil && size != 0 {
		receipt.AddDownlink(size)
	}
}

// WriteBytesWithReceipt records the actual scalar result, including positive
// progress returned with an error.
func WriteBytesWithReceipt(writer io.Writer, payload []byte, receipt stats.Exchange) (int, error) {
	n, err := writer.Write(payload)
	if n > 0 {
		receipt.AddDownlink(uint64(n))
	}
	return n, err
}

// AttachWriterReceipt binds opt-in accounting before an exclusively owned
// endpoint writer is used. Unsupported writers keep their identity and add no
// byte facts. A BufferedWriter must be empty at attachment, and every later
// operation must be decoded payload. Use AttachWriterReceiptWithStatus when
// the caller needs to distinguish unsupported attachment.
func AttachWriterReceipt(writer Writer, receipt stats.Exchange) Writer {
	bound, _ := AttachWriterReceiptWithStatus(writer, receipt)
	return bound
}

// AttachWriterReceiptWithStatus reports whether the endpoint writer accepted
// the receipt. A selected consumer may account for an unsupported writer itself.
// A nonempty BufferedWriter is rejected without changing its writer or buffer;
// no pre-binding bytes are classified or credited by this helper.
func AttachWriterReceiptWithStatus(writer Writer, receipt stats.Exchange) (Writer, bool) {
	if buffered, ok := writer.(*BufferedWriter); ok {
		buffered.Lock()
		defer buffered.Unlock()

		if !buffered.buffer.IsEmpty() {
			return writer, false
		}
		var attached bool
		buffered.writer, attached = attachWriterReceipt(buffered.writer, receipt)
		return writer, attached
	}
	return attachWriterReceipt(writer, receipt)
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
		return w.receipt
	case *SequentialWriter:
		return w.receipt
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

// DiscardBufferedWriter releases a response buffer abandoned by its sole writer
// owner. It performs no flush or endpoint close and must follow the last native
// write/flush attempt; it is not a concurrent cancellation operation.
func DiscardBufferedWriter(writer *BufferedWriter) {
	writer.Lock()
	defer writer.Unlock()
	writer.buffer.Release()
	writer.buffer = nil
}
