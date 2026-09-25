package buf

import (
	"io"

	"github.com/xtls/xray-core/features/stats"
)

type inspectionBufferToBytesWriter struct {
	*BufferToBytesWriter
	receipt stats.Exchange
}

func (w *inspectionBufferToBytesWriter) Write(payload []byte) (int, error) {
	return writeBytesInspection(w.Writer, payload, w.receipt)
}

func (w *inspectionBufferToBytesWriter) WriteMultiBuffer(mb MultiBuffer) error {
	size := uint64(mb.Len())
	err := w.BufferToBytesWriter.WriteMultiBuffer(mb)
	recordBufferOperation(w.receipt, size, err)
	return err
}

func (w *inspectionBufferToBytesWriter) ReadFrom(reader io.Reader) (int64, error) {
	var size SizeCounter
	err := Copy(NewReader(reader), w, CountSize(&size))
	return size.Size, err
}

type inspectionSequentialWriter struct {
	*SequentialWriter
	receipt stats.Exchange
}

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

func (r *inspectionPrefixReceipt) SetEndReason(reason stats.EndReason) {
	if reason == stats.EndReasonWriteError {
		// A failed native flush releases the entire pending buffer. Its
		// unaccepted header tail is not part of any subsequent payload write.
		r.remaining = 0
	}
	r.Exchange.SetEndReason(reason)
}

func (w *inspectionSequentialWriter) Write(payload []byte) (int, error) {
	return writeBytesInspection(w.Writer, payload, w.receipt)
}

func (w *inspectionSequentialWriter) WriteMultiBuffer(mb MultiBuffer) error {
	size := uint64(mb.Len())
	err := w.SequentialWriter.WriteMultiBuffer(mb)
	recordBufferOperation(w.receipt, size, err)
	return err
}

func recordBufferOperation(receipt stats.Exchange, size uint64, err error) {
	if err == nil {
		if size != 0 {
			receipt.AddDownlink(size)
		}
		return
	}
	receipt.MarkDownlinkIncomplete()
	receipt.SetEndReason(stats.EndReasonWriteError)
}

func writeBytesInspection(writer io.Writer, payload []byte, receipt stats.Exchange) (int, error) {
	n, err := writeScalarInspection(writer, payload, receipt)
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		receipt.SetEndReason(stats.EndReasonWriteError)
	}
	return n, err
}

func writeScalarInspection(writer io.Writer, payload []byte, receipt stats.Exchange) (int, error) {
	n, err := writer.Write(payload)
	if n > 0 {
		receipt.AddDownlink(uint64(n))
	}
	return n, err
}

// AttachWriterReceipt wraps a known native endpoint writer with opt-in receipt
// accounting. Unsupported writers keep their identity and report unavailable
// result facts. For BufferedWriter, pre-binding buffered bytes must be framing,
// and every later successful operation must be decoded payload.
func AttachWriterReceipt(writer Writer, receipt stats.Exchange) Writer {
	if buffered, ok := writer.(*BufferedWriter); ok {
		buffered.Lock()
		defer buffered.Unlock()

		attachBufferedWriterReceipt(buffered, receipt)
		return writer
	}
	return attachWriterReceipt(writer, receipt)
}

// The caller holds the existing buffered-writer mutex.
func attachBufferedWriterReceipt(buffered *BufferedWriter, receipt stats.Exchange) {
	if buffered.buffer != nil && !buffered.buffer.IsEmpty() {
		receipt = &inspectionPrefixReceipt{Exchange: receipt, remaining: uint64(buffered.buffer.Len())}
	}
	buffered.writer = attachWriterReceipt(buffered.writer, receipt)
}

func attachWriterReceipt(writer Writer, receipt stats.Exchange) Writer {
	switch w := writer.(type) {
	case *BufferToBytesWriter:
		return &inspectionBufferToBytesWriter{BufferToBytesWriter: w, receipt: receipt}
	case *SequentialWriter:
		return &inspectionSequentialWriter{SequentialWriter: w, receipt: receipt}
	case interface{ WithWriterReceipt(stats.Exchange) Writer }:
		return w.WithWriterReceipt(receipt)
	default:
		receipt.MarkDownlinkIncomplete()
		return writer
	}
}

// WriterReceipt returns only a receipt bound to this actual endpoint writer.
// It must not be inferred from an inherited execution context.
func WriterReceipt(writer Writer) stats.Exchange {
	switch w := writer.(type) {
	case *inspectionBufferToBytesWriter:
		return originalWriterReceipt(w.receipt)
	case *inspectionSequentialWriter:
		return originalWriterReceipt(w.receipt)
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

func originalWriterReceipt(receipt stats.Exchange) stats.Exchange {
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
	writer.flushNext = false
}
