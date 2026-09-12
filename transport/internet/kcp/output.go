package kcp

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/retry"
)

type SegmentWriter interface {
	Write(seg Segment) error
}

type SimpleSegmentWriter struct {
	sync.Mutex
	buffer *buf.Buffer
	writer io.Writer
	closed bool
}

func NewSegmentWriter(writer io.Writer) SegmentWriter {
	return &SimpleSegmentWriter{
		writer: writer,
		buffer: buf.New(),
	}
}

func (w *SimpleSegmentWriter) Write(seg Segment) error {
	w.Lock()
	defer w.Unlock()
	if w.closed {
		return errors.New("KCP segment writer is closed")
	}

	w.buffer.Clear()
	rawBytes := w.buffer.Extend(seg.ByteSize())
	seg.Serialize(rawBytes)
	_, err := w.writer.Write(w.buffer.Bytes())
	return err
}

func (w *SimpleSegmentWriter) Release() {
	w.Lock()
	if !w.closed {
		w.closed = true
		w.buffer.Release()
		w.buffer = nil
	}
	w.Unlock()
}

type RetryableWriter struct {
	writer SegmentWriter
}

func NewRetryableWriter(writer SegmentWriter) SegmentWriter {
	return &RetryableWriter{
		writer: writer,
	}
}

func (w *RetryableWriter) Write(seg Segment) error {
	return retry.Timed(5, 100).On(func() error {
		return w.writer.Write(seg)
	})
}

func (w *RetryableWriter) Release() {
	if writer, ok := w.writer.(interface{ Release() }); ok {
		writer.Release()
	}
}
