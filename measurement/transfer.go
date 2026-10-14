package measurement

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

const transferChunk = 32 << 10

var (
	ErrTransferTimeout  = errors.New("active transfer time limit reached")
	ErrUploadIncomplete = errors.New("upload payload not fully accepted by HTTP writer")
)

type DownloadRequest struct {
	// HTTPS.MaxBodyBytes is the caller-selected streamed payload ceiling.
	HTTPS           HTTPSRequest
	TransferTimeout time.Duration
}

type DownloadReceipt struct {
	// HTTPS.Body is nil: no download payload is retained. HTTPS.BodyComplete
	// describes native body-reader completion; PayloadBytes counts the consumed stream.
	HTTPS            HTTPSReceipt
	DeclaredLength   *int64 // -1 means no declared length; absent before response.
	PayloadBytes     int64
	ActiveElapsed    *time.Duration // Read phase, absent before response.
	ByteLimitReached bool
}

// Download streams one HTTPS GET with fixed-size scratch space. Reaching the
// payload ceiling is a bounded observation; it does not imply response EOF.
func (e *Executor) Download(ctx context.Context, request DownloadRequest) (result DownloadReceipt, resultErr error) {
	if ctx == nil || request.TransferTimeout <= 0 {
		return result, errors.New("invalid download context/time budget")
	}
	result.HTTPS, resultErr = e.http(ctx, request.HTTPS, httpPlan{method: http.MethodGet, secure: true, consume: func(ctx *operation, response *http.Response, receipt *HTTPSReceipt) (err error) {
		result.DeclaredLength = receipt.ContentLength
		started := time.Now()
		timer := time.AfterFunc(request.TransferTimeout, func() { ctx.cancel(ErrTransferTimeout) })
		defer timer.Stop()
		defer func() {
			elapsed := time.Since(started)
			result.ActiveElapsed = &elapsed
			if cause := context.Cause(ctx); cause != nil {
				err = errors.Join(err, cause)
			}
		}()
		result.PayloadBytes, result.ByteLimitReached, err = consumeHTTPBody(ctx, response, receipt, request.HTTPS.MaxBodyBytes, false)
		return err
	}})
	return result, resultErr
}

type UploadRequest struct {
	// HTTPS.MaxBodyBytes bounds the retained endpoint response.
	HTTPS           HTTPSRequest
	PayloadBytes    int64
	TransferTimeout time.Duration
}

type UploadReceipt struct {
	HTTPS               HTTPSReceipt
	GeneratedBytes      int64
	WriterAcceptedBytes int64
	ActiveElapsed       *time.Duration
}

// Upload generates a finite repeated byte pattern in 32 KiB chunks. Counts are
// application bytes accepted by net/http's chunk writer, including a positive
// n returned with an error, never kernel/wire/remote accepted bytes.
func (e *Executor) Upload(ctx context.Context, request UploadRequest) (result UploadReceipt, resultErr error) {
	if ctx == nil || request.PayloadBytes < 1 || request.TransferTimeout <= 0 {
		return result, errors.New("invalid upload context/byte/time budget")
	}
	body := &uploadBody{bytes: request.PayloadBytes, timeout: request.TransferTimeout}
	result.HTTPS, resultErr = e.http(ctx, request.HTTPS, httpPlan{method: http.MethodPost, secure: true, body: body, finish: func() error {
		// Native HTTP may return before its body writer. Snapshot without joining,
		// before operation cleanup can be mistaken for a native writer failure.
		body.mu.Lock()
		result.GeneratedBytes, result.WriterAcceptedBytes = body.produced, body.written
		if !body.began.IsZero() {
			elapsed := body.elapsed
			if elapsed == 0 {
				elapsed = time.Since(body.began)
			}
			result.ActiveElapsed = &elapsed
		}
		writeErr := body.err
		body.mu.Unlock()
		return writeErr
	}})
	if result.GeneratedBytes != request.PayloadBytes || result.WriterAcceptedBytes != request.PayloadBytes {
		resultErr = errors.Join(resultErr, ErrUploadIncomplete)
	}
	return result, resultErr
}

type uploadBody struct {
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelCauseFunc
	bytes             int64
	timeout           time.Duration
	closed            bool
	began             time.Time
	elapsed           time.Duration
	produced, written int64
	err               error
}

func (b *uploadBody) Read([]byte) (int, error) {
	return 0, ErrUnsupported // Never silently substitute reader production accounting.
}

func (b *uploadBody) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *uploadBody) WriteTo(writer io.Writer) (count int64, resultErr error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, ErrUploadIncomplete
	}
	b.began = time.Now()
	b.mu.Unlock()
	timer := time.AfterFunc(b.timeout, func() { b.cancel(ErrTransferTimeout) })
	defer timer.Stop()
	defer func() {
		b.mu.Lock()
		b.elapsed, b.err = time.Since(b.began), resultErr
		b.mu.Unlock()
	}()
	buffer := make([]byte, transferChunk)
	for i := range buffer {
		buffer[i] = byte(i)
	}
	for count < b.bytes {
		if err := b.ctx.Err(); err != nil {
			return count, errors.Join(err, context.Cause(b.ctx))
		}
		chunk := buffer[:min(int64(len(buffer)), b.bytes-count)]
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return count, ErrUploadIncomplete
		}
		b.produced += int64(len(chunk))
		b.mu.Unlock()
		n, err := writer.Write(chunk)
		b.mu.Lock()
		b.written += int64(n)
		b.err = err
		b.mu.Unlock()
		count += int64(n)
		if err != nil {
			return count, err
		}
		if n != len(chunk) {
			return count, io.ErrShortWrite
		}
	}
	return count, nil
}
