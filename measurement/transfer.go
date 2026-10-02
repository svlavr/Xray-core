package measurement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const transferChunk = 32 << 10

var (
	ErrTransferTimeout     = errors.New("active transfer time limit reached")
	ErrDigestMismatch      = errors.New("download payload digest mismatch")
	ErrIntegrityIncomplete = errors.New("complete download required for expected digest")
	ErrUploadIncomplete    = errors.New("upload payload not fully accepted by HTTP writer")
	ErrUploadACK           = errors.New("invalid upload acknowledgment")
)

type DownloadRequest struct {
	// HTTPS.MaxBodyBytes is the caller-selected streamed payload ceiling.
	HTTPS           HTTPSRequest
	TransferTimeout time.Duration
	ExpectedSHA256  *[sha256.Size]byte // Validated only after complete HTTP framing.
}

type DownloadReceipt struct {
	// HTTPS.Body is nil: no download payload is retained. HTTPS.BodyComplete
	// describes framing completion; PayloadBytes counts the consumed stream.
	HTTPS             HTTPSReceipt
	DeclaredLength    *int64 // -1 means no declared length; absent before response.
	PayloadBytes      int64
	SHA256            *[sha256.Size]byte // Present only for requested integrity, including partial bytes.
	ActiveElapsed     *time.Duration     // Read and hash phase, absent before response.
	ByteLimitReached  bool
	IntegrityVerified bool
}

// Download streams one HTTPS GET with fixed-size scratch space. Reaching the
// payload ceiling is a bounded observation; it does not imply response EOF.
func (e *Executor) Download(ctx context.Context, request DownloadRequest) (result DownloadReceipt, resultErr error) {
	if ctx == nil || request.TransferTimeout <= 0 {
		return result, errors.New("invalid download context/time budget")
	}
	var expected *[sha256.Size]byte
	if request.ExpectedSHA256 != nil {
		copy := *request.ExpectedSHA256
		expected = &copy
	}
	phaseCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	result.HTTPS, resultErr = e.exchangeHTTP(phaseCtx, request.HTTPS, http.MethodGet, nil, nil, func(ctx context.Context, response *http.Response, receipt *HTTPSReceipt) (err error) {
		length := response.ContentLength
		result.DeclaredLength = &length
		started := time.Now()
		timer := time.AfterFunc(request.TransferTimeout, func() { cancel(ErrTransferTimeout) })
		defer timer.Stop()
		var digest hash.Hash
		if expected != nil {
			digest = sha256.New()
		}
		defer func() {
			if digest != nil {
				sum := [sha256.Size]byte(digest.Sum(nil))
				result.SHA256 = &sum
			}
			elapsed := time.Since(started)
			result.ActiveElapsed = &elapsed
			if cause := context.Cause(phaseCtx); cause != nil {
				err = errors.Join(err, cause)
			}
		}()
		buffer := make([]byte, transferChunk)
		for result.PayloadBytes < request.HTTPS.MaxBodyBytes {
			if err := ctx.Err(); err != nil {
				return err
			}
			remaining := request.HTTPS.MaxBodyBytes - result.PayloadBytes
			n, readErr := response.Body.Read(buffer[:min(int64(len(buffer)), remaining)])
			if n > 0 {
				if digest != nil {
					_, _ = digest.Write(buffer[:n])
				}
				result.PayloadBytes += int64(n)
			}
			if readErr != nil {
				if readErr == io.EOF {
					receipt.BodyComplete = true
					break
				}
				return readErr
			}
		}
		result.ByteLimitReached = result.PayloadBytes == request.HTTPS.MaxBodyBytes
		if result.ByteLimitReached && length == result.PayloadBytes {
			// Fixed Content-Length framing is complete at its exact boundary.
			receipt.BodyComplete = true
		}
		if expected != nil {
			if !receipt.BodyComplete {
				return ErrIntegrityIncomplete
			}
			if [sha256.Size]byte(digest.Sum(nil)) != *expected {
				return ErrDigestMismatch
			}
			result.IntegrityVerified = true
		}
		return nil
	})
	return result, resultErr
}

type UploadRequest struct {
	// HTTPS.MaxBodyBytes bounds the retained endpoint response.
	HTTPS           HTTPSRequest
	PayloadBytes    int64
	TransferTimeout time.Duration
	// RequireAcknowledgment selects the explicit nonce/bytes/SHA-256 endpoint
	// contract. Otherwise the bounded response is raw and no ACK is inferred.
	RequireAcknowledgment bool
}

// UploadAcknowledgment is the selected TLS endpoint's validated declaration,
// not independent proof of storage, wire bytes or a terminal proxy route.
type UploadAcknowledgment struct {
	Bytes  int64
	SHA256 [sha256.Size]byte
}

type UploadReceipt struct {
	HTTPS                HTTPSReceipt
	Nonce                string
	GeneratedBytes       int64
	WriterAcceptedBytes  int64
	WriterAcceptedSHA256 *[sha256.Size]byte
	ActiveElapsed        *time.Duration
	Acknowledgment       *UploadAcknowledgment // absent unless the selected contract passes.
}

// Upload generates a finite repeated byte pattern in 32 KiB chunks. Counts are
// application bytes accepted by net/http's chunk writer, including a positive
// n returned with an error, never kernel/wire/remote accepted bytes.
func (e *Executor) Upload(ctx context.Context, request UploadRequest) (result UploadReceipt, resultErr error) {
	if ctx == nil || request.PayloadBytes < 1 || request.TransferTimeout <= 0 {
		return result, errors.New("invalid upload context/byte/time budget")
	}
	if request.RequireAcknowledgment {
		var err error
		request.HTTPS.URL, result.Nonce, err = withNonce(request.HTTPS.URL, "upload")
		if err != nil {
			return result, err
		}
	}
	phaseCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	body := &uploadBody{ctx: phaseCtx, cancel: cancel, bytes: request.PayloadBytes, timeout: request.TransferTimeout}
	if request.RequireAcknowledgment {
		body.accepted = sha256.New()
	}
	result.HTTPS, resultErr = e.exchangeHTTP(phaseCtx, request.HTTPS, http.MethodPost, body, nil, func(ctx context.Context, response *http.Response, receipt *HTTPSReceipt) error {
		return readHTTPSBody(response, receipt, request.HTTPS.MaxBodyBytes)
	})
	// Native HTTP may return before its body writer. Snapshot observed raw
	// counts without a completion certificate or a second cleanup deadline.
	body.mu.Lock()
	result.GeneratedBytes, result.WriterAcceptedBytes = body.produced, body.written
	if body.accepted != nil {
		digest := [sha256.Size]byte(body.accepted.Sum(nil))
		result.WriterAcceptedSHA256 = &digest
	}
	if !body.began.IsZero() {
		elapsed := body.elapsed
		if elapsed == 0 {
			elapsed = time.Since(body.began)
		}
		result.ActiveElapsed = &elapsed
	}
	writeErr := body.err
	body.mu.Unlock()
	resultErr = errors.Join(resultErr, writeErr)
	if cause := context.Cause(phaseCtx); cause != nil {
		resultErr = errors.Join(resultErr, cause)
	}
	if result.GeneratedBytes != request.PayloadBytes || result.WriterAcceptedBytes != request.PayloadBytes {
		resultErr = errors.Join(resultErr, ErrUploadIncomplete)
	}
	if resultErr == nil && request.RequireAcknowledgment {
		result.Acknowledgment, resultErr = uploadACK(result.HTTPS, result.Nonce, result.WriterAcceptedBytes, *result.WriterAcceptedSHA256)
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
	accepted          hash.Hash
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
		if b.accepted != nil {
			_, _ = b.accepted.Write(chunk[:n])
		}
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

func uploadACK(exchange HTTPSReceipt, nonce string, count int64, digest [sha256.Size]byte) (*UploadAcknowledgment, error) {
	if exchange.StatusCode != http.StatusOK {
		return nil, ErrUploadACK
	}
	var ack struct {
		Nonce  string `json:"nonce"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(exchange.Body, &ack) != nil || ack.Nonce != nonce || ack.Bytes != count || !strings.EqualFold(ack.SHA256, hex.EncodeToString(digest[:])) {
		return nil, ErrUploadACK
	}
	return &UploadAcknowledgment{Bytes: ack.Bytes, SHA256: digest}, nil
}
