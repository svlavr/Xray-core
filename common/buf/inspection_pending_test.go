package buf

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/stats"
)

type pendingReceipt struct {
	stats.Exchange
	credited uint64
}

func (r *pendingReceipt) AddUplink(n uint64)       { r.credited += n }
func (r *pendingReceipt) AddSelectedUplink(uint64) {}

type pendingPayload struct {
	release chan struct{}
	data    *Buffer
}

func (r *pendingPayload) ReadMultiBuffer() (MultiBuffer, error) {
	<-r.release
	return MultiBuffer{r.data}, io.EOF
}

func TestInspectionCompletedPendingReadIsReleasedOnInterrupt(t *testing.T) {
	payload := New()
	payload.Write([]byte("unconsumed"))
	lower := &pendingPayload{release: make(chan struct{}), data: payload}
	receipt := new(pendingReceipt)
	cursor := NewInspectionReader(&BufferedReader{Reader: lower}, receipt, func() {})
	if mb, err := cursor.ReadMultiBufferTimeout(time.Millisecond); err != nil || len(mb) != 0 {
		t.Fatalf("pending: %v %v", mb, err)
	}
	cursor.mu.Lock()
	pending := cursor.pending
	cursor.mu.Unlock()
	close(lower.release)
	<-pending.done
	cursor.Interrupt()
	if !payload.IsEmpty() || receipt.credited != 0 {
		t.Fatal("abandoned payload leaked or was credited")
	}
	if mb, err := cursor.ReadMultiBuffer(); len(mb) != 0 || err != io.ErrClosedPipe {
		t.Fatalf("closed: %v %v", mb, err)
	}
	cursor.Interrupt()
}
