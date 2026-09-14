package dispatcher

import (
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// userStreamReader owns the post-handshake USER input, retained payload and
// concrete stop owner. Reads have one consumer; stop may run concurrently.
type userStreamReader struct {
	mu       sync.Mutex
	reads    sync.WaitGroup
	stopOnce sync.Once
	reader   buf.Reader
	stop     io.Closer
	retained buf.MultiBuffer
	returned stats.Counter
	pending  *userStreamPendingRead
	closed   bool
	stopErr  error
}

type userStreamPendingRead struct {
	done chan struct{}
	mb   buf.MultiBuffer
	err  error
}

func newUserStreamReader(reader buf.Reader, retained buf.MultiBuffer, stop io.Closer, returned stats.Counter) *userStreamReader {
	return &userStreamReader{reader: reader, stop: stop, retained: retained, returned: returned}
}

func (r *userStreamReader) count(mb buf.MultiBuffer) {
	if r.returned != nil {
		r.returned.Add(int64(mb.Len()))
	}
}

func (r *userStreamReader) takeRetainedLocked() buf.MultiBuffer {
	if r.retained.IsEmpty() {
		return nil
	}
	mb := r.retained
	r.retained = nil
	return mb
}

func (r *userStreamReader) takePending(pending *userStreamPendingRead) (buf.MultiBuffer, error) {
	<-pending.done
	r.mu.Lock()
	if r.pending != pending {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	r.pending = nil
	mb, err := pending.mb, pending.err
	pending.mb, pending.err = nil, nil
	if r.closed {
		r.mu.Unlock()
		buf.ReleaseMulti(mb)
		return nil, io.ErrClosedPipe
	}
	r.mu.Unlock()
	r.count(mb)
	return mb, err
}

func (r *userStreamReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	r.reads.Add(1)
	defer r.reads.Done()
	if mb := r.takeRetainedLocked(); mb != nil {
		r.mu.Unlock()
		r.count(mb)
		return mb, nil
	}
	if pending := r.pending; pending != nil {
		r.mu.Unlock()
		return r.takePending(pending)
	}
	reader := r.reader
	r.mu.Unlock()

	mb, err := reader.ReadMultiBuffer()
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		buf.ReleaseMulti(mb)
		return nil, io.ErrClosedPipe
	}
	r.count(mb)
	return mb, err
}

// ReadMultiBufferTimeout keeps one resumable pending read. It remains bounded
// for transports whose SetReadDeadline method is a no-op.
func (r *userStreamReader) ReadMultiBufferTimeout(duration time.Duration) (buf.MultiBuffer, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	r.reads.Add(1)
	defer r.reads.Done()
	if mb := r.takeRetainedLocked(); mb != nil {
		r.mu.Unlock()
		r.count(mb)
		return mb, nil
	}
	pending := r.pending
	if pending == nil {
		pending = &userStreamPendingRead{done: make(chan struct{})}
		r.pending = pending
		reader := r.reader
		r.reads.Add(1)
		go func() {
			pending.mb, pending.err = reader.ReadMultiBuffer()
			close(pending.done)
			r.reads.Done()
		}()
	}
	r.mu.Unlock()

	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-pending.done:
		return r.takePending(pending)
	case <-timer.C:
		return nil, nil
	}
}

func (r *userStreamReader) Interrupt()   { _ = r.stopAndWait(true) }
func (r *userStreamReader) Close() error { return r.stopAndWait(false) }

func (r *userStreamReader) stopAndWait(interrupt bool) error {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		stop := r.stop
		r.mu.Unlock()
		if interrupt {
			r.stopErr = common.Interrupt(stop)
		} else {
			r.stopErr = common.Close(stop)
		}
		r.reads.Wait()

		r.mu.Lock()
		buf.ReleaseMulti(r.retained)
		r.retained = nil
		if r.pending != nil {
			r.pending.mb = buf.ReleaseMulti(r.pending.mb)
			r.pending = nil
		}
		r.reader = nil
		r.stop = nil
		r.mu.Unlock()
	})
	return r.stopErr
}
