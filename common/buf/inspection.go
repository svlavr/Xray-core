package buf

import (
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
)

// InspectionReader is the decoded input cursor for an observed supplied stream.
// It replaces the handshake residual, timeout wrapper and sniff replay owners.
// Its lower reader is unchanged, including native readv. Only consumption by
// sniffing/execution credits custody; an abandoned pending read does not.
type InspectionReader struct {
	// InputAlreadyObserved is set for a callback endpoint whose decoded input
	// was credited before entering a native pipe. The cursor still owns replay
	// and pending reads, but pipe consumption adds no logical bytes.
	InputAlreadyObserved bool
	// PacketDestination enables packet metadata receipts and supplies the
	// requested destination for packets without explicit UDP metadata. Set once
	// at admission before dispatch; replay never records a packet twice.
	PacketDestination net.Destination
	mu                sync.Mutex
	reader            Reader
	initial, replay   MultiBuffer
	replayErr         error
	pending           *inspectionRead
	closed            bool
	flow              stats.Exchange
	counter           stats.Counter
	unblock           func()
}
type inspectionRead struct {
	done  chan struct{}
	mb    MultiBuffer
	err   error
	ready bool
}

func NewInspectionReader(r *BufferedReader, flow stats.Exchange, unblock func()) *InspectionReader {
	c := &InspectionReader{reader: r.Reader, initial: r.Buffer, flow: flow, unblock: unblock}
	r.Buffer = nil
	return c
}

// SetCounter preserves the separate native user counter on consumed input.
func (r *InspectionReader) SetCounter(c stats.Counter) {
	r.mu.Lock()
	r.counter = c
	r.mu.Unlock()
}

func (r *InspectionReader) readReason(err error) {
	if err == nil {
		return
	}
	reason := stats.EndReasonReadError
	if err == io.EOF {
		reason = stats.EndReasonEOF
	}
	if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		reason = stats.EndReasonTimeout
	}
	r.flow.SetEndReason(reason)
}

func (r *InspectionReader) credit(mb MultiBuffer) {
	if !r.InputAlreadyObserved && r.PacketDestination.IsValid() {
		for _, b := range mb {
			if b == nil {
				continue
			}
			destination := r.PacketDestination
			if b.UDP != nil {
				destination = *b.UDP
			}
			r.flow.PacketDestination(destination)
		}
	}
	n := uint64(mb.Len())
	if !r.InputAlreadyObserved {
		r.flow.AddUplink(n)
	}
	if r.counter != nil {
		r.counter.Add(int64(n))
	}
}

func (r *InspectionReader) next(timeout time.Duration, timed bool) (MultiBuffer, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	if !r.initial.IsEmpty() {
		mb := r.initial
		r.initial = nil
		r.credit(mb)
		r.mu.Unlock()
		return mb, nil
	}
	p := r.pending
	if p == nil && !timed {
		r.mu.Unlock()
		mb, err := r.reader.ReadMultiBuffer()
		r.mu.Lock()
		if r.closed {
			ReleaseMulti(mb)
			mb = nil
			err = io.ErrClosedPipe
		} else {
			r.credit(mb)
			r.readReason(err)
		}
		r.mu.Unlock()
		return mb, err
	}
	if p == nil {
		p = &inspectionRead{done: make(chan struct{})}
		r.pending = p
		go func() {
			mb, err := r.reader.ReadMultiBuffer()
			r.mu.Lock()
			if r.closed {
				ReleaseMulti(mb)
				r.pending = nil
			} else {
				p.mb, p.err, p.ready = mb, err, true
			}
			close(p.done)
			r.mu.Unlock()
		}()
	}
	r.mu.Unlock()
	if timed {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-p.done:
		case <-timer.C:
			return nil, nil
		}
	} else {
		<-p.done
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, io.ErrClosedPipe
	}
	mb, err := p.mb, p.err
	p.mb = nil
	r.pending = nil
	r.credit(mb)
	r.readReason(err)
	return mb, err
}

func (r *InspectionReader) ReadMultiBuffer() (MultiBuffer, error) {
	return r.read(0, false)
}

func (r *InspectionReader) ReadMultiBufferTimeout(timeout time.Duration) (MultiBuffer, error) {
	return r.read(timeout, true)
}

func (r *InspectionReader) read(timeout time.Duration, timed bool) (MultiBuffer, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	if !r.replay.IsEmpty() || r.replayErr != nil {
		mb, err := r.replay, r.replayErr
		r.replay, r.replayErr = nil, nil
		r.mu.Unlock()
		return mb, err
	}
	r.mu.Unlock()
	return r.next(timeout, timed)
}

// Cache keeps every returned byte and its terminal error for one replay.
func (r *InspectionReader) Cache(b *Buffer, timeout time.Duration) error {
	r.mu.Lock()
	err := r.replayErr
	r.mu.Unlock()
	if err != nil {
		return err
	}
	mb, err := r.next(timeout, true)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	if !mb.IsEmpty() {
		r.replay, _ = MergeMulti(r.replay, mb)
	}
	r.replayErr = err
	b.Clear()
	r.replay.Copy(b.Extend(min(r.replay.Len(), b.Cap())))
	if !r.replay.IsEmpty() {
		return nil
	}
	return err
}

// Interrupt seals custody, releases retained values and unblocks the exact
// endpoint. A pending lower read still releases any result it already owns.
func (r *InspectionReader) Interrupt() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.initial = ReleaseMulti(r.initial)
	r.replay = ReleaseMulti(r.replay)
	r.replayErr = nil
	if p := r.pending; p != nil && p.ready {
		p.mb = ReleaseMulti(p.mb)
		r.pending = nil
	}
	r.mu.Unlock()
	r.unblock()
}
