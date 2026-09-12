package pipe

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
)

type state byte

const (
	open state = iota
	closed
	errord
)

type pipeOption struct {
	limit           int32 // maximum buffer size in bytes
	discardOverflow bool
	lifecycle       WriteLifecycle
}

func (o *pipeOption) isFull(curSize int32) bool {
	return o.limit >= 0 && curSize > o.limit
}

type pipe struct {
	sync.Mutex
	data        buf.MultiBuffer
	readSignal  *signal.Notifier
	writeSignal *signal.Notifier
	done        *done.Instance
	errChan     chan error
	option      pipeOption
	state       state
}

var (
	errBufferFull = errors.New("buffer full")
	errSlowDown   = errors.New("slow down")
)

func (p *pipe) Len() int32 {
	p.Lock()
	defer p.Unlock()
	data := p.data
	if data == nil {
		return 0
	}
	return data.Len()
}

func (p *pipe) getState(forRead bool) error {
	switch p.state {
	case open:
		if !forRead && p.option.isFull(p.data.Len()) {
			return errBufferFull
		}
		return nil
	case closed:
		if !forRead {
			return io.ErrClosedPipe
		}
		if !p.data.IsEmpty() {
			return nil
		}
		return io.EOF
	case errord:
		return io.ErrClosedPipe
	default:
		panic("impossible case")
	}
}

func (p *pipe) readMultiBufferInternal() (buf.MultiBuffer, error, bool) {
	p.Lock()
	defer p.Unlock()

	if err := p.getState(true); err != nil {
		return nil, err, p.state != open && p.data.IsEmpty()
	}

	data := p.data
	p.data = nil
	return data, nil, p.state != open
}

func (p *pipe) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		data, err, drained := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			if drained && p.option.lifecycle != nil {
				p.option.lifecycle.MarkDrained()
			}
			return data, err
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case err = <-p.errChan:
			return nil, err
		}
	}
}

func (p *pipe) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	for {
		data, err, drained := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			if drained && p.option.lifecycle != nil {
				p.option.lifecycle.MarkDrained()
			}
			return data, err
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case <-timer.C:
			return nil, buf.ErrReadTimeout
		}
	}
}

func (p *pipe) writeMultiBufferInternal(mb buf.MultiBuffer) error {
	p.Lock()
	defer p.Unlock()

	if err := p.getState(false); err != nil {
		return err
	}

	if p.data == nil {
		p.data = mb
	} else {
		p.data, _ = buf.MergeMulti(p.data, mb)
	}
	return nil
}

func (p *pipe) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}
	var acceptedBytes uint64
	for _, buffer := range mb {
		acceptedBytes += uint64(buffer.Len())
	}
	reserved := false
	if p.option.lifecycle != nil {
		reserved = p.option.lifecycle.BeginWrite()
	}
	accepted := false
	defer func() {
		if p.option.lifecycle == nil {
			return
		}
		if accepted {
			p.option.lifecycle.CompleteWrite(reserved, acceptedBytes)
		} else {
			p.option.lifecycle.CompleteWrite(reserved, 0)
		}
	}()

	for {
		err := p.writeMultiBufferInternal(mb)
		if err == nil {
			p.readSignal.Signal()
			accepted = true
			return nil
		}

		if err == errBufferFull {
			if p.option.discardOverflow {
				buf.ReleaseMulti(mb)
				return nil
			}
			select {
			case <-p.writeSignal.Wait():
				continue
			case <-p.done.Wait():
				buf.ReleaseMulti(mb)
				return io.ErrClosedPipe
			}
		}

		buf.ReleaseMulti(mb)
		p.readSignal.Signal()
		return err
	}
}

func (p *pipe) Close() error {
	p.Lock()
	alreadyStopped := p.state == closed || p.state == errord
	if !alreadyStopped {
		p.state = closed
		common.Must(p.done.Close())
	}
	drained := p.data.IsEmpty()
	p.Unlock()

	if p.option.lifecycle != nil {
		p.option.lifecycle.HalfClose()
		p.option.lifecycle.Seal()
		if drained {
			p.option.lifecycle.MarkDrained()
		}
	}
	return nil
}

// Interrupt implements common.Interruptible.
func (p *pipe) Interrupt() {
	p.Lock()

	if !p.data.IsEmpty() {
		buf.ReleaseMulti(p.data)
		p.data = nil
		if p.state == closed {
			p.state = errord
		}
	}

	if p.state == closed || p.state == errord {
		p.Unlock()
		if p.option.lifecycle != nil {
			p.option.lifecycle.Seal()
			p.option.lifecycle.MarkDrained()
		}
		return
	}

	p.state = errord

	common.Must(p.done.Close())
	p.Unlock()
	if p.option.lifecycle != nil {
		p.option.lifecycle.Seal()
		p.option.lifecycle.MarkDrained()
	}
}
