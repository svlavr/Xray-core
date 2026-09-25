package proxy

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/features/stats"
)

// rawCopyReceipt is the bounded set of existing sinks updated for every
// positive destination-pump result. Callers must not repeat a final addition.
type rawCopyReceipt struct {
	exchange     stats.Exchange
	readCounter  stats.Counter
	writeCounter stats.Counter
	userCounter  stats.Counter
}

func (r *rawCopyReceipt) add(n int64) {
	if r == nil || n <= 0 {
		return
	}
	if r.exchange != nil {
		r.exchange.AddDownlink(uint64(n))
	}
	if r.readCounter != nil {
		r.readCounter.Add(n)
	}
	if r.writeCounter != nil {
		r.writeCounter.Add(n)
	}
	if r.userCounter != nil {
		r.userCounter.Add(n)
	}
}

func (r *rawCopyReceipt) markReadError(err error) {
	if errors.Is(err, io.EOF) {
		r.markError(err, stats.EndReasonEOF)
		return
	}
	r.markError(err, stats.EndReasonReadError)
}

func (r *rawCopyReceipt) markWriteError(err error) {
	r.markError(err, stats.EndReasonWriteError)
}

func (r *rawCopyReceipt) markError(err error, reason stats.EndReason) {
	if r == nil || r.exchange == nil || err == nil {
		return
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		reason = stats.EndReasonTimeout
	}
	r.exchange.SetEndReason(reason)
}
