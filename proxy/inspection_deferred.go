package proxy

import (
	"math"
	"sync"

	"github.com/xtls/xray-core/features/stats"
)

// deferredEndpointReceipt keeps pre-route sniff and endpoint receipts local
// until the consuming owner selects raw payload or decoded DNS messages.
// It never retains packet buffers or creates another logical exchange.
type deferredEndpointReceipt struct {
	stats.Exchange
	mu       sync.Mutex
	mode     endpointReceiptMode
	uplink   uint64
	downlink uint64
	upLost   bool
	downLost bool
	upOver   bool
	downOver bool
	reasons  [7]stats.EndReason
	reasonN  int
}

type endpointReceiptMode uint8

const (
	endpointPending endpointReceiptMode = iota
	endpointRaw
	endpointDecoded
)

func (r *deferredEndpointReceipt) addPending(value *uint64, overflow *bool, n uint64) {
	if math.MaxUint64-*value < n {
		*value = math.MaxUint64
		*overflow = true
		return
	}
	*value += n
}

func (r *deferredEndpointReceipt) AddUplink(n uint64) {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		r.addPending(&r.uplink, &r.upOver, n)
	case endpointRaw:
		r.Exchange.AddUplink(n)
	}
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) AddDownlink(n uint64) {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		r.addPending(&r.downlink, &r.downOver, n)
	case endpointRaw:
		r.Exchange.AddDownlink(n)
	}
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) MarkUplinkIncomplete() {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		r.upLost = true
	case endpointRaw:
		r.Exchange.MarkUplinkIncomplete()
	}
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) MarkDownlinkIncomplete() {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		r.downLost = true
	case endpointRaw:
		r.Exchange.MarkDownlinkIncomplete()
	}
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) SetEndReason(reason stats.EndReason) {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		for i := 0; i < r.reasonN; i++ {
			if r.reasons[i] == reason {
				r.mu.Unlock()
				return
			}
		}
		if r.reasonN < len(r.reasons) {
			r.reasons[r.reasonN] = reason
			r.reasonN++
		}
	case endpointRaw:
		r.Exchange.SetEndReason(reason)
	}
	r.mu.Unlock()
}

// selectRaw must run under mu before any route binding or owner ending.
func (r *deferredEndpointReceipt) selectRaw() {
	if r.mode != endpointPending {
		return
	}
	r.mode = endpointRaw
	r.Exchange.AddUplink(r.uplink)
	r.Exchange.AddDownlink(r.downlink)
	if r.upOver {
		r.Exchange.AddUplink(1)
	}
	if r.downOver {
		r.Exchange.AddDownlink(1)
	}
	if r.upLost {
		r.Exchange.MarkUplinkIncomplete()
	}
	if r.downLost {
		r.Exchange.MarkDownlinkIncomplete()
	}
	for i := 0; i < r.reasonN; i++ {
		r.Exchange.SetEndReason(r.reasons[i])
	}
}

func (r *deferredEndpointReceipt) BindRoute() {
	r.mu.Lock()
	r.selectRaw()
	r.Exchange.BindRoute()
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) Unassign() {
	r.mu.Lock()
	r.selectRaw()
	r.Exchange.Unassign()
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) Finish() {
	r.mu.Lock()
	r.selectRaw()
	r.Exchange.Finish()
	r.mu.Unlock()
}

// selectDecoded drops uncommitted raw sniff/framing results and gives the DNS
// message owner the underlying receipt. Once raw settled, transfer is unsafe.
func (r *deferredEndpointReceipt) selectDecoded() stats.Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mode != endpointPending {
		return nil
	}
	r.mode = endpointDecoded
	r.Exchange.BindRoute()
	return r.Exchange
}

// The store invokes an exact stop on its underlying exchange. Settle known
// pre-claim facts before that store publishes the owner-close snapshot.
func (r *deferredEndpointReceipt) settleBeforeStop() {
	r.mu.Lock()
	r.selectRaw()
	r.mu.Unlock()
}
