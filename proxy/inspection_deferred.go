package proxy

import (
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
}

type endpointReceiptMode uint8

const (
	endpointPending endpointReceiptMode = iota
	endpointRaw
	endpointDecoded
)

func (r *deferredEndpointReceipt) AddUplink(n uint64) {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		r.uplink += n
	case endpointRaw:
		r.Exchange.AddUplink(n)
	}
	r.mu.Unlock()
}

func (r *deferredEndpointReceipt) AddDownlink(n uint64) {
	r.mu.Lock()
	switch r.mode {
	case endpointPending:
		r.downlink += n
	case endpointRaw:
		r.Exchange.AddDownlink(n)
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
