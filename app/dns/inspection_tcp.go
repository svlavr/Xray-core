package dns

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// dnsTCPExchange keeps TCP framing outside the decoded DNS payload facts. The
// dispatcher may consume the two-byte length prefix in separate reads, while
// its inspection cursor already guarantees that sniff replay is credited once.
type dnsTCPExchange struct {
	stats.Exchange

	mu              sync.Mutex
	prefixRemaining uint64
	bodyRemaining   uint64
}

func newDNSTCPExchange(exchange stats.Exchange, bodySize uint64) *dnsTCPExchange {
	return &dnsTCPExchange{
		Exchange:        exchange,
		prefixRemaining: 2,
		bodyRemaining:   bodySize,
	}
}

func (e *dnsTCPExchange) AddUplink(value uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if discarded := min(value, e.prefixRemaining); discarded != 0 {
		e.prefixRemaining -= discarded
		value -= discarded
	}
	credited := min(value, e.bodyRemaining)
	e.bodyRemaining -= credited

	if credited != 0 {
		e.Exchange.AddUplink(credited)
	}
}

func (e *dnsTCPExchange) finishUplink() {
	e.mu.Lock()
	incomplete := e.prefixRemaining != 0 || e.bodyRemaining != 0
	e.mu.Unlock()
	if incomplete {
		e.Exchange.MarkUplinkIncomplete()
	}
}

// dnsTCPQueryOwner owns only one routed DNS request connection. Close may race
// Dispatch returning its link; Attach closes that late connection immediately
// when local control already stopped the request.
type dnsTCPQueryOwner struct {
	mu       sync.Mutex
	conn     net.Conn
	closed   bool
	cancel   context.CancelFunc
	exchange *dnsTCPExchange
	endOnce  sync.Once
}

func (o *dnsTCPQueryOwner) attach(conn net.Conn) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		_ = conn.Close()
		return io.ErrClosedPipe
	}
	if o.conn != nil {
		o.mu.Unlock()
		_ = conn.Close()
		return io.ErrClosedPipe
	}
	o.conn = conn
	o.mu.Unlock()
	return nil
}

func (o *dnsTCPQueryOwner) Close() error {
	if o.exchange != nil {
		o.exchange.finishUplink()
	}
	return o.closeResources()
}

func (o *dnsTCPQueryOwner) closeResources() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	conn := o.conn
	cancel := o.cancel
	o.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (o *dnsTCPQueryOwner) finish() {
	o.endOnce.Do(func() {
		if o.exchange != nil {
			o.exchange.finishUplink()
			o.exchange.Finish()
		}
		_ = o.closeResources()
	})
}

func (o *dnsTCPQueryOwner) markWriteError() {
	if o == nil || o.exchange == nil {
		return
	}
	o.exchange.MarkUplinkIncomplete()
	o.exchange.SetEndReason(stats.EndReasonWriteError)
}

func (o *dnsTCPQueryOwner) recordResponseRead(n int64, expected int64, err error) {
	if o == nil || o.exchange == nil {
		return
	}
	if n > 0 {
		o.exchange.AddDownlink(uint64(n))
	}
	if err != nil || n != expected {
		o.exchange.MarkDownlinkIncomplete()
		o.exchange.SetEndReason(stats.EndReasonReadError)
	}
}

func (o *dnsTCPQueryOwner) markResponseError() {
	if o == nil || o.exchange == nil {
		return
	}
	o.exchange.MarkDownlinkIncomplete()
	o.exchange.SetEndReason(stats.EndReasonReadError)
}

func (o *dnsTCPQueryOwner) markResponseDecodeError() {
	if o == nil || o.exchange == nil {
		return
	}
	o.exchange.SetEndReason(stats.EndReasonReadError)
}

func beginRoutedDNSTCPObservation(ctx context.Context, destination net.Destination, bodySize uint64) (context.Context, *dnsTCPQueryOwner) {
	// The routed DNS request is a new INTERNAL root and must never continue the
	// observation that caused name resolution.
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	instance := core.FromContext(ctx)
	if instance == nil {
		return ctx, nil
	}
	provider, ok := instance.GetFeature(stats.ManagerType()).(stats.ObservationProvider)
	if !ok {
		return ctx, nil
	}
	store := provider.Observation()
	if store == nil {
		return ctx, nil
	}

	observedCtx, cancel := context.WithCancel(ctx)
	owner := &dnsTCPQueryOwner{cancel: cancel}
	root := store.PrepareTCP(stats.TrafficOriginInternal, net.Destination{}, destination, owner.Close)
	if root == nil {
		cancel()
		return ctx, nil
	}
	owner.exchange = newDNSTCPExchange(root, bodySize)
	observation := &session.LogicalObservation{Exchange: owner.exchange, InputAtExecution: true}
	observation.ReturnedLink.Store(true)
	return session.ContextWithLogicalObservation(observedCtx, observation), owner
}
