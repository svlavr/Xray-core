package core

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
)

// apiObservation owns the caller-facing endpoint lifecycle. The dispatcher
// remains the execution owner; this guard only joins exact local Close with
// the inspection root created for the API call.
type apiObservation struct {
	mu            sync.Mutex
	closer        io.Closer
	exchange      stats.Exchange
	closed        bool
	finishOnClose bool
	cancel        context.CancelFunc
}

func beginAPIObservation(ctx context.Context, instance *Instance, destination net.Destination, kind stats.FlowKind, finishOnClose bool) (context.Context, *apiObservation) {
	if current := session.LogicalObservationFromContext(ctx); current != nil && current.Exchange != nil {
		continuation := &session.LogicalObservation{Exchange: current.Exchange}
		continuation.ReturnedLink.Store(true)
		return session.ContextWithLogicalObservation(ctx, continuation), nil
	}
	feature := instance.GetFeature(stats.ManagerType())
	provider, ok := feature.(stats.ObservationProvider)
	if !ok {
		return ctx, nil
	}
	store := provider.Observation()
	if store == nil {
		return ctx, nil
	}

	ownedCtx, cancel := context.WithCancel(ctx)
	owner := &apiObservation{finishOnClose: finishOnClose, cancel: cancel}
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	var exchange stats.Exchange
	if kind == stats.FlowKindTCP {
		exchange = store.PrepareTCP(session.TrafficOriginFromContext(ctx), source, destination, owner.Close)
	} else {
		exchange = store.Begin(kind, session.TrafficOriginFromContext(ctx), source, destination, owner.Close)
	}
	owner.mu.Lock()
	owner.exchange = exchange
	closed := owner.closed
	owner.mu.Unlock()
	if exchange == nil {
		cancel()
		return ctx, nil
	}
	if closed {
		exchange.Finish()
	}
	observation := &session.LogicalObservation{Exchange: exchange, InputAtExecution: true}
	observation.ReturnedLink.Store(true)
	return session.ContextWithLogicalObservation(ownedCtx, observation), owner
}

func (o *apiObservation) attach(closer io.Closer) {
	o.mu.Lock()
	o.closer = closer
	closed := o.closed
	o.mu.Unlock()
	if closed {
		closer.Close()
	}
}

func (o *apiObservation) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	closer := o.closer
	exchange := o.exchange
	finish := o.finishOnClose
	cancel := o.cancel
	o.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var err error
	if closer != nil {
		err = closer.Close()
	}
	if exchange != nil && (finish || closer == nil) {
		exchange.Finish()
	}
	return err
}

func (o *apiObservation) recordRead(n int, err error) {
	if n > 0 {
		o.exchange.AddDownlink(uint64(n))
	}
	if err == nil {
		return
	}
	reason := stats.EndReasonReadError
	if err == io.EOF {
		reason = stats.EndReasonEOF
	}
	if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		reason = stats.EndReasonTimeout
	}
	o.exchange.SetEndReason(reason)
}

type inspectedAPIConn struct {
	net.Conn
	observation *apiObservation
}

func (c *inspectedAPIConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	c.observation.recordRead(n, err)
	return n, err
}

func (c *inspectedAPIConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.Conn.(buf.Reader).ReadMultiBuffer()
	c.observation.recordRead(int(mb.Len()), err)
	return mb, err
}

func (c *inspectedAPIConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return c.Conn.(buf.Writer).WriteMultiBuffer(mb)
}

func (c *inspectedAPIConn) Close() error {
	return c.observation.Close()
}

type inspectedAPIPacketConn struct {
	net.PacketConn
	observation *apiObservation
}

func (c *inspectedAPIPacketConn) Close() error {
	return c.observation.Close()
}
