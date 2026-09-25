package taggedimpl

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

type taggedObservation struct {
	mu       sync.Mutex
	conn     net.Conn
	exchange stats.Exchange
	closed   bool
	cancel   context.CancelFunc
}

func beginTaggedObservation(ctx context.Context, instance *core.Instance, destination net.Destination) (context.Context, *taggedObservation) {
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
	owner := &taggedObservation{cancel: cancel}
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	var exchange stats.Exchange
	if destination.Network == net.Network_TCP {
		exchange = store.PrepareTCP(session.TrafficOriginFromContext(ctx), source, destination, owner.Close)
	} else {
		exchange = store.Begin(stats.FlowKindUDPAssociation, session.TrafficOriginFromContext(ctx), source, destination, owner.Close)
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

func (o *taggedObservation) attach(conn net.Conn) {
	o.mu.Lock()
	o.conn = conn
	closed := o.closed
	o.mu.Unlock()
	if closed {
		conn.Close()
	}
}

func (o *taggedObservation) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	conn := o.conn
	exchange, cancel := o.exchange, o.cancel
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if conn != nil {
		err = conn.Close()
	}
	if exchange != nil {
		exchange.Finish()
	}
	return err
}

func (o *taggedObservation) recordRead(n int, err error) {
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

type inspectedTaggedConn struct {
	net.Conn
	observation *taggedObservation
}

func (c *inspectedTaggedConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	c.observation.recordRead(n, err)
	return n, err
}

func (c *inspectedTaggedConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.Conn.(buf.Reader).ReadMultiBuffer()
	c.observation.recordRead(int(mb.Len()), err)
	return mb, err
}

func (c *inspectedTaggedConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return c.Conn.(buf.Writer).WriteMultiBuffer(mb)
}

func (c *inspectedTaggedConn) Close() error { return c.observation.Close() }

func DialTaggedOutbound(ctx context.Context, dispatcher routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
	instance := core.FromContext(ctx)
	if instance == nil {
		return nil, errors.New("Instance context variable is not in context, dial denied. ")
	}
	ctx, observation := beginTaggedObservation(ctx, instance, dest)
	content := new(session.Content)
	content.SkipDNSResolve = true

	ctx = session.ContextWithContent(ctx, content)
	ctx = session.SetForcedOutboundTagToContext(ctx, tag)

	r, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		if observation != nil {
			observation.Close()
		}
		return nil, err
	}
	var readerOpt cnc.ConnectionOption
	if dest.Network == net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(r.Reader)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(r.Reader)
	}
	conn := cnc.NewConnection(cnc.ConnectionInputMulti(r.Writer), readerOpt)
	if observation == nil {
		return conn, nil
	}
	observation.attach(conn)
	return &inspectedTaggedConn{Conn: conn, observation: observation}, nil
}

func init() {
	tagged.Dialer = DialTaggedOutbound
}
