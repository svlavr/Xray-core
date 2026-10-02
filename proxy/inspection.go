package proxy

import (
	"context"
	"io"
	stdnet "net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

// ObserveTCP attaches inspection to one decoded, unencoded TCP endpoint before
// DispatchLink. The caller must own conn exclusively for this exchange; this
// is not suitable for HTTP keep-alive requests or shared carrier connections.
// link.Reader may retain handshake residual payload. link.Writer must write
// directly to conn without post-binding protocol framing; a BufferedWriter may
// contain a known pre-binding framing prefix, which receipt attachment excludes
// from successful decoded operations. When enabled, the caller must defer the returned
// cleanup until DispatchLink returns. Disabled collection leaves the context and
// link unchanged and returns nil cleanup.
func ObserveTCP(ctx context.Context, manager stats.Manager, conn net.Conn, dest net.Destination, link *transport.Link) (context.Context, func()) {
	return observeEndpoint(ctx, manager, conn, dest, link, net.Network_TCP, false)
}

// ObserveUDP attaches receipts to one exclusively owned, decoded UDP association.
// The reader must preserve packet boundaries/destinations and the writer must
// expose actual endpoint results, directly or through WithWriterReceipt.
// The caller defers cleanup until DispatchLink returns, as for ObserveTCP.
func ObserveUDP(ctx context.Context, manager stats.Manager, conn net.Conn, dest net.Destination, link *transport.Link) (context.Context, func()) {
	return observeEndpoint(ctx, manager, conn, dest, link, net.Network_UDP, false)
}

func observeEndpoint(ctx context.Context, manager stats.Manager, conn net.Conn, dest net.Destination, link *transport.Link, kind net.Network, returned bool) (context.Context, func()) {
	if isMuxCarrier(dest) {
		return ctx, nil
	}
	observedCtx, observation, cancel := beginObservation(ctx, manager, conn, dest, kind, returned)
	if observation == nil {
		return ctx, nil
	}
	observation.SuppliedEndpoint = !returned
	flow := observation.Exchange
	cursor := buf.NewInspectionReader(link.Reader, flow, func() { cancel(); conn.Close() })
	if kind == net.Network_UDP {
		cursor.PacketDestination = dest
	}
	link.Reader = cursor
	link.Writer, observation.WriterReceiptAttached = buf.AttachWriterReceiptWithStatus(link.Writer, flow)
	return observedCtx, func() {
		cursor.Interrupt()
		flow.Finish()
	}
}

func beginObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind net.Network, returned bool) (context.Context, *session.LogicalObservation, context.CancelFunc) {
	observedCtx, flow, cancel := BeginObservedEndpoint(ctx, ObservationStore(manager), conn, dest, kind)
	if flow == nil {
		return ctx, nil, nil
	}
	observation := &session.LogicalObservation{Exchange: flow}
	observation.ReturnedLink.Store(returned)
	return session.ContextWithLogicalObservation(observedCtx, observation), observation, cancel
}

// BeginReturnedObservation admits an exclusive codec endpoint before Dispatch.
// The caller binds its decoded input and codec output when native preparation
// produces them and defers cleanup until the endpoint owner returns.
func BeginReturnedObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind net.Network) (context.Context, *session.LogicalObservation, func()) {
	return beginOwnedObservation(ctx, manager, conn, dest, kind, true)
}

// BeginExecutionObservation admits request-local work whose decoded input is
// credited when the selected execution owner consumes the returned link. The
// supplied closer must stop only that request, never a shared accepted carrier.
func BeginExecutionObservation(ctx context.Context, manager stats.Manager, owner io.Closer, dest net.Destination) (context.Context, *session.LogicalObservation, func()) {
	store := ObservationStore(manager)
	if store == nil || isMuxCarrier(dest) {
		return ctx, nil, nil
	}
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	flow := store.PrepareTCP(session.TrafficOriginFromContext(ctx), source, dest, owner.Close)
	if flow == nil {
		return ctx, nil, nil
	}
	observation := &session.LogicalObservation{Exchange: flow, InputAtExecution: true}
	observation.ReturnedLink.Store(true)
	return session.ContextWithLogicalObservation(ctx, observation), observation, func() {
		owner.Close()
		flow.Finish()
	}
}

func beginOwnedObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind net.Network, returned bool) (context.Context, *session.LogicalObservation, func()) {
	// The native MUX dispatcher recognizes this reserved carrier address even
	// when an incoming protocol command did not explicitly name MUX.
	if isMuxCarrier(dest) {
		return ctx, nil, nil
	}
	ctx, observation, cancel := beginObservation(ctx, manager, conn, dest, kind, returned)
	if observation == nil {
		return ctx, nil, nil
	}
	return ctx, observation, func() {
		cancel()
		conn.Close()
		observation.Exchange.Finish()
	}
}

func isMuxCarrier(dest net.Destination) bool {
	return dest.Address != nil && dest.Address.Family().IsDomain() && dest.Address.Domain() == "v1.mux.cool"
}

// ObservationStore resolves optional collection once at the native owner entry.
func ObservationStore(manager stats.Manager) stats.AdmissionStore {
	provider, ok := manager.(stats.ObservationProvider)
	if !ok {
		return nil
	}
	return provider.Observation()
}

// BeginObservedEndpoint admits an exclusively owned decoded endpoint without
// changing I/O. The caller owns cancel and Finish, and must attach its actual
// receipts before finishing the exchange.
func BeginObservedEndpoint(ctx context.Context, store stats.AdmissionStore, conn io.Closer, dest net.Destination, kind net.Network) (context.Context, stats.Exchange, context.CancelFunc) {
	if store == nil {
		return ctx, nil, nil
	}
	observedCtx, cancel := context.WithCancel(ctx)
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	stop := func() error { cancel(); return closeObservedEndpoint(conn) }
	var flow stats.Exchange
	if kind == net.Network_TCP {
		flow = store.PrepareTCP(session.TrafficOriginFromContext(ctx), source, dest, stop)
	} else {
		flow = store.Begin(kind, session.TrafficOriginFromContext(ctx), source, dest, stop)
	}
	if flow == nil {
		cancel()
		return ctx, nil, nil
	}
	return observedCtx, flow, cancel
}

func closeObservedEndpoint(conn io.Closer) error {
	err := conn.Close()
	for candidate := err; candidate != nil; {
		if candidate == stdnet.ErrClosed || candidate == io.ErrClosedPipe {
			return nil
		}
		// A joined error can include a real owner failure alongside ErrClosed.
		// Only one ordinary wrapping chain proves that close was idempotent.
		wrapped, ok := candidate.(interface{ Unwrap() error })
		if !ok {
			break
		}
		candidate = wrapped.Unwrap()
	}
	return err
}

// RecordPacketWrite maps a native framed-packet write to logical payload. A
// partial frame has no proven complete packet; its ciphertext/header prefix
// must not be counted as payload. The callback's native ray holds the receipt.
func RecordPacketWrite(receipt stats.Exchange, payload uint64, encoded, written int) {
	RecordPacketOutcome(receipt, payload, encoded > 0 && written == encoded)
}

// RecordPacketOutcome also accepts a native fragment group's combined result:
// one complete logical packet wins over any partial retry of that same packet.
func RecordPacketOutcome(receipt stats.Exchange, payload uint64, complete bool) {
	if receipt != nil && complete {
		receipt.AddDownlink(payload)
	}
}

// ObservedEndpoint returns the admitted endpoint when this reader owns it.
// Protocol-specific eligibility and effective target remain with the caller.
func ObservedEndpoint(ctx context.Context, reader buf.Reader, eligible bool) *session.LogicalObservation {
	if !eligible {
		return nil
	}
	if override, ok := reader.(*buf.EndpointOverrideReader); ok {
		reader = override.Reader
	}
	if _, ok := reader.(*buf.InspectionReader); !ok {
		return nil
	}
	observation := session.LogicalObservationFromContext(ctx)
	if observation == nil {
		return nil
	}
	return observation
}
