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
	return observeEndpoint(ctx, manager, conn, dest, link, stats.FlowKindTCP, false)
}

// ObserveReturnedTCP binds the decoded endpoint before Dispatch returns its
// native pipe link. ObserveTCP's exclusive endpoint and payload-only writer
// requirements apply. The dispatcher consumes the one-shot role claim; its
// cleanup releases only its cursor, while the actual endpoint owner finishes.
func ObserveReturnedTCP(ctx context.Context, manager stats.Manager, conn net.Conn, dest net.Destination, endpoint *transport.Link) (context.Context, func()) {
	return observeEndpoint(ctx, manager, conn, dest, endpoint, stats.FlowKindTCP, true)
}

// ObserveUDP attaches receipts to one exclusively owned, decoded UDP association.
// The reader must preserve packet boundaries/destinations and the writer must
// expose actual endpoint results, directly or through WithWriterReceipt.
// The caller defers cleanup until DispatchLink returns, as for ObserveTCP.
func ObserveUDP(ctx context.Context, manager stats.Manager, conn net.Conn, dest net.Destination, link *transport.Link) (context.Context, func()) {
	return observeEndpoint(ctx, manager, conn, dest, link, stats.FlowKindUDPAssociation, false)
}

// ObserveFallback admits one dispatcher-bypassing fallback exchange before its
// direct dial. The configured destination is recorded without fabricating a
// routed outbound, and the existing buffered reader retains first-read custody.
// Disabled collection returns before parsing the configured destination.
func ObserveFallback(ctx context.Context, manager stats.Manager, conn io.Closer, network, address string, reader buf.Reader) (context.Context, buf.Reader, stats.Exchange, func()) {
	store := ObservationStore(manager)
	if store == nil {
		return ctx, reader, nil, nil
	}
	if network == "tcp4" || network == "tcp6" {
		network = "tcp"
	}
	destination, err := net.ParseDestination(network + ":" + address)
	if err != nil {
		destination = net.Destination{}
	}
	observedCtx, flow, cancel := BeginObservedEndpoint(ctx, store, conn, destination, stats.FlowKindTCP)
	if flow == nil {
		return ctx, reader, nil, nil
	}
	flow.Route(stats.RouteStep{
		Selection:      stats.SelectionUnknown,
		Original:       destination,
		RouteTarget:    destination,
		SelectedTarget: destination,
	})
	flow.BindRoute()
	cursor := ObserveDecodedReader(reader, flow, func() { cancel(); conn.Close() })
	return observedCtx, cursor, flow, func() {
		cursor.Interrupt()
		flow.Finish()
	}
}

func observeEndpoint(ctx context.Context, manager stats.Manager, conn net.Conn, dest net.Destination, link *transport.Link, kind stats.FlowKind, returned bool) (context.Context, func()) {
	if isMuxCarrier(dest) {
		return ctx, nil
	}
	var observedCtx context.Context
	var observation *session.LogicalObservation
	var cancel context.CancelFunc
	if returned {
		observedCtx, observation, cancel = beginObservation(ctx, manager, conn, dest, kind, true)
	} else {
		observedCtx, observation, cancel = beginDeferredObservation(ctx, manager, conn, dest, kind)
	}
	if observation == nil {
		return ctx, nil
	}
	flow := observation.Exchange
	cursor := ObserveDecodedReader(link.Reader, flow, func() { cancel(); conn.Close() })
	if kind == stats.FlowKindUDPAssociation {
		cursor.PacketDestination = dest
	}
	link.Reader = cursor
	link.Writer = buf.AttachWriterReceipt(link.Writer, flow)
	return observedCtx, func() {
		cursor.Interrupt()
		flow.Finish()
	}
}

func beginDeferredObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind stats.FlowKind) (context.Context, *session.LogicalObservation, context.CancelFunc) {
	store := ObservationStore(manager)
	if store == nil {
		return ctx, nil, nil
	}
	observedCtx, cancel := context.WithCancel(ctx)
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	gate := new(deferredEndpointReceipt)
	// A UDP Begin publishes the exchange immediately. Its stop may run before
	// Begin returns, so keep the gate locked until the underlying receipt exists.
	gate.mu.Lock()
	stop := func() error {
		gate.settleBeforeStop()
		cancel()
		return closeObservedEndpoint(conn)
	}
	var flow stats.Exchange
	if kind == stats.FlowKindTCP {
		flow = store.PrepareTCP(session.TrafficOriginFromContext(ctx), source, dest, stop)
	} else {
		flow = store.Begin(kind, session.TrafficOriginFromContext(ctx), source, dest, stop)
	}
	if flow == nil {
		gate.mu.Unlock()
		cancel()
		return ctx, nil, nil
	}
	gate.Exchange = flow
	gate.mu.Unlock()
	observation := &session.LogicalObservation{Exchange: gate}
	return session.ContextWithLogicalObservation(observedCtx, observation), observation, cancel
}

func beginObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind stats.FlowKind, returned bool) (context.Context, *session.LogicalObservation, context.CancelFunc) {
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
func BeginReturnedObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind stats.FlowKind) (context.Context, *session.LogicalObservation, func()) {
	return beginOwnedObservation(ctx, manager, conn, dest, kind, true)
}

// BeginSuppliedObservation admits an exclusive decoded endpoint before its
// protocol response is prepared. The caller attaches decoded receipts only
// after preparation succeeds, so response framing and failed preparation stay
// outside logical payload accounting.
func BeginSuppliedObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind stats.FlowKind) (context.Context, *session.LogicalObservation, func()) {
	return beginOwnedObservation(ctx, manager, conn, dest, kind, false)
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

func beginOwnedObservation(ctx context.Context, manager stats.Manager, conn io.Closer, dest net.Destination, kind stats.FlowKind, returned bool) (context.Context, *session.LogicalObservation, func()) {
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

// ObserveDecodedReader wraps only decoded payload and retains existing buffered
// input once. Its owning task must Interrupt it during native cleanup.
// Use a no-op unblock for a task-local cursor when endpoint close belongs to the
// enclosing admission; ending one direction must not close its active sibling.
func ObserveDecodedReader(reader buf.Reader, flow stats.Exchange, unblock func()) *buf.InspectionReader {
	buffered, ok := reader.(*buf.BufferedReader)
	if !ok {
		buffered = &buf.BufferedReader{Reader: reader}
	}
	return buf.NewInspectionReader(buffered, flow, unblock)
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
func BeginObservedEndpoint(ctx context.Context, store stats.AdmissionStore, conn io.Closer, dest net.Destination, kind stats.FlowKind) (context.Context, stats.Exchange, context.CancelFunc) {
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
	if kind == stats.FlowKindTCP {
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
func RecordPacketWrite(receipt stats.Exchange, payload uint64, encoded, written int, err error) {
	if receipt == nil {
		return
	}
	complete := encoded > 0 && written == encoded
	partial := encoded > 0 && written != 0 && !complete
	if err == nil && written != encoded {
		err = io.ErrShortWrite
	}
	RecordPacketOutcome(receipt, payload, complete, partial, err)
}

// RecordUnframedPacketWrite retains the actual payload prefix from a raw
// WriteTo. Unlike encoded frames, each returned byte is a logical payload byte.
// A short-nil is an error fact without changing the native caller's result.
func RecordUnframedPacketWrite(receipt stats.Exchange, offered, written int, err error) {
	if receipt == nil {
		return
	}
	if written < 0 || written > offered {
		receipt.MarkDownlinkIncomplete()
		receipt.SetEndReason(stats.EndReasonWriteError)
		return
	}
	receipt.AddDownlink(uint64(written))
	if err != nil || written != offered {
		receipt.SetEndReason(stats.EndReasonWriteError)
	}
}

// RecordPacketOutcome also accepts a native fragment group's combined result:
// one complete logical packet wins over any partial retry of that same packet.
func RecordPacketOutcome(receipt stats.Exchange, payload uint64, complete, partial bool, err error) {
	if receipt == nil {
		return
	}
	switch {
	case complete:
		receipt.AddDownlink(payload)
	case partial:
		receipt.MarkDownlinkIncomplete()
	}
	if err != nil {
		receipt.SetEndReason(stats.EndReasonWriteError)
	}
}

// ClaimObservedEndpoint binds an eligible endpoint to its actual consuming
// outbound. Protocol-specific eligibility and effective target remain with the
// caller.
func ClaimObservedEndpoint(ctx context.Context, reader buf.Reader, eligible bool) *session.LogicalObservation {
	if !eligible {
		return nil
	}
	if receipt := session.RouteOnlyReceiptFromContext(ctx); receipt != nil {
		receipt.Commit()
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
	observation.Exchange.BindRoute()
	return observation
}

// ClaimDecodedEndpoint transfers one supplied endpoint's pre-route raw receipt
// to a decoded message owner. The same flow keeps its selected handler and
// exact local stop; an ordinary raw claim or owner ending makes transfer fail.
func ClaimDecodedEndpoint(ctx context.Context, reader buf.Reader) stats.Exchange {
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
	deferred, ok := observation.Exchange.(*deferredEndpointReceipt)
	if !ok {
		return nil
	}
	return deferred.selectDecoded()
}
