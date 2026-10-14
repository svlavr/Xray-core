package mux

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/stats"
)

// stop removes the exact retained identity, then closes its native endpoints.
// The map lock never covers pipe I/O, child close, or a statistics callback.
func (x *XUDP) stop() {
	XUDPManager.Lock()
	if XUDPManager.Map[x.GlobalID] == x {
		delete(XUDPManager.Map, x.GlobalID)
	}
	s, flow, cancel := x.Mux, x.inspection, x.cancel
	XUDPManager.Unlock()
	if cancel != nil {
		cancel()
	}
	if s != nil {
		s.Close(false)
		closeRetainedEndpoints(s)
	}
	if flow != nil {
		flow.Finish()
	}
}

func (w *ServerWorker) observeRetained(ctx context.Context, target *FrameMetadata, x *XUDP) context.Context {
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx, cancel := context.WithCancel(ctx)
	XUDPManager.Lock()
	x.cancel = cancel
	current := XUDPManager.Map[x.GlobalID] == x
	XUDPManager.Unlock()
	if !current {
		cancel()
		return ctx
	}
	var flow stats.Exchange
	if w.store != nil {
		var source net.Destination
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			source = inbound.Source
		}
		flow = w.store.Begin(net.Network_UDP, session.TrafficOriginFromContext(ctx), source, target.Target, func() error { x.stop(); return nil })
	}
	XUDPManager.Lock()
	x.inspection = flow
	current = XUDPManager.Map[x.GlobalID] == x
	XUDPManager.Unlock()
	if !current {
		cancel()
		if flow != nil {
			flow.Finish()
		}
	}
	if flow == nil {
		return ctx
	}
	observation := &session.LogicalObservation{Exchange: flow}
	observation.ReturnedLink.Store(true)
	return session.ContextWithLogicalObservation(ctx, observation)
}

// handleObservedXUDPLocked takes custody of an already decoded packet and
// the caller's map lock. It reserves preparation before releasing that lock.
func (w *ServerWorker) handleObservedXUDPLocked(ctx context.Context, meta *FrameMetadata, mb buf.MultiBuffer, x *XUDP) error {
	requestCtx := session.ContextWithLogicalObservation(ctx, nil)
	defer func() { buf.ReleaseMulti(mb) }()
	var err error
	if x != nil && x.Status == Initializing {
		XUDPManager.Unlock()
		return nil
	}
	var native *XUDP
	if x == nil || !x.selected {
		native = x
		x = &XUDP{GlobalID: meta.GlobalID, selected: true}
		XUDPManager.Map[meta.GlobalID] = x
	}
	x.Status = Initializing
	old, flow := x.Mux, x.inspection
	XUDPManager.Unlock()
	if native != nil {
		native.Mux.Close(false)
		native.Interrupt()
	}
	if flow != nil {
		var runtime stats.RuntimeID
		if w.store != nil {
			runtime = w.store.Runtime()
		}
		flow.Rebind(runtime, session.TrafficOriginFromContext(ctx))
	}
	if old != nil {
		old.Close(false)
	}
	defer func() {
		XUDPManager.Lock()
		if XUDPManager.Map[x.GlobalID] == x && x.Status == Initializing {
			if x.Mux == nil {
				delete(XUDPManager.Map, x.GlobalID)
			} else {
				x.Status, x.Expire = Expiring, time.Now().Add(time.Minute)
			}
		}
		XUDPManager.Unlock()
	}()
	for attempt := 0; attempt < 2; attempt++ {
		s := &Session{parent: w.sessionManager, ID: meta.SessionID, transferType: protocol.TransferTypePacket, XUDP: x, server: true, done: done.New()}
		if old == nil {
			ctx = w.observeRetained(requestCtx, meta, x)
			link, dispatchErr := w.dispatcher.Dispatch(session.ContextWithTimeoutOnly(ctx, true), meta.Target)
			if dispatchErr != nil {
				stopped := ctx.Err() != nil
				x.stop()
				if stopped {
					s.XUDP = nil
					s.replyEnd(w.carrierWriter())
					return nil
				}
				return errors.New("failed to dispatch XUDP request").Base(dispatchErr)
			}
			s.input, s.output = link.Reader, link.Writer
		} else {
			s.input, s.output = old.input, old.output
		}
		if !retainedEndpointsSupported(s) {
			closeRetainedEndpoints(s)
			x.stop()
			return errors.New("unsupported observed XUDP endpoints")
		}
		m := w.sessionManager
		m.Lock()
		XUDPManager.Lock()
		s.inspection = x.inspection
		published := !m.closed && m.sessions[s.ID] == nil && XUDPManager.Map[x.GlobalID] == x
		if published {
			x.Mux = s
			m.sessions[s.ID] = s
			m.count++
		}
		XUDPManager.Unlock()
		m.Unlock()
		if !published {
			closeRetainedEndpoints(s)
			x.stop()
			s.XUDP = nil
			s.replyEnd(w.carrierWriter())
			return nil
		}
		var saved buf.MultiBuffer
		if old != nil {
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			saved = buf.MultiBuffer{b}
		}
		payload := mb
		mb = nil
		err = s.WriteMultiBuffer(payload)
		if err == nil || s.done.Done() {
			buf.ReleaseMulti(saved)
			XUDPManager.Lock()
			if XUDPManager.Map[x.GlobalID] == x && !s.done.Done() {
				x.Status = Active
			}
			XUDPManager.Unlock()
			go handle(ctx, s, w.carrierWriter())
			return nil
		}
		s.finishServer()
		x.stop()
		if old == nil {
			return err
		}
		// Native failed-retained-write retry creates a new endpoint identity.
		XUDPManager.Lock()
		if XUDPManager.Map[meta.GlobalID] != nil {
			XUDPManager.Unlock()
			buf.ReleaseMulti(saved)
			s.replyEnd(w.carrierWriter())
			return nil
		}
		x = &XUDP{GlobalID: meta.GlobalID, selected: true}
		XUDPManager.Map[meta.GlobalID] = x
		XUDPManager.Unlock()
		old, mb = nil, saved
	}
	return io.ErrClosedPipe
}
