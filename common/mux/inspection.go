package mux

import (
	"bytes"
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

type childCloser struct{ session *Session }

func (c childCloser) Close() error { return c.session.Close(false) }

// A stop during preparation still has a native child END owner. The admission
// keeps its base lifetime until both the initial frame drain and END return.
func (s *Session) cancelAdmission(ctx context.Context, output buf.Writer) {
	s.Close(false)
	s.parent.Lock()
	canReply := !s.parent.closed && (s.parent.sessions[s.ID] == nil || s.parent.sessions[s.ID] == s)
	if canReply {
		if s.parent.sessions[s.ID] == nil {
			s.parent.sessions[s.ID] = s
			s.parent.count++
			s.parent.markSeenLocked(s.ID)
		}
		s.input = buf.NewReader(bytes.NewReader(nil))
		s.output = buf.Discard
	}
	s.parent.Unlock()
	if canReply {
		go handle(ctx, s, output)
	} else {
		s.finishServer()
	}
}

func (w *ServerWorker) initializeInspection(ctx context.Context) {
	instance := core.FromContext(ctx)
	if instance == nil {
		return
	}
	manager, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return
	}
	w.stats = manager
	w.store = proxy.ObservationStore(manager)
	if w.store == nil {
		return
	}
	w.runtime = w.store.Info().Runtime
	w.link.Writer = newInspectionOutput(w.link.Writer)
}

func (w *ServerWorker) observeChild(ctx context.Context, dest net.Destination, s *Session) (context.Context, func()) {
	if w.store == nil {
		return ctx, nil
	}
	if admission, ok := w.dispatcher.(interface{ InspectMuxChild(net.Destination) bool }); ok && !admission.InspectMuxChild(dest) {
		return ctx, nil
	}
	kind := stats.FlowKindTCP
	if dest.Network == net.Network_UDP {
		kind = stats.FlowKindUDPAssociation
	}
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx, observation, cleanup := proxy.BeginReturnedObservation(ctx, w.stats, childCloser{s}, dest, kind)
	if observation != nil {
		s.parent.Lock()
		s.inspection = observation.Exchange
		s.parent.Unlock()
	}
	return ctx, cleanup
}

func (w *ServerWorker) observeRetained(ctx context.Context, dest net.Destination, x *XUDP) (context.Context, error) {
	if w.store == nil {
		return ctx, nil
	}
	original := ctx
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx, cancel := context.WithCancel(ctx)
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	flow := w.store.Begin(stats.FlowKindUDPAssociation, session.TrafficOriginFromContext(ctx), source, dest, func() error { x.Interrupt(); return nil })
	if flow == nil {
		cancel()
		return original, nil
	}
	XUDPManager.Lock()
	current := XUDPManager.Map[x.GlobalID] == x
	x.inspection, x.cancel = flow, cancel
	XUDPManager.Unlock()
	if !current {
		cancel()
		return ctx, io.ErrClosedPipe
	}
	observation := &session.LogicalObservation{Exchange: flow}
	observation.ReturnedLink.Store(true)
	return session.ContextWithLogicalObservation(ctx, observation), nil
}

// The optional router serializes each native carrier frame operation while
// retaining child-local decoded accounting.
type inspectionOutput struct {
	sync.Mutex
	writer buf.Writer
}

func newInspectionOutput(writer buf.Writer) *inspectionOutput {
	return &inspectionOutput{writer: writer}
}

func (o *inspectionOutput) WriteMultiBuffer(mb buf.MultiBuffer) error {
	o.Lock()
	defer o.Unlock()
	return o.writer.WriteMultiBuffer(mb)
}

func (o *inspectionOutput) Close() error {
	// Serialize a buffered carrier flush with normal frame writes.
	if _, buffered := o.writer.(*buf.BufferedWriter); buffered {
		o.Lock()
		defer o.Unlock()
	}
	return common.Close(o.writer)
}

func (o *inspectionOutput) Interrupt() {
	if _, buffered := o.writer.(*buf.BufferedWriter); buffered {
		o.Close()
		return
	}
	// Pipe interruption must remain able to unblock a capacity-waiting frame.
	common.Interrupt(o.writer)
}

func (o *inspectionOutput) writeFrame(mb buf.MultiBuffer, payload int32, flow stats.Exchange) error {
	o.Lock()
	defer o.Unlock()
	accepted := true
	var err error
	if writer, ok := o.writer.(interface {
		WriteMultiBufferResult(buf.MultiBuffer) (bool, error)
	}); ok {
		accepted, err = writer.WriteMultiBufferResult(mb)
	} else {
		err = o.writer.WriteMultiBuffer(mb)
	}
	if err == nil {
		if accepted {
			if payload > 0 {
				flow.AddDownlink(uint64(payload))
			}
		}
	} else {
		if accepted {
			flow.MarkDownlinkIncomplete()
		}
		flow.SetEndReason(stats.EndReasonWriteError)
	}
	return err
}

type childInput struct {
	buf.Reader
	flow   stats.Exchange
	target net.Destination
}

func (r *childInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	for _, b := range mb {
		if b != nil && r.target.Network == net.Network_UDP {
			target := r.target
			if b.UDP != nil {
				target = *b.UDP
			}
			r.flow.PacketDestination(target)
		}
	}
	r.flow.AddUplink(uint64(mb.Len()))
	if err != nil && err != io.EOF {
		r.flow.SetEndReason(stats.EndReasonReadError)
	}
	return mb, err
}

func (s *Session) copyInput(reader *buf.BufferedReader, target net.Destination) error {
	rr := s.NewReader(reader, &target)
	raw := rr
	if s.inspection != nil {
		if s.xudp == nil {
			rr = &childInput{Reader: rr, flow: s.inspection, target: target}
		}
	}
	err := buf.Copy(rr, s.output)
	if err != nil && buf.IsWriteError(err) {
		s.Close(false)
		return buf.Copy(raw, buf.Discard)
	}
	return err
}
