package mux

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/pipe"
)

func (w *ServerWorker) initializeInspection(ctx context.Context) {
	if instance := core.FromContext(ctx); instance != nil {
		if manager, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager); ok {
			w.store = proxy.ObservationStore(manager)
		}
	}
}

func (w *ServerWorker) inspectChild(dest net.Destination) bool {
	if w.store == nil {
		return false
	}
	admission, ok := w.dispatcher.(interface{ InspectMuxChild(net.Destination) bool })
	return !ok || admission.InspectMuxChild(dest)
}

func (w *ServerWorker) observeChild(ctx context.Context, dest net.Destination, s *Session) context.Context {
	original := ctx
	ctx = session.ContextWithLogicalObservation(ctx, nil)
	ctx, cancel := context.WithCancel(ctx)
	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	stop := func() error { cancel(); return s.Close(false) }
	var flow stats.Exchange
	if dest.Network == net.Network_UDP {
		flow = w.store.Begin(net.Network_UDP, session.TrafficOriginFromContext(ctx), source, dest, stop)
	} else {
		flow = w.store.PrepareTCP(session.TrafficOriginFromContext(ctx), source, dest, stop)
	}
	if flow == nil {
		cancel()
		return original
	}
	s.parent.Lock()
	s.inspection = flow
	s.cleanup = func() { cancel(); flow.Finish() }
	s.parent.Unlock()
	observation := &session.LogicalObservation{Exchange: flow}
	observation.ReturnedLink.Store(true)
	return session.ContextWithLogicalObservation(ctx, observation)
}

func (s *Session) finishServer() {
	s.Close(false)
	s.parent.Lock()
	if s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
	cleanup := s.cleanup
	s.cleanup = nil
	s.parent.Unlock()
	if cleanup != nil {
		cleanup()
	}
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
	return mb, err
}

func (s *Session) copyInput(reader *buf.BufferedReader, target net.Destination) error {
	raw := s.NewReader(reader, &target)
	input, output := raw, s.output
	if s.server && s.XUDP != nil {
		output = s
	} else if s.inspection != nil {
		input = &childInput{Reader: raw, flow: s.inspection, target: target}
	}
	err := buf.Copy(input, output)
	if buf.IsWriteError(err) {
		s.Close(false)
		return buf.Copy(raw, buf.Discard)
	}
	return err
}

// ReadMultiBuffer is selected only for an observed retained session. The gate
// ends at native dequeue, before its response can block on the old carrier.
func (s *Session) ReadMultiBuffer() (buf.MultiBuffer, error) {
	s.ioGate.RLock()
	defer s.ioGate.RUnlock()
	if s.done.Done() {
		return nil, io.EOF
	}
	return s.input.ReadMultiBuffer()
}

func (s *Session) WriteMultiBuffer(mb buf.MultiBuffer) error {
	s.ioGate.RLock()
	defer s.ioGate.RUnlock()
	if s.done.Done() {
		buf.ReleaseMulti(mb)
		return io.EOF
	}
	writer := s.output.(interface {
		WriteMultiBufferStop(buf.MultiBuffer, <-chan struct{}) error
	})
	size := uint64(mb.Len())
	var target net.Destination
	if len(mb) == 1 && mb[0] != nil && mb[0].UDP != nil {
		target = *mb[0].UDP
	}
	if s.inspection != nil {
		s.inspection.PacketDestination(target)
	}
	err := writer.WriteMultiBufferStop(mb, s.done.Wait())
	if err == nil && s.inspection != nil {
		s.inspection.AddUplink(size)
	}
	return err
}

func retainedEndpointsSupported(s *Session) bool {
	_, reader := s.input.(*pipe.Reader)
	_, writer := s.output.(interface {
		WriteMultiBufferStop(buf.MultiBuffer, <-chan struct{}) error
	})
	return reader && writer
}

func closeRetainedEndpoints(s *Session) {
	common.Interrupt(s.input)
	common.Close(s.output)
}

// replyEnd owns only the canceled admission's native END. The parser can drain
// its current frame while that response waits for its own carrier.
func (s *Session) replyEnd(output buf.Writer) {
	s.Close(false)
	s.parent.Lock()
	if !s.parent.closed && s.parent.sessions[s.ID] == nil {
		s.parent.sessions[s.ID] = s
		s.parent.count++
	}
	canReply := !s.parent.closed && s.parent.sessions[s.ID] == s
	s.parent.Unlock()
	if canReply {
		go func() {
			NewResponseWriter(s.ID, output, s.transferType).Close()
			s.finishServer()
		}()
	} else {
		s.finishServer()
	}
}
