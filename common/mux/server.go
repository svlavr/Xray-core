package mux

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type Server struct {
	dispatcher routing.Dispatcher
	mu         sync.Mutex
	workers    map[*ServerWorker]struct{}
	reapers    task.Lifecycle
	sealed     bool
	closeOnce  sync.Once
	closeDone  chan struct{}
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{
		workers:   make(map[*ServerWorker]struct{}),
		closeDone: make(chan struct{}),
	}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
	})
	return s
}

func (s *Server) newWorker(ctx context.Context, link *transport.Link) (*ServerWorker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return nil, errors.New("mux server is closed")
	}
	worker, err := NewServerWorker(ctx, s.dispatcher, link)
	if err != nil {
		return nil, err
	}
	if !s.reapers.Acquire() {
		_ = worker.CloseAndWait()
		return nil, errors.New("mux server is closed")
	}
	s.workers[worker] = struct{}{}
	go func() {
		defer s.reapers.Release()
		<-worker.WaitClosed()
		_ = worker.CloseAndWait()
		s.mu.Lock()
		delete(s.workers, worker)
		s.mu.Unlock()
	}()
	return worker, nil
}

// Type implements common.HasType.
func (s *Server) Type() interface{} {
	return s.dispatcher.Type()
}

// Dispatch implements routing.Dispatcher
func (s *Server) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.Dispatch(ctx, dest)
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	_, err := s.newWorker(ctx, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if err != nil {
		common.Interrupt(uplinkReader)
		common.Interrupt(uplinkWriter)
		common.Interrupt(downlinkReader)
		common.Interrupt(downlinkWriter)
		return nil, err
	}

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// DispatchLink implements routing.Dispatcher
func (s *Server) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.DispatchLink(ctx, dest, link)
	}
	worker, err := s.newWorker(ctx, link)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-worker.done.Wait():
	}
	return worker.CloseAndWait()
}

// Start implements common.Runnable.
func (s *Server) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.sealed = true
		s.reapers.Seal()
		workers := make([]*ServerWorker, 0, len(s.workers))
		for worker := range s.workers {
			workers = append(workers, worker)
		}
		s.mu.Unlock()

		for _, worker := range workers {
			_ = worker.Close()
		}
		for _, worker := range workers {
			_ = worker.CloseAndWait()
		}
		s.reapers.Wait()
		close(s.closeDone)
	})
	<-s.closeDone
	return nil
}

type ServerWorker struct {
	dispatcher     routing.Dispatcher
	link           *transport.Link
	sessionManager *SessionManager
	done           *done.Instance
	timer          *time.Ticker
	flowCarrier    session.MuxCarrierObservation
	carrierFrame   session.MuxCarrierFrameObservation
	ctx            context.Context
	cancel         context.CancelFunc
	tasks          task.Lifecycle
	stopOnce       sync.Once
}

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	workerCtx, cancel := context.WithCancel(ctx)
	worker := &ServerWorker{
		dispatcher:     d,
		link:           link,
		sessionManager: NewSessionManager(),
		done:           done.New(),
		timer:          time.NewTicker(60 * time.Second),
		flowCarrier:    session.MuxCarrierObservationFromDispatcher(d),
		ctx:            workerCtx,
		cancel:         cancel,
	}
	worker.carrierFrame = session.MuxCarrierFrameObservationFromCarrier(worker.flowCarrier)
	if worker.carrierFrame != nil {
		worker.link = &transport.Link{Reader: observedServerCarrierReader{Reader: link.Reader, observation: worker.carrierFrame}, Writer: observedServerCarrierWriter{Writer: link.Writer, observation: worker.carrierFrame}}
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.CanSpliceCopy = 3
	}
	worker.tasks.Acquire()
	worker.tasks.Acquire()
	go func() {
		defer worker.tasks.Release()
		worker.run(workerCtx)
	}()
	go func() {
		defer worker.tasks.Release()
		worker.monitor()
	}()
	return worker, nil
}

func handle(ctx context.Context, s *Session, output buf.Writer, participant task.ParticipantLease) {
	if participant != nil {
		defer participant.Release(nil)
	}
	writer := NewResponseWriter(s.ID, output, s.transferType)
	if err := buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "session ", s.ID, " ends.")
		writer.hasError = true
	}
	// XUDP rebinding may reuse the retained downstream reader only after this
	// binding has definitely stopped reading it. This receipt intentionally
	// precedes the carrier response write and this session's own Close.
	s.inputComplete()

	writer.Close()
	s.Close(false)
}

func (w *ServerWorker) monitor() {
	defer w.timer.Stop()
	defer func() {
		if w.carrierFrame != nil {
			w.carrierFrame.DownlinkSealed()
			w.carrierFrame.MonitorCompleted()
		}
	}()

	for {
		checkSize := w.sessionManager.Size()
		checkCount := w.sessionManager.Count()
		select {
		case <-w.done.Wait():
			w.sessionManager.Close()
			common.Interrupt(w.link.Writer)
			common.Interrupt(w.link.Reader)
			return
		case <-w.timer.C:
			if w.sessionManager.CloseIfNoSessionAndIdle(checkSize, checkCount) {
				_ = w.done.Close()
			}
		}
	}
}

func (w *ServerWorker) ActiveConnections() uint32 {
	return uint32(w.sessionManager.Size())
}

func (w *ServerWorker) Closed() bool {
	return w.done.Done()
}

func (w *ServerWorker) WaitClosed() <-chan struct{} {
	return w.done.Wait()
}

func (w *ServerWorker) Close() error {
	w.stopOnce.Do(func() {
		w.tasks.Seal()
		w.cancel()
		_ = w.done.Close()
		_ = w.sessionManager.Close()
		common.Interrupt(w.link.Writer)
		common.Interrupt(w.link.Reader)
	})
	return nil
}

func (w *ServerWorker) CloseAndWait() error {
	if w == nil {
		return nil
	}
	_ = w.Close()
	w.tasks.Wait()
	return nil
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !w.tasks.Acquire() {
		return errors.New("mux server worker is closed")
	}
	transferred := false
	defer func() {
		if !transferred {
			w.tasks.Release()
		}
	}()
	ctx = session.SubContextFromMuxInbound(ctx)
	ctx = session.ContextWithMultiplexedLogicalSession(ctx)
	if meta.Inbound != nil && meta.Inbound.Source.IsValid() && meta.Inbound.Local.IsValid() {
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			newInbound := *inbound
			newInbound.Source = meta.Inbound.Source
			newInbound.Local = meta.Inbound.Local
			ctx = session.ContextWithInbound(ctx, &newInbound)
		}
	}
	errors.LogInfo(ctx, "received request for ", meta.Target)
	{
		msg := &log.AccessMessage{
			To:     meta.Target,
			Status: log.AccessAccepted,
			Reason: "",
		}
		if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
			msg.From = inbound.Source
			msg.Email = inbound.User.Email
		}
		ctx = log.ContextWithAccessMessage(ctx, msg)
	}

	if network := session.AllowedNetworkFromContext(ctx); network != net.Network_Unknown {
		if meta.Target.Network != network {
			return errors.New("unexpected network ", meta.Target.Network) // it will break the whole Mux connection
		}
	}

	if meta.GlobalID != [8]byte{} { // MUST ignore empty Global ID
		mb, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
		if err != nil {
			return err
		}
		XUDPManager.Lock()
		x := XUDPManager.Map[meta.GlobalID]
		var old *Session
		var expected *Session
		if x == nil {
			observation := session.MuxXUDPObservationFromCarrier(w.flowCarrier, meta.Target, muxObservationSource(meta))
			if observation == nil {
				observation = session.MuxXUDPObservationFromDispatcher(w.dispatcher, meta.Target, muxObservationSource(meta))
			}
			x = &XUDP{GlobalID: meta.GlobalID, observation: observation}
			XUDPManager.Map[meta.GlobalID] = x
			XUDPManager.Unlock()
		} else {
			if x.Status == Initializing { // nearly impossible
				XUDPManager.Unlock()
				errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
				// It's not a good idea to return an err here, so just let client wait.
				// Client will receive an End frame after sending a Keep frame.
				return nil
			}
			old = x.Mux
			expected = old
			if old != nil {
				old.xudpRebinding = true
			}
			x.Status = Initializing
			XUDPManager.Unlock()
			var retiredObservation session.XUDPEpochObservation
			var removedObservation session.XUDPEpochObservation
			// Detach the previous binding before the retained reader is made
			// authoritative for this carrier. Close is a receipt fence here.
			if err = old.close(ctx, false); err != nil {
				common.Interrupt(old.input)
				common.Close(old.output)
				XUDPManager.Lock()
				if XUDPManager.Map[x.GlobalID] == x && x.Status == Initializing && x.Mux == expected {
					if err == errXUDPReaderUnsupported {
						// Replace exact old authority while holding the manager lock:
						// no delete/recreate window may admit a stale callback.
						retiredObservation = x.observation
						if old != nil && old.xudpBinding != nil {
							old.xudpBinding.RevokeUnproven()
						}
						observation := session.MuxXUDPObservationFromCarrier(w.flowCarrier, meta.Target, muxObservationSource(meta))
						if observation == nil {
							observation = session.MuxXUDPObservationFromDispatcher(w.dispatcher, meta.Target, muxObservationSource(meta))
						}
						x = &XUDP{GlobalID: meta.GlobalID, observation: observation}
						XUDPManager.Map[meta.GlobalID] = x
						old = nil
						expected = nil
						err = nil
					} else {
						removedObservation = x.observation
						if old != nil && old.xudpBinding != nil {
							old.xudpBinding.RevokeUnproven()
						}
						delete(XUDPManager.Map, x.GlobalID)
					}
				}
				XUDPManager.Unlock()
				if retiredObservation != nil {
					// old.close above completed local retained endpoint actions and
					// the exact old authority was replaced under the manager lock.
					retiredObservation.Terminalize()
				}
				if removedObservation != nil {
					removedObservation.Terminalize()
				}
				if err != nil {
					buf.ReleaseMulti(mb)
					return errors.New("XUDP rebind stopped before old reader quiesced").Base(err)
				}
			}
			if old == nil {
				// The old retained reader was unsupported, so this request must
				// create a fresh downstream link instead of aliasing it.
			} else {
				b := buf.New()
				b.Write(mb[0].Bytes())
				b.UDP = mb[0].UDP
				if err = old.output.WriteMultiBuffer(mb); err != nil {
					oldObservation := x.observation
					observation := session.MuxXUDPObservationFromCarrier(w.flowCarrier, meta.Target, muxObservationSource(meta))
					if observation == nil {
						observation = session.MuxXUDPObservationFromDispatcher(w.dispatcher, meta.Target, muxObservationSource(meta))
					}
					XUDPManager.Lock()
					if XUDPManager.Map[x.GlobalID] != x || x.Status != Initializing || x.Mux != expected {
						XUDPManager.Unlock()
						b.Release()
						return errors.New("XUDP retained writer replacement lost exact authority")
					}
					// A fresh reservation makes the old epoch incapable of publishing
					// another binding before its local close/terminal receipt.
					x = &XUDP{GlobalID: meta.GlobalID, observation: observation}
					XUDPManager.Map[meta.GlobalID] = x
					expected = nil
					XUDPManager.Unlock()
					common.Interrupt(old.input)
					common.Close(old.output)
					if oldObservation != nil {
						oldObservation.WriteReplaced()
						oldObservation.Terminalize()
					}
					mb = buf.MultiBuffer{b}
				} else {
					b.Release()
					mb = nil
				}
				errors.LogInfoInner(ctx, err, "XUDP hit ", meta.GlobalID)
			}
		}
		if mb != nil {
			ctx = session.ContextWithTimeoutOnly(ctx, true)
			if x.observation != nil {
				ctx = x.observation.Context(ctx)
			}
			// Actually, it won't return an error in Xray-core's implementations.
			link, err := w.dispatcher.Dispatch(ctx, meta.Target)
			if err != nil {
				XUDPManager.Lock()
				if XUDPManager.Map[x.GlobalID] == x && x.Status == Initializing && x.Mux == expected {
					delete(XUDPManager.Map, x.GlobalID)
				}
				XUDPManager.Unlock()
				err = errors.New("XUDP new ", meta.GlobalID).Base(errors.New("failed to dispatch request to ", meta.Target).Base(err))
				return err // it will break the whole Mux connection
			}
			if writeErr := link.Writer.WriteMultiBuffer(mb); writeErr != nil && x.observation != nil {
				x.observation.InitialWriteUnproven()
			}
			old = &Session{input: link.Reader, output: link.Writer}
			errors.LogInfoInner(ctx, err, "XUDP new ", meta.GlobalID)
		}
		if old == nil {
			return errors.New("XUDP has no retained link")
		}
		s := &Session{
			input:        old.input,
			output:       old.output,
			parent:       w.sessionManager,
			ID:           meta.SessionID,
			transferType: protocol.TransferTypePacket,
			XUDP:         x,
			inputDone:    make(chan struct{}),
		}
		if x.observation != nil {
			s.xudpBinding = x.observation.PrepareBinding(session.MuxXUDPCarrierObservation(w.flowCarrier))
		}
		if !w.sessionManager.addAndPublishXUDP(s, x, expected) {
			// No reader was started, so this path must not wait for inputDone.
			removed := false
			XUDPManager.Lock()
			if XUDPManager.Map[x.GlobalID] == x && x.Status == Initializing && x.Mux == expected {
				delete(XUDPManager.Map, x.GlobalID)
				removed = true
			}
			XUDPManager.Unlock()
			common.Interrupt(s.input)
			common.Close(s.output)
			if removed && x.observation != nil {
				x.observation.Terminalize()
			}
			return errors.New("failed to add new session")
		}
		if w.carrierFrame != nil {
			w.carrierFrame.Reserve()
		}
		transferred = true
		go func() {
			defer w.tasks.Release()
			defer func() {
				if w.carrierFrame != nil {
					w.carrierFrame.Release()
				}
			}()
			handle(ctx, s, w.link.Writer, nil)
		}()
		return nil
	}

	var flowScope session.MuxSessionObservation
	if w.flowCarrier != nil {
		source := muxObservationSource(meta)
		switch meta.Target.Network {
		case net.Network_TCP:
			flowScope = w.flowCarrier.NewTCPSession(meta.GlobalID, meta.Target, source)
		case net.Network_UDP:
			flowScope = session.MuxUDPSessionObservationFromCarrier(w.flowCarrier, meta.GlobalID, meta.Target, source)
		}
		if flowScope != nil {
			ctx = flowScope.Context(ctx)
		}
	}
	link, err := w.dispatcher.Dispatch(ctx, meta.Target)
	if err != nil {
		if flowScope != nil {
			flowScope.AfterClose()
		}
		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		return errors.New("failed to dispatch request.").Base(err)
	}
	s := &Session{
		input:        link.Reader,
		output:       link.Writer,
		parent:       w.sessionManager,
		ID:           meta.SessionID,
		transferType: protocol.TransferTypeStream,
		flowScope:    flowScope,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	if !w.sessionManager.Add(s) {
		s.Close(false)
		return errors.New("failed to add new session")
	}
	var participant task.ParticipantLease
	if flowScope != nil {
		participant = flowScope.AcquireParticipant()
	}
	if w.carrierFrame != nil {
		w.carrierFrame.Reserve()
	}
	transferred = true
	go func() {
		defer w.tasks.Release()
		defer func() {
			if w.carrierFrame != nil {
				w.carrierFrame.Release()
			}
		}()
		handle(ctx, s, w.link.Writer, participant)
	}()
	if !meta.Option.Has(OptionData) {
		return nil
	}

	rr := s.NewReader(reader, &meta.Target)
	err = buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}
	return err
}

func muxObservationSource(meta *FrameMetadata) string {
	if meta == nil || meta.Inbound == nil || !meta.Inbound.Source.IsValid() {
		return ""
	}
	return meta.Inbound.Source.String()
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := w.sessionManager.Get(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader, &meta.Target)
	err := buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream writer. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

func (w *ServerWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := w.sessionManager.Get(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleFrame(ctx context.Context, reader *buf.BufferedReader) error {
	var meta FrameMetadata
	err := meta.Unmarshal(reader, session.IsReverseMuxFromContext(ctx))
	if err != nil {
		return errors.New("failed to read metadata").Base(err)
	}

	switch meta.SessionStatus {
	case SessionStatusKeepAlive:
		err = w.handleStatusKeepAlive(&meta, reader)
	case SessionStatusEnd:
		err = w.handleStatusEnd(&meta, reader)
	case SessionStatusNew:
		err = w.handleStatusNew(session.ContextWithIsReverseMux(ctx, false), &meta, reader)
	case SessionStatusKeep:
		err = w.handleStatusKeep(&meta, reader)
	default:
		status := meta.SessionStatus
		return errors.New("unknown status: ", status).AtError()
	}

	if err != nil {
		return errors.New("failed to process data").Base(err)
	}
	return nil
}

func (w *ServerWorker) run(ctx context.Context) {
	defer func() {
		if w.carrierFrame != nil {
			w.carrierFrame.UplinkSealed()
			w.carrierFrame.ReaderExited()
		}
		if w.flowCarrier != nil {
			w.flowCarrier.Close()
		}
		_ = w.done.Close()
	}()

	reader := &buf.BufferedReader{Reader: w.link.Reader}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := w.handleFrame(ctx, reader)
			if err != nil {
				if errors.Cause(err) != io.EOF {
					errors.LogInfoInner(ctx, err, "unexpected EOF")
				}
				return
			}
		}
	}
}
