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
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type Server struct {
	dispatcher routing.Dispatcher
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
	})
	return s
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

	_, err := NewServerWorker(ctx, s.dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if err != nil {
		return nil, err
	}

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// DispatchLink implements routing.Dispatcher
func (s *Server) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.DispatchLink(ctx, dest, link)
	}
	worker, err := NewServerWorker(ctx, s.dispatcher, link)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-worker.done.Wait():
	}
	return nil
}

// Start implements common.Runnable.
func (s *Server) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	return nil
}

type ServerWorker struct {
	dispatcher     routing.Dispatcher
	link           *transport.Link
	sessionManager *SessionManager
	done           *done.Instance
	timer          *time.Ticker
	store          stats.AdmissionStore
	writeGate      sync.Mutex
}

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	worker := &ServerWorker{
		dispatcher:     d,
		link:           link,
		sessionManager: NewSessionManager(),
		done:           done.New(),
		timer:          time.NewTicker(60 * time.Second),
	}
	worker.initializeInspection(ctx)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.CanSpliceCopy = 3
	}
	go worker.run(ctx)
	go worker.monitor()
	return worker, nil
}

func handle(ctx context.Context, s *Session, output buf.Writer) {
	writer := NewResponseWriter(s.ID, output, s.transferType)
	writer.receipt = s.inspection
	input := s.input
	if s.server && s.XUDP != nil {
		input = s
	}
	if err := buf.Copy(input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "session ", s.ID, " ends.")
		writer.hasError = true
	}

	writer.Close()
	if s.server {
		s.finishServer()
	} else {
		s.Close(false)
	}
}

func (w *ServerWorker) monitor() {
	defer w.timer.Stop()

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
				common.Must(w.done.Close())
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
	return w.done.Close()
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	ctx = session.SubContextFromMuxInbound(ctx)
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
			if inbound.User != nil {
				msg.Email = inbound.User.Email
			}
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
		inspect := w.inspectChild(meta.Target)
		XUDPManager.Lock()
		x := XUDPManager.Map[meta.GlobalID]
		if inspect || (x != nil && x.selected) {
			return w.handleObservedXUDPLocked(ctx, meta, mb, x)
		}
		if x == nil {
			x = &XUDP{GlobalID: meta.GlobalID, Status: Initializing}
			XUDPManager.Map[meta.GlobalID] = x
			XUDPManager.Unlock()
		} else {
			if x.Status == Initializing { // another carrier owns preparation
				XUDPManager.Unlock()
				buf.ReleaseMulti(mb)
				errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
				// It's not a good idea to return an err here, so just let client wait.
				// Client will receive an End frame after sending a Keep frame.
				return nil
			}
			x.Status = Initializing
			XUDPManager.Unlock()
			x.Mux.Close(false) // detach from previous Mux
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			if err = x.Mux.output.WriteMultiBuffer(mb); err != nil {
				x.Interrupt()
				mb = buf.MultiBuffer{b}
			} else {
				b.Release()
				mb = nil
			}
			errors.LogInfoInner(ctx, err, "XUDP hit ", meta.GlobalID)
		}
		if mb != nil {
			ctx = session.ContextWithTimeoutOnly(ctx, true)
			// Actually, it won't return an error in Xray-core's implementations.
			link, err := w.dispatcher.Dispatch(ctx, meta.Target)
			if err != nil {
				XUDPManager.Lock()
				delete(XUDPManager.Map, x.GlobalID)
				XUDPManager.Unlock()
				err = errors.New("XUDP new ", meta.GlobalID).Base(errors.New("failed to dispatch request to ", meta.Target).Base(err))
				return err // it will break the whole Mux connection
			}
			link.Writer.WriteMultiBuffer(mb) // it's meaningless to test a new pipe
			x.Mux = &Session{
				input:  link.Reader,
				output: link.Writer,
			}
			errors.LogInfoInner(ctx, err, "XUDP new ", meta.GlobalID)
		}
		s := &Session{
			input:        x.Mux.input,
			output:       x.Mux.output,
			parent:       w.sessionManager,
			ID:           meta.SessionID,
			transferType: protocol.TransferTypePacket,
			XUDP:         x,
		}
		added := w.sessionManager.Add(s)
		if !added {
			s.Close(false)
		}
		// Initializing reserves the native endpoint until its real child is
		// admitted. Selected takeover cannot observe a half-published Mux.
		w.sessionManager.Lock()
		XUDPManager.Lock()
		x.Mux = s
		if s.closed {
			x.Status, x.Expire = Expiring, time.Now().Add(time.Minute)
		} else {
			x.Status = Active
		}
		XUDPManager.Unlock()
		w.sessionManager.Unlock()
		if !added {
			return errors.New("failed to add new session")
		}
		go handle(ctx, s, w.carrierWriter())
		return nil
	}

	s := &Session{parent: w.sessionManager, ID: meta.SessionID, transferType: protocol.TransferTypeStream}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	if w.inspectChild(meta.Target) {
		s.server = true
		ctx = w.observeChild(ctx, meta.Target, s)
		if !w.sessionManager.Add(s) {
			s.replyEnd(w.carrierWriter())
			if meta.Option.Has(OptionData) {
				return buf.Copy(NewStreamReader(reader), buf.Discard)
			}
			return nil
		}
	}
	link, err := w.dispatcher.Dispatch(ctx, meta.Target)
	if err != nil {
		if s.server {
			s.replyEnd(w.carrierWriter())
		}
		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		if s.server && ctx.Err() != nil {
			return nil
		}
		return errors.New("failed to dispatch request.").Base(err)
	}
	s.parent.Lock()
	s.input, s.output = link.Reader, link.Writer
	closed := s.closed
	s.parent.Unlock()
	if closed {
		common.Interrupt(link.Reader)
		common.Close(link.Writer)
	}
	if !s.server && !w.sessionManager.Add(s) {
		s.Close(false)
		return errors.New("failed to add new session")
	}
	go handle(ctx, s, w.carrierWriter())
	if !meta.Option.Has(OptionData) {
		return nil
	}
	return s.copyInput(reader, meta.Target)
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, retired := w.sessionManager.lookup(meta.SessionID)
	if s == nil {
		if retired {
			return buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.carrierWriter(), protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	return s.copyInput(reader, meta.Target)
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
		return errors.New("unknown status: ", status)
	}

	if err != nil {
		return errors.New("failed to process data").Base(err)
	}
	return nil
}

func (w *ServerWorker) run(ctx context.Context) {
	defer func() {
		common.Must(w.done.Close())
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

func (w *ServerWorker) carrierWriter() buf.Writer {
	if w.store != nil {
		return w
	}
	return w.link.Writer
}

func (w *ServerWorker) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if _, native := w.link.Writer.(*pipe.Writer); native {
		return w.link.Writer.WriteMultiBuffer(mb)
	}
	w.writeGate.Lock()
	defer w.writeGate.Unlock()
	return w.link.Writer.WriteMultiBuffer(mb)
}
