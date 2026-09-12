package mux

import (
	"context"
	goerrors "errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type ClientManager struct {
	Enabled bool // whether mux is enabled from user config
	Picker  WorkerPicker
}

func (m *ClientManager) BindMuxClientCarrierAuthority(provider session.MuxClientCarrierAuthorityProvider) bool {
	picker, ok := m.Picker.(*IncrementalWorkerPicker)
	if !ok || picker == nil {
		return false
	}
	return picker.BindMuxClientCarrierAuthority(provider)
}

func (m *ClientManager) Close() error {
	if m == nil {
		return nil
	}
	if picker, ok := m.Picker.(*IncrementalWorkerPicker); ok && picker != nil {
		picker.Close()
	}
	return nil
}

func (m *ClientManager) SignalStop() {
	if m == nil {
		return
	}
	if picker, ok := m.Picker.(*IncrementalWorkerPicker); ok && picker != nil {
		picker.SignalStop()
	}
}

func (m *ClientManager) Retire() {
	if m == nil {
		return
	}
	if picker, ok := m.Picker.(*IncrementalWorkerPicker); ok && picker != nil {
		picker.Retire()
	}
}

func (m *ClientManager) Stop() {
	m.SignalStop()
}

func (m *ClientManager) Wait() {
	if m == nil {
		return
	}
	if picker, ok := m.Picker.(*IncrementalWorkerPicker); ok && picker != nil {
		picker.Wait()
	}
}

func (m *ClientManager) Dispatch(ctx context.Context, link *transport.Link) error {
	for i := 0; i < 16; i++ {
		var worker *ClientWorker
		var err error
		if picker, ok := m.Picker.(*IncrementalWorkerPicker); ok {
			worker, err = picker.PickAvailableContext(ctx)
		} else {
			worker, err = m.Picker.PickAvailable()
		}
		if err != nil {
			return err
		}
		if worker.Dispatch(ctx, link) {
			return nil
		}
	}

	return errors.New("unable to find an available mux client").AtWarning()
}

type WorkerPicker interface {
	PickAvailable() (*ClientWorker, error)
}

type IncrementalWorkerPicker struct {
	Factory ClientWorkerFactory

	access      sync.Mutex
	workers     []*ClientWorker
	cleanupTask *task.Periodic
	authority   session.MuxClientCarrierAuthorityProvider
	sealed      bool
	retiring    bool
	creating    *pickerCreation
	stopOnce    sync.Once
	waitOnce    sync.Once
	stopDone    chan struct{}
	retired     []*ClientWorker
}

type pickerCreation struct{ done chan struct{} }

func (p *IncrementalWorkerPicker) cleanupFunc() error {
	p.access.Lock()
	if len(p.workers) == 0 && len(p.retired) == 0 {
		p.access.Unlock()
		return errors.New("no worker")
	}
	p.cleanup()
	kept := p.retired[:0]
	var quiesced []*ClientWorker
	for _, worker := range p.retired {
		if !worker.Quiesced() {
			kept = append(kept, worker)
		} else {
			quiesced = append(quiesced, worker)
		}
	}
	p.retired = kept
	p.access.Unlock()
	for _, worker := range quiesced {
		worker.Wait()
	}
	return nil
}

func (p *IncrementalWorkerPicker) cleanup() {
	var activeWorkers []*ClientWorker
	for _, w := range p.workers {
		if !w.Closed() {
			activeWorkers = append(activeWorkers, w)
		} else {
			p.retired = append(p.retired, w)
		}
	}
	p.workers = activeWorkers
}

func (p *IncrementalWorkerPicker) findAvailable() int {
	for idx, w := range p.workers {
		if !w.IsFull() {
			return idx
		}
	}

	return -1
}

func (p *IncrementalWorkerPicker) pickInternal(ctx context.Context, admitted bool) (*ClientWorker, bool, error) {
	p.access.Lock()
	if p.sealed || (p.retiring && !admitted) {
		p.access.Unlock()
		return nil, false, errors.New("mux client picker is not admitting new invocations")
	}
	admitted = true

	idx := p.findAvailable()
	if idx >= 0 {
		n := len(p.workers)
		if n > 1 && idx != n-1 {
			p.workers[n-1], p.workers[idx] = p.workers[idx], p.workers[n-1]
		}
		worker := p.workers[idx]
		p.access.Unlock()
		return worker, false, nil
	}

	p.cleanup()
	if p.creating != nil {
		creation := p.creating
		p.access.Unlock()
		<-creation.done
		return p.pickInternal(ctx, admitted)
	}

	// Factory.Create can dial or publish goroutines; it must never run while
	// picker state is locked. The creation claim lets Close win safely.
	creation := &pickerCreation{done: make(chan struct{})}
	p.creating = creation
	provider := p.authority
	p.access.Unlock()
	var generationRight *core.RetirementRight
	if sourceRight := core.RetirementRightFromContext(ctx); sourceRight != nil {
		var ok bool
		generationRight, ok = sourceRight.AcquireContinuation()
		if !ok {
			p.access.Lock()
			p.creating = nil
			close(creation.done)
			p.access.Unlock()
			return nil, false, errors.New("mux worker generation continuation rejected")
		}
	}
	var worker *ClientWorker
	var err error
	if factory, ok := p.Factory.(interface {
		CreateWithMuxClientCarrierAuthorityAndGeneration(session.MuxClientCarrierAuthorityProvider, *core.RetirementRight) (*ClientWorker, error)
	}); ok {
		worker, err = factory.CreateWithMuxClientCarrierAuthorityAndGeneration(provider, generationRight)
	} else if generationRight != nil {
		generationRight.Release()
		err = errors.New("mux worker factory cannot retain generation ownership")
	} else if factory, ok := p.Factory.(interface {
		CreateWithMuxClientCarrierAuthority(session.MuxClientCarrierAuthorityProvider) (*ClientWorker, error)
	}); ok {
		worker, err = factory.CreateWithMuxClientCarrierAuthority(provider)
	} else {
		worker, err = p.Factory.Create()
	}
	p.access.Lock()
	if err != nil {
		p.creating = nil
		close(creation.done)
		p.access.Unlock()
		return nil, false, err
	}
	if p.sealed {
		p.retired = append(p.retired, worker)
		p.creating = nil
		p.access.Unlock()
		common.Close(worker)
		close(creation.done)
		return nil, false, errors.New("mux client picker closed during creation")
	}
	p.workers = append(p.workers, worker)

	if p.cleanupTask == nil {
		p.cleanupTask = &task.Periodic{
			Interval: time.Second * 30,
			Execute:  p.cleanupFunc,
		}
	}
	p.access.Unlock()
	// Start is part of the creation receipt but must not execute cleanup while
	// picker access is held.
	common.Must(p.cleanupTask.Start())
	p.access.Lock()
	p.creating = nil
	close(creation.done)
	p.access.Unlock()
	return worker, true, nil
}

func (p *IncrementalWorkerPicker) PickAvailable() (*ClientWorker, error) {
	worker, _, err := p.pickInternal(context.Background(), false)
	return worker, err
}

func (p *IncrementalWorkerPicker) PickAvailableContext(ctx context.Context) (*ClientWorker, error) {
	// A live exact-generation right proves this invocation crossed the Handler
	// gate before retirement and may complete its already-admitted selection.
	admitted := core.RetirementRightFromContext(ctx) != nil
	worker, _, err := p.pickInternal(ctx, admitted)
	return worker, err
}

func (p *IncrementalWorkerPicker) BindMuxClientCarrierAuthority(provider session.MuxClientCarrierAuthorityProvider) bool {
	p.access.Lock()
	defer p.access.Unlock()
	if p.sealed || p.authority != nil || provider == nil || len(p.workers) != 0 || p.creating != nil {
		return false
	}
	p.authority = provider
	return true
}

func (p *IncrementalWorkerPicker) Retire() {
	p.access.Lock()
	if !p.sealed {
		p.retiring = true
	}
	p.access.Unlock()
}

// SignalStop seals publication and closes every already-published worker. It
// never waits for an in-flight constructor, cleanup callback, or worker.
func (p *IncrementalWorkerPicker) SignalStop() {
	p.stopOnce.Do(func() {
		p.access.Lock()
		p.sealed = true
		p.retiring = true
		p.stopDone = make(chan struct{})
		p.cleanup()
		workers := append([]*ClientWorker(nil), p.workers...)
		workers = append(workers, p.retired...)
		cleanup := p.cleanupTask
		p.access.Unlock()
		if cleanup != nil {
			common.Must(cleanup.Close())
		}
		for _, worker := range workers {
			common.Close(worker)
		}
	})
}

func (p *IncrementalWorkerPicker) Stop() {
	p.SignalStop()
}

func (p *IncrementalWorkerPicker) Wait() {
	p.SignalStop()
	p.waitOnce.Do(func() {
		p.access.Lock()
		creation := p.creating
		p.access.Unlock()
		if creation != nil {
			<-creation.done
		}
		p.access.Lock()
		p.cleanup()
		workers := append([]*ClientWorker(nil), p.workers...)
		workers = append(workers, p.retired...)
		cleanup := p.cleanupTask
		p.access.Unlock()
		for _, worker := range workers {
			common.Close(worker)
		}
		if cleanup != nil {
			common.Must(cleanup.CloseAndWait())
		}
		for _, worker := range workers {
			worker.Wait()
		}
		p.access.Lock()
		p.workers = nil
		p.retired = nil
		close(p.stopDone)
		p.access.Unlock()
	})
	<-p.stopDone
}

func (p *IncrementalWorkerPicker) Close() {
	p.Stop()
	p.Wait()
}

type ClientWorkerFactory interface {
	Create() (*ClientWorker, error)
}

type DialingWorkerFactory struct {
	Proxy    proxy.Outbound
	Dialer   internet.Dialer
	Strategy ClientStrategy
	Context  context.Context
}

func (f *DialingWorkerFactory) Create() (*ClientWorker, error) {
	return f.CreateWithMuxClientCarrierAuthorityAndGeneration(nil, nil)
}

func (f *DialingWorkerFactory) CreateWithMuxClientCarrierAuthority(authority session.MuxClientCarrierAuthorityProvider) (*ClientWorker, error) {
	return f.CreateWithMuxClientCarrierAuthorityAndGeneration(authority, nil)
}

func (f *DialingWorkerFactory) CreateWithMuxClientCarrierAuthorityAndGeneration(authority session.MuxClientCarrierAuthorityProvider, generationRight *core.RetirementRight) (*ClientWorker, error) {
	opts := []pipe.Option{pipe.WithSizeLimit(64 * 1024)}
	uplinkReader, upLinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	var carrier session.MuxClientCarrierObservation
	if authority != nil {
		carrier = authority.NewMuxClientCarrierObservation()
	}
	c, err := newClientWorkerPrepared(transport.Link{
		Reader: downlinkReader,
		Writer: upLinkWriter,
	}, f.Strategy, carrier, generationRight)
	if err != nil {
		if generationRight != nil {
			generationRight.Release()
		}
		return nil, err
	}
	if authority != nil {
		c.recordEarlyFlowCarrierAttempt()
	}

	baseCtx := f.Context
	if baseCtx == nil {
		baseCtx = context.Background()
	} else {
		baseCtx = context.WithoutCancel(baseCtx)
	}
	baseCtx = session.ContextWithOutbounds(baseCtx, []*session.Outbound{{Target: net.TCPDestination(muxCoolAddress, muxCoolPort)}})
	if generationRight != nil {
		baseCtx = core.ContextWithRetirementRight(baseCtx, generationRight)
	}
	ctx, cancel := context.WithCancel(baseCtx)
	if generationRight != nil {
		c.generationStop = context.AfterFunc(generationRight.GenerationContext(), cancel)
	}
	if !c.reserveCoreTasks() {
		if c.carrierFrame != nil {
			c.carrierFrame.Abort()
		}
		cancel()
		c.timer.Stop()
		common.Interrupt(uplinkReader)
		common.Interrupt(upLinkWriter)
		common.Interrupt(downlinkReader)
		common.Interrupt(downlinkWriter)
		common.Close(c)
		c.Wait()
		return nil, errors.New("mux worker core tasks could not be reserved during construction")
	}
	if !c.reserveFactory(cancel) {
		if c.carrierFrame != nil {
			c.carrierFrame.Abort()
		}
		cancel()
		c.releaseReservedCoreTasks()
		c.timer.Stop()
		common.Interrupt(uplinkReader)
		common.Interrupt(upLinkWriter)
		common.Interrupt(downlinkReader)
		common.Interrupt(downlinkWriter)
		common.Close(c)
		c.Wait()
		return nil, errors.New("mux worker closed during construction")
	}
	if c.carrierFrame != nil {
		c.carrierFrame.Commit()
	}
	c.startReservedCoreTasks()
	go func(p proxy.Outbound, d internet.Dialer, c *ClientWorker, ctx context.Context) {
		defer c.finishFactory()
		defer cancel()
		if errP := p.Process(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, d); errP != nil {
			errC := errors.Cause(errP)
			if !(goerrors.Is(errC, io.EOF) || goerrors.Is(errC, io.ErrClosedPipe) || goerrors.Is(errC, context.Canceled)) {
				errors.LogInfoInner(ctx, errP, "failed to handler mux client connection")
			}
		}
		common.Must(c.Close())
	}(f.Proxy, f.Dialer, c, ctx)

	return c, nil
}

type ClientStrategy struct {
	MaxConcurrency uint32
	MaxConnection  uint32
}

type ClientWorker struct {
	sessionManager  *SessionManager
	link            transport.Link
	done            *done.Instance
	timer           *time.Ticker
	strategy        ClientStrategy
	flowCarrierMu   sync.Mutex
	flowCarrier     atomic.Pointer[muxClientCarrierObservation]
	flowCarrierOnce sync.Once
	carrierFrame    session.MuxClientCarrierFrameObservation
	carrierOnce     sync.Once
	lifecycle       task.Lifecycle
	factoryMu       sync.Mutex
	factoryCancel   func()
	generationRight *core.RetirementRight
	generationStop  func() bool
	generationOnce  sync.Once
}

type muxClientCarrierObservation struct {
	observation session.MuxClientCarrierObservation
}

var (
	muxCoolAddress = net.DomainAddress("v1.mux.cool")
	muxCoolPort    = net.Port(9527)
)

// NewClientWorker creates a new mux.Client.
func NewClientWorker(stream transport.Link, s ClientStrategy) (*ClientWorker, error) {
	return newClientWorker(stream, s, nil, nil)
}

func newClientWorker(stream transport.Link, s ClientStrategy, carrier session.MuxClientCarrierObservation, generationRight *core.RetirementRight) (*ClientWorker, error) {
	c, err := newClientWorkerPrepared(stream, s, carrier, generationRight)
	if err != nil {
		return nil, err
	}
	if !c.reserveCoreTasks() {
		c.timer.Stop()
		common.Close(c)
		c.Wait()
		return nil, errors.New("mux worker core tasks could not be reserved")
	}
	c.startReservedCoreTasks()
	return c, nil
}

func newClientWorkerPrepared(stream transport.Link, s ClientStrategy, carrier session.MuxClientCarrierObservation, generationRight *core.RetirementRight) (*ClientWorker, error) {
	c := &ClientWorker{
		sessionManager:  NewSessionManager(),
		link:            stream,
		done:            done.New(),
		timer:           time.NewTicker(time.Second * 16),
		strategy:        s,
		generationRight: generationRight,
	}
	if carrier != nil {
		c.flowCarrier.Store(&muxClientCarrierObservation{observation: carrier})
		c.carrierFrame = session.MuxClientCarrierFrameObservationFromCarrier(carrier)
		if c.carrierFrame != nil {
			c.link = transport.Link{Reader: observedClientCarrierReader{Reader: stream.Reader, observation: c.carrierFrame}, Writer: observedClientCarrierWriter{Writer: stream.Writer, observation: c.carrierFrame}}
		}
	}
	return c, nil
}

func (c *ClientWorker) reserveCoreTasks() bool {
	if !c.lifecycle.Acquire() {
		return false
	}
	if !c.lifecycle.Acquire() {
		c.lifecycle.Release()
		return false
	}
	return true
}

func (c *ClientWorker) startReservedCoreTasks() {
	go func() { defer c.lifecycle.Release(); c.fetchOutput() }()
	go func() { defer c.lifecycle.Release(); c.monitor() }()
}

func (c *ClientWorker) releaseReservedCoreTasks() {
	c.lifecycle.Release()
	c.lifecycle.Release()
}

func (m *ClientWorker) TotalConnections() uint32 {
	return uint32(m.sessionManager.Count())
}

func (m *ClientWorker) ActiveConnections() uint32 {
	return uint32(m.sessionManager.Size())
}

// Closed returns true if this Client is closed.
func (m *ClientWorker) Closed() bool {
	return m.done.Done()
}

func (m *ClientWorker) WaitClosed() <-chan struct{} {
	return m.done.Wait()
}

func (m *ClientWorker) Close() error {
	m.lifecycle.Seal()
	m.factoryMu.Lock()
	cancel := m.factoryCancel
	m.factoryMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Close the allocation/start gate synchronously. Dispatch may already hold
	// a lifecycle claim, so the manager and session gates are the authority that
	// decide whether that admitted initialization starts or cleans up only.
	common.Must(m.sessionManager.Close())
	return m.done.Close()
}

// Wait is a truthful receipt for the worker participants registered by this
// stage. It may block if an inherited proxy ignores cancellation.
func (m *ClientWorker) Wait() {
	m.lifecycle.Wait()
	m.carrierOnce.Do(func() {
		if m.carrierFrame != nil {
			m.carrierFrame.WorkerQuiesced()
		}
	})
	m.generationOnce.Do(func() {
		if m.generationStop != nil {
			m.generationStop()
		}
		if m.generationRight != nil {
			m.generationRight.Release()
		}
	})
}

func (m *ClientWorker) Quiesced() bool {
	select {
	case <-m.lifecycle.Done():
		return true
	default:
		return false
	}
}

func (m *ClientWorker) reserveFactory(cancel func()) bool {
	if m.done.Done() || !m.lifecycle.Acquire() {
		return false
	}
	m.factoryMu.Lock()
	m.factoryCancel = cancel
	m.factoryMu.Unlock()
	return true
}

func (m *ClientWorker) finishFactory() {
	m.factoryMu.Lock()
	m.factoryCancel = nil
	m.factoryMu.Unlock()
	m.lifecycle.Release()
}

func (m *ClientWorker) monitor() {
	defer m.timer.Stop()

	for {
		checkSize := m.sessionManager.Size()
		checkCount := m.sessionManager.Count()
		select {
		case <-m.done.Wait():
			m.sessionManager.Close()
			common.Interrupt(m.link.Writer)
			common.Interrupt(m.link.Reader)
			return
		case <-m.timer.C:
			if m.sessionManager.CloseIfNoSessionAndIdle(checkSize, checkCount) {
				common.Must(m.Close())
			}
		}
	}
}

func writeFirstPayload(reader buf.Reader, writer *Writer) error {
	err := buf.CopyOnceTimeout(reader, writer, time.Millisecond*100)
	if err == buf.ErrNotTimeoutReader || err == buf.ErrReadTimeout {
		return writer.WriteMultiBuffer(buf.MultiBuffer{})
	}

	if err != nil {
		return err
	}

	return nil
}

func fetchInput(ctx context.Context, s *Session, output buf.Writer) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	var inbound *session.Inbound
	if session.IsReverseMuxFromContext(ctx) {
		inbound = session.InboundFromContext(ctx)
	}
	writer := NewWriter(s.ID, ob.Target, output, s.transferType, xudp.GetGlobalID(ctx), inbound)
	defer s.Close(false)
	defer writer.Close()

	errors.LogInfo(ctx, "dispatching request to ", ob.Target)
	if err := writeFirstPayload(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to write first payload")
		writer.hasError = true
		return
	}

	if err := buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to fetch all input")
		writer.hasError = true
		return
	}
}

func (m *ClientWorker) IsClosing() bool {
	sm := m.sessionManager
	if m.strategy.MaxConnection > 0 && sm.Count() >= int(m.strategy.MaxConnection) {
		return true
	}
	return false
}

// IsFull returns true if this ClientWorker is unable to accept more connections.
// it might be because it is closing, or the number of connections has reached the limit.
func (m *ClientWorker) IsFull() bool {
	if m.IsClosing() || m.Closed() {
		return true
	}

	sm := m.sessionManager
	if m.strategy.MaxConcurrency > 0 && sm.Size() >= int(m.strategy.MaxConcurrency) {
		return true
	}
	return false
}

func (m *ClientWorker) Dispatch(ctx context.Context, link *transport.Link) bool {
	if m.IsFull() {
		return false
	}

	sm := m.sessionManager
	if !m.lifecycle.Acquire() {
		return false
	}
	transferType := protocol.TransferTypeStream
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 && outbounds[len(outbounds)-1].Target.Network == net.Network_UDP {
		transferType = protocol.TransferTypePacket
	}
	s := sm.AllocateWithLink(&m.strategy, link.Reader, link.Writer, transferType, m.lifecycle.Release)
	if s == nil {
		m.lifecycle.Release()
		return false
	}
	m.observeFlowCarrier(ctx)
	if !s.startInput() {
		return true
	}
	go func() {
		defer s.releaseClaim()
		fetchInput(ctx, s, m.link.Writer)
	}()
	if _, ok := link.Reader.(*pipe.Reader); !ok {
		select {
		case <-ctx.Done():
		case <-s.done.Wait():
		}
	}
	return true
}

func (m *ClientWorker) observeFlowCarrier(ctx context.Context) {
	scope := session.MuxClientSessionObservationFromContext(ctx)
	if scope == nil {
		return
	}
	carrier := m.flowCarrier.Load()
	if carrier == nil {
		m.flowCarrierOnce.Do(func() {
			m.flowCarrierMu.Lock()
			defer m.flowCarrierMu.Unlock()
			if m.flowCarrier.Load() == nil {
				if observation := scope.NewCarrier(); observation != nil {
					m.flowCarrier.Store(&muxClientCarrierObservation{observation: observation})
				}
			}
		})
		carrier = m.flowCarrier.Load()
	}
	if carrier != nil {
		carrier.observation.AttachTo(scope)
	}
}

// recordEarlyFlowCarrierAttempt reserves the one worker-scoped carrier mint
// slot when an authority was consulted before the worker is published. A nil
// early result remains a completed observation attempt.
func (m *ClientWorker) recordEarlyFlowCarrierAttempt() {
	m.flowCarrierOnce.Do(func() {})
}

func (m *ClientWorker) handleStatueKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) handleStatusNew(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := m.sessionManager.Get(meta.SessionID)
	if !found {
		if m.sessionManager.Closed() {
			return errClientSessionGateClosed
		}
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, m.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	return m.handleStatusKeepSession(s, meta, reader)
}

func (m *ClientWorker) handleStatusKeepSession(s *Session, meta *FrameMetadata, reader *buf.BufferedReader) error {
	rr := s.NewReader(reader, &meta.Target)
	if !s.waitForStart() {
		return errClientSessionGateClosed
	}
	err := buf.Copy(rr, s.output)
	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

var errClientSessionGateClosed = errors.New("mux client session gate resolved as cleanup only")

func (m *ClientWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := m.sessionManager.Get(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) fetchOutput() {
	defer func() {
		common.Must(m.Close())
	}()

	reader := &buf.BufferedReader{Reader: m.link.Reader}

	var meta FrameMetadata
	for {
		err := meta.Unmarshal(reader, false)
		if err != nil {
			if errors.Cause(err) != io.EOF {
				errors.LogInfoInner(context.Background(), err, "failed to read metadata")
			}
			break
		}

		switch meta.SessionStatus {
		case SessionStatusKeepAlive:
			err = m.handleStatueKeepAlive(&meta, reader)
		case SessionStatusEnd:
			err = m.handleStatusEnd(&meta, reader)
		case SessionStatusNew:
			err = m.handleStatusNew(&meta, reader)
		case SessionStatusKeep:
			err = m.handleStatusKeep(&meta, reader)
		default:
			status := meta.SessionStatus
			errors.LogError(context.Background(), "unknown status: ", status)
			return
		}

		if err != nil {
			if err != errClientSessionGateClosed {
				errors.LogInfoInner(context.Background(), err, "failed to process data")
			}
			return
		}
	}
}
