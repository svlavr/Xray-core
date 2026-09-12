package outbound

import (
	"context"
	stderrors "errors"
	"sort"
	"strings"
	"sync"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/outbound"
)

// Manager is to manage all outbound handlers.
type Manager struct {
	access              sync.RWMutex
	defaultHandler      outbound.Handler
	taggedHandler       map[string]outbound.Handler
	untaggedHandlers    []outbound.Handler
	running             bool
	tagsCache           *sync.Map
	flowCarrierBindings map[*Handler][]func()
	muxAuthority        session.MuxClientCarrierAuthorityProvider
	closed              bool
	closeDone           chan struct{}
	closeErr            error
	signalOnce          sync.Once
	retirement          *core.RetirementLedger
	generations         map[outbound.Handler]*core.RetirementGeneration
	entries             map[*core.RetirementGeneration]*handlerGenerationEntry
	retained            map[*core.RetirementGeneration]*handlerGenerationEntry
	shared              map[string]*sharedHandler
	sharedCreating      map[string]*sharedHandlerCreation
	sharedClosing       map[outbound.Handler]*sharedHandlerClose
	stopping            bool
}

type sharedHandler struct {
	handler outbound.Handler
	refs    int
}

type sharedHandlerCreation struct {
	done       chan struct{}
	cancel     context.CancelFunc
	err        error
	cleanupErr error
	handler    outbound.Handler
}

type sharedHandlerClose struct {
	done chan struct{}
	err  error
}

type sharedHandlerRegistration struct {
	manager  *Manager
	tag      string
	handler  outbound.Handler
	released bool
}

func (r *sharedHandlerRegistration) Handler() outbound.Handler {
	if r == nil {
		return nil
	}
	return r.handler
}

type handlerGenerationEntry struct {
	handler    outbound.Handler
	generation *core.RetirementGeneration

	closerOnce sync.Once
	closeOnce  sync.Once
	done       chan struct{}
	closeDone  chan struct{}
	resultMu   sync.Mutex
	result     error
}

func newHandlerGenerationEntry(handler outbound.Handler, generation *core.RetirementGeneration) *handlerGenerationEntry {
	return &handlerGenerationEntry{handler: handler, generation: generation, done: make(chan struct{}), closeDone: make(chan struct{})}
}

func (e *handlerGenerationEntry) startHandlerClose() {
	e.closeOnce.Do(func() {
		go func() {
			result := closeOutboundHandler(e.handler)
			e.resultMu.Lock()
			e.result = result
			e.resultMu.Unlock()
			close(e.closeDone)
		}()
	})
}

func closeOutboundHandler(handler outbound.Handler) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("outbound handler close panic: ", recovered)
		}
	}()
	return handler.Close()
}

func (e *handlerGenerationEntry) closeResult() error {
	<-e.done
	e.resultMu.Lock()
	defer e.resultMu.Unlock()
	return e.result
}

type enteredHandler struct {
	handler outbound.Handler
	ctx     context.Context
	task    *core.RetirementTask
	once    sync.Once
}

func (e *enteredHandler) Handler() outbound.Handler { return e.handler }
func (e *enteredHandler) Context() context.Context  { return e.ctx }
func (e *enteredHandler) Release() {
	if e == nil {
		return
	}
	e.once.Do(func() {
		if e.task != nil {
			e.task.Release()
		}
	})
}

// New creates a new Manager.
func New(ctx context.Context, config *proxyman.OutboundConfig) (*Manager, error) {
	m := &Manager{
		taggedHandler:       make(map[string]outbound.Handler),
		tagsCache:           &sync.Map{},
		flowCarrierBindings: make(map[*Handler][]func()),
		retirement:          core.RetirementLedgerFromContext(ctx),
		generations:         make(map[outbound.Handler]*core.RetirementGeneration),
		entries:             make(map[*core.RetirementGeneration]*handlerGenerationEntry),
		retained:            make(map[*core.RetirementGeneration]*handlerGenerationEntry),
		shared:              make(map[string]*sharedHandler),
		sharedCreating:      make(map[string]*sharedHandlerCreation),
		sharedClosing:       make(map[outbound.Handler]*sharedHandlerClose),
	}
	return m, nil
}

func (r *sharedHandlerRegistration) Enter(ctx context.Context) (outbound.HandlerEntry, error) {
	if r == nil || r.manager == nil {
		return nil, errors.New("shared outbound registration is unavailable")
	}
	r.manager.access.RLock()
	if r.released || r.manager.stopping || r.manager.closed || r.manager.shared[r.tag] == nil || r.manager.shared[r.tag].handler != r.handler || r.manager.taggedHandler[r.tag] != r.handler {
		r.manager.access.RUnlock()
		return nil, errors.New("shared outbound registration is no longer active")
	}
	entry, err := r.manager.enterLocked(ctx, r.handler)
	r.manager.access.RUnlock()
	return entry, err
}

func (r *sharedHandlerRegistration) Release(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.releaseSharedHandler(ctx, r)
}

// RegisterVLESSReverse shares one exact synthetic handler by tag. Creation
// happens outside Manager.access; concurrent callers wait on the same receipt.
func (m *Manager) RegisterVLESSReverse(ctx context.Context, tag string, factory func(context.Context) (outbound.Handler, error)) (outbound.VLESSReverseRegistration, error) {
	if tag == "" || factory == nil {
		return nil, common.ErrNoClue
	}
	for {
		m.access.Lock()
		if m.stopping || m.closed {
			m.access.Unlock()
			return nil, errors.New("outbound manager is stopping")
		}
		if shared := m.shared[tag]; shared != nil {
			if m.taggedHandler[tag] != shared.handler {
				delete(m.shared, tag)
				m.access.Unlock()
				continue
			}
			shared.refs++
			registered := &sharedHandlerRegistration{manager: m, tag: tag, handler: shared.handler}
			m.access.Unlock()
			return registered, nil
		}
		if creating := m.sharedCreating[tag]; creating != nil {
			done := creating.done
			m.access.Unlock()
			select {
			case <-done:
				if creating.err != nil {
					return nil, creating.err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if m.taggedHandler[tag] != nil || m.defaultHandler == nil {
			m.access.Unlock()
			return nil, errors.New("vless reverse requires a pre-existing ordinary outbound and unowned tag: ", tag)
		}
		factoryCtx, cancel := context.WithCancel(ctx)
		creating := &sharedHandlerCreation{done: make(chan struct{}), cancel: cancel}
		m.sharedCreating[tag] = creating
		m.access.Unlock()

		handler, err := factory(factoryCtx)
		if err == nil && (handler == nil || handler.Tag() != tag) {
			err = errors.New("vless reverse factory returned wrong tag")
		}
		m.access.RLock()
		stopping := m.stopping || m.closed
		m.access.RUnlock()
		adopted := false
		if err == nil && !stopping {
			m.access.Lock()
			if m.sharedCreating[tag] == creating && !m.stopping && !m.closed {
				creating.handler = handler
			} else {
				stopping = true
			}
			m.access.Unlock()
		}
		if err == nil && !stopping {
			err = m.AddHandler(ctx, handler)
			adopted = err == nil
		}
		if err == nil && stopping {
			err = errors.New("outbound manager stopped during vless reverse creation")
		}
		m.access.Lock()
		if err == nil && !m.stopping && !m.closed && m.taggedHandler[tag] == handler {
			m.shared[tag] = &sharedHandler{handler: handler, refs: 1}
		} else if err == nil {
			err = errors.New("outbound manager stopped during vless reverse publication")
		}
		cancel()
		m.access.Unlock()
		if err != nil {
			if handler != nil && !adopted {
				creating.cleanupErr = closeOutboundHandler(handler)
				err = stderrors.Join(err, creating.cleanupErr)
			}
		}
		m.access.Lock()
		if m.sharedCreating[tag] == creating {
			delete(m.sharedCreating, tag)
		}
		creating.err = err
		close(creating.done)
		m.access.Unlock()
		if err != nil {
			return nil, err
		}
		return &sharedHandlerRegistration{manager: m, tag: tag, handler: handler}, nil
	}
}

func (m *Manager) releaseSharedHandler(ctx context.Context, registration *sharedHandlerRegistration) error {
	tag, handler := registration.tag, registration.handler
	m.access.Lock()
	shared := m.shared[tag]
	if registration.released {
		m.access.Unlock()
		return nil
	}
	if shared == nil || shared.handler != handler || m.taggedHandler[tag] != handler {
		registration.released = true
		m.access.Unlock()
		return nil
	}
	if shared.refs > 1 {
		shared.refs--
		registration.released = true
		m.access.Unlock()
		return nil
	}
	// The refcount transition and exact-tag detachment are linearized under the
	// manager lock. ReserveRetirement below is still before map mutation.
	generation := m.generations[handler]
	if generation != nil {
		if err := m.retirement.ReserveRetirement(generation); err != nil {
			m.access.Unlock()
			return err
		}
	}
	delete(m.shared, tag)
	delete(m.taggedHandler, tag)
	if m.defaultHandler == handler {
		m.defaultHandler = nil
	}
	entry := m.entries[generation]
	if generation != nil {
		m.retained[generation] = m.entries[generation]
	}
	var standaloneClose *sharedHandlerClose
	if generation == nil {
		standaloneClose = &sharedHandlerClose{done: make(chan struct{})}
		m.sharedClosing[handler] = standaloneClose
	}
	registration.released = true
	m.tagsCache = &sync.Map{}
	m.access.Unlock()
	if stock, ok := handler.(*Handler); ok && generation != nil {
		stock.Retire()
	}
	if generation != nil {
		generation.Retire()
		m.startGenerationCloser(entry, true)
		return nil
	}
	standaloneClose.err = closeOutboundHandler(handler)
	m.access.Lock()
	close(standaloneClose.done)
	if m.sharedClosing[handler] == standaloneClose {
		delete(m.sharedClosing, handler)
	}
	m.access.Unlock()
	return standaloneClose.err
}

// Type implements common.HasType.
func (m *Manager) Type() interface{} {
	return outbound.ManagerType()
}

func (*Manager) ShutdownPhase() features.ShutdownPhase {
	return features.ShutdownPhaseTrafficOwner
}

// Start implements core.Feature
func (m *Manager) Start() error {
	m.access.Lock()
	if m.stopping || m.closed {
		m.access.Unlock()
		return errors.New("outbound manager is stopping")
	}

	m.running = true

	defer m.access.Unlock()
	for _, h := range m.taggedHandler {
		if err := h.Start(); err != nil {
			return err
		}
	}
	for _, h := range m.untaggedHandlers {
		if err := h.Start(); err != nil {
			return err
		}
	}
	return nil
}

// Close implements core.Feature
func (m *Manager) Close() error {
	m.SignalStop()
	m.access.Lock()
	if m.closed {
		done := m.closeDone
		m.access.Unlock()
		if done != nil {
			<-done
		}
		m.access.RLock()
		err := m.closeErr
		m.access.RUnlock()
		return err
	}
	m.closed = true
	m.closeDone = make(chan struct{})
	done := m.closeDone
	m.running = false
	handlers := make([]outbound.Handler, 0, len(m.taggedHandler)+len(m.untaggedHandlers))
	for _, h := range m.taggedHandler {
		handlers = append(handlers, h)
	}
	handlers = append(handlers, m.untaggedHandlers...)
	bindings := m.flowCarrierBindings
	creations := make([]*sharedHandlerCreation, 0, len(m.sharedCreating))
	for _, creation := range m.sharedCreating {
		creations = append(creations, creation)
	}
	standaloneClosing := make([]*sharedHandlerClose, 0, len(m.sharedClosing))
	for _, closing := range m.sharedClosing {
		standaloneClosing = append(standaloneClosing, closing)
	}
	entries := make([]*handlerGenerationEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	m.taggedHandler = make(map[string]outbound.Handler)
	m.untaggedHandlers = nil
	m.defaultHandler = nil
	m.flowCarrierBindings = make(map[*Handler][]func())
	m.generations = make(map[outbound.Handler]*core.RetirementGeneration)
	m.entries = make(map[*core.RetirementGeneration]*handlerGenerationEntry)
	m.retained = make(map[*core.RetirementGeneration]*handlerGenerationEntry)
	m.shared = make(map[string]*sharedHandler)
	m.access.Unlock()
	var errs []error
	for _, creation := range creations {
		<-creation.done
		errs = append(errs, creation.cleanupErr)
	}
	for _, closing := range standaloneClosing {
		<-closing.done
		errs = append(errs, closing.err)
	}
	if len(entries) != 0 {
		// Signal every stock handler before starting any join. Custom handlers
		// receive concurrent Close calls in the following phase.
		for _, entry := range entries {
			if handler, ok := entry.handler.(*Handler); ok {
				handler.SignalStop()
			}
		}
		for _, entry := range entries {
			entry.startHandlerClose()
			m.startGenerationCloser(entry, true)
		}
		for _, entry := range entries {
			errs = append(errs, entry.closeResult())
		}
	} else {
		// Standalone managers have no generation ledger. Close their finite
		// snapshot concurrently so detour dependencies are all signaled.
		results := make(chan error, len(handlers))
		for _, handler := range handlers {
			go func() { results <- closeOutboundHandler(handler) }()
		}
		for range handlers {
			errs = append(errs, <-results)
		}
	}
	for _, releases := range bindings {
		for _, release := range releases {
			release()
		}
	}

	err := errors.Combine(errs...)
	m.access.Lock()
	m.closeErr = err
	close(done)
	m.access.Unlock()
	return err
}

func (m *Manager) SignalStop() {
	if m == nil {
		return
	}
	m.signalOnce.Do(func() {
		m.access.Lock()
		m.stopping = true
		creationCancels := make([]context.CancelFunc, 0, len(m.sharedCreating))
		for _, creation := range m.sharedCreating {
			creationCancels = append(creationCancels, creation.cancel)
		}
		m.access.Unlock()
		for _, cancel := range creationCancels {
			cancel()
		}
		if m.retirement != nil {
			m.retirement.SealAndSnapshot()
		}
		m.access.RLock()
		entries := make([]*handlerGenerationEntry, 0, len(m.entries))
		for _, entry := range m.entries {
			entries = append(entries, entry)
		}
		m.access.RUnlock()
		for _, entry := range entries {
			if handler, ok := entry.handler.(*Handler); ok {
				handler.SignalStop()
			} else {
				entry.startHandlerClose()
			}
		}
	})
}

// GetDefaultHandler implements outbound.Manager.
func (m *Manager) GetDefaultHandler() outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	if m.defaultHandler == nil {
		return nil
	}
	return m.defaultHandler
}

// GetHandler implements outbound.Manager.
func (m *Manager) GetHandler(tag string) outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()
	if handler, found := m.taggedHandler[tag]; found {
		return handler
	}
	return nil
}

func (m *Manager) EnterHandler(ctx context.Context, tag string) (outbound.HandlerEntry, error) {
	m.access.RLock()
	defer m.access.RUnlock()
	if m.closed {
		return nil, errors.New("outbound manager is closed")
	}
	handler := m.taggedHandler[tag]
	if handler == nil {
		return nil, errors.New("outbound handler not found: ", tag)
	}
	return m.enterLocked(ctx, handler)
}

func (m *Manager) EnterDefaultHandler(ctx context.Context) (outbound.HandlerEntry, error) {
	m.access.RLock()
	defer m.access.RUnlock()
	if m.closed {
		return nil, errors.New("outbound manager is closed")
	}
	if m.defaultHandler == nil {
		return nil, errors.New("default outbound handler not found")
	}
	return m.enterLocked(ctx, m.defaultHandler)
}

func (m *Manager) enterLocked(ctx context.Context, handler outbound.Handler) (outbound.HandlerEntry, error) {
	generation := m.generations[handler]
	if generation == nil {
		return &enteredHandler{handler: handler, ctx: ctx}, nil
	}
	enteredCtx, task, err := core.EnterRetirement(ctx, generation)
	if err != nil {
		return nil, err
	}
	return &enteredHandler{handler: handler, ctx: enteredCtx, task: task}, nil
}

// AddHandler implements outbound.Manager.
func (m *Manager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	m.access.Lock()
	if m.stopping || m.closed {
		m.access.Unlock()
		return errors.New("outbound manager is stopping")
	}
	if generation := m.generations[handler]; generation != nil {
		m.access.Unlock()
		return errors.New("outbound handler instance already has a live generation")
	}

	tag := handler.Tag()
	if len(tag) > 0 {
		if _, found := m.taggedHandler[tag]; found {
			m.access.Unlock()
			return errors.New("existing tag found: " + tag)
		}
	}
	var generation *core.RetirementGeneration
	var entry *handlerGenerationEntry
	if m.retirement != nil {
		var err error
		generation, err = m.retirement.Register(handler, handler.Tag())
		if err != nil {
			m.access.Unlock()
			return err
		}
		if stock, ok := handler.(*Handler); ok && !stock.BindRetirementGeneration(generation) {
			abandoned := generation.Abandon()
			m.access.Unlock()
			if !abandoned {
				<-generation.Drained()
				generation.Release()
			}
			return errors.New("outbound handler already belongs to a generation")
		}
		entry = newHandlerGenerationEntry(handler, generation)
		m.generations[handler] = generation
		m.entries[generation] = entry
	}
	if stock, ok := handler.(*Handler); ok && m.muxAuthority != nil {
		stock.BindMuxClientCarrierAuthority(m.muxAuthority)
	}
	m.tagsCache = &sync.Map{}
	if m.defaultHandler == nil {
		m.defaultHandler = handler
	}
	if len(tag) > 0 {
		m.taggedHandler[tag] = handler
	} else {
		m.untaggedHandlers = append(m.untaggedHandlers, handler)
	}
	m.bindFlowCarrierObservation(handler)
	if m.running {
		startErr := handler.Start()
		if startErr != nil {
			if len(tag) > 0 {
				if m.taggedHandler[tag] == handler {
					delete(m.taggedHandler, tag)
				}
			} else {
				for index, candidate := range m.untaggedHandlers {
					if candidate == handler {
						m.untaggedHandlers = append(m.untaggedHandlers[:index], m.untaggedHandlers[index+1:]...)
						break
					}
				}
			}
			if m.defaultHandler == handler {
				m.defaultHandler = nil
			}
			var releases []func()
			if stock, ok := handler.(*Handler); ok {
				releases = append(releases, m.flowCarrierBindings[stock]...)
				delete(m.flowCarrierBindings, stock)
			}
			abandoned := generation == nil || generation.Abandon()
			if abandoned {
				delete(m.generations, handler)
				delete(m.entries, generation)
			} else {
				m.retained[generation] = entry
			}
			m.access.Unlock()
			for _, release := range releases {
				release()
			}
			if !abandoned {
				if stock, ok := handler.(*Handler); ok {
					stock.SignalStop()
				}
				entry.startHandlerClose()
				m.startGenerationCloser(entry, true)
				return errors.Combine(startErr, entry.closeResult())
			}
			return errors.Combine(startErr, closeOutboundHandler(handler))
		}
		m.access.Unlock()
		return nil
	}
	m.access.Unlock()
	return nil
}

// RemoveHandler implements outbound.Manager.
func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {
	return m.removeHandler(ctx, tag, nil)
}

// RemoveHandlerInstance removes handler only while that exact object remains
// current. A stale removal is an idempotent no-op and cannot affect a same-tag
// replacement.
func (m *Manager) RemoveHandlerInstance(ctx context.Context, handler outbound.Handler) error {
	if handler == nil {
		return common.ErrNoClue
	}
	return m.removeHandler(ctx, handler.Tag(), handler)
}

func (m *Manager) removeHandler(ctx context.Context, tag string, expected outbound.Handler) error {
	if tag == "" {
		return common.ErrNoClue
	}
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		if expected != nil {
			return nil
		}
		return errors.New("outbound manager is closed")
	}

	handler, found := m.taggedHandler[tag]
	if expected != nil && (!found || handler != expected) {
		m.access.Unlock()
		return nil
	}
	generation := m.generations[handler]
	entry := m.entries[generation]
	if expected != nil && generation != nil && generation.Phase() != core.RetirementActive {
		m.access.Unlock()
		return nil
	}
	if found && generation != nil {
		if err := m.retirement.ReserveRetirement(generation); err != nil {
			if expected != nil && generation.Phase() != core.RetirementActive {
				m.access.Unlock()
				return nil
			}
			m.access.Unlock()
			return err
		}
	}
	sharedSynthetic := false
	if found {
		if shared := m.shared[tag]; shared != nil && shared.handler == handler {
			sharedSynthetic = true
			delete(m.shared, tag)
		}
		if creating := m.sharedCreating[tag]; creating != nil && creating.handler == handler {
			sharedSynthetic = true
		}
	}
	m.tagsCache = &sync.Map{}
	if found {
		delete(m.taggedHandler, tag)
	}
	if m.defaultHandler != nil && m.defaultHandler.Tag() == tag {
		m.defaultHandler = nil
	}
	var releases []func()
	if stock, ok := handler.(*Handler); ok {
		releases = append(releases, m.flowCarrierBindings[stock]...)
		delete(m.flowCarrierBindings, stock)
	}
	if found && generation != nil {
		m.retained[generation] = entry
	}
	var standaloneClose *sharedHandlerClose
	if found && generation == nil && sharedSynthetic {
		standaloneClose = &sharedHandlerClose{done: make(chan struct{})}
		m.sharedClosing[handler] = standaloneClose
	}
	m.access.Unlock()
	for _, release := range releases {
		release()
	}
	if stock, ok := handler.(*Handler); ok && generation != nil {
		stock.Retire()
	}
	if generation != nil {
		generation.Retire()
		m.startGenerationCloser(entry, true)
		return nil
	}
	if standaloneClose != nil {
		standaloneClose.err = closeOutboundHandler(handler)
		m.access.Lock()
		close(standaloneClose.done)
		if m.sharedClosing[handler] == standaloneClose {
			delete(m.sharedClosing, handler)
		}
		m.access.Unlock()
		return standaloneClose.err
	}
	// Standalone managers preserve upstream detach-only removal. Instance-backed
	// managers retain the exact generation until its drain receipt. A shared
	// synthetic handler is the exception: its exact owner must close and join it.
	return nil
}

func (m *Manager) startGenerationCloser(entry *handlerGenerationEntry, asynchronous bool) {
	if entry == nil {
		return
	}
	entry.closerOnce.Do(func() {
		closeGeneration := func() {
			<-entry.generation.Drained()
			entry.startHandlerClose()
			<-entry.closeDone
			m.access.Lock()
			if m.retained[entry.generation] == entry {
				delete(m.retained, entry.generation)
			}
			if m.entries[entry.generation] == entry {
				delete(m.entries, entry.generation)
			}
			if m.generations[entry.handler] == entry.generation {
				delete(m.generations, entry.handler)
			}
			m.access.Unlock()
			entry.generation.Release()
			close(entry.done)
		}
		if asynchronous {
			go closeGeneration()
		} else {
			closeGeneration()
		}
	})
}

func (m *Manager) BindMuxClientCarrierAuthority(provider session.MuxClientCarrierAuthorityProvider) bool {
	m.access.Lock()
	defer m.access.Unlock()
	if provider == nil || m.muxAuthority != nil {
		return false
	}
	m.muxAuthority = provider
	bound := false
	for _, handler := range m.taggedHandler {
		if h, ok := handler.(*Handler); ok && h.BindMuxClientCarrierAuthority(provider) {
			bound = true
		}
	}
	for _, handler := range m.untaggedHandlers {
		if h, ok := handler.(*Handler); ok && h.BindMuxClientCarrierAuthority(provider) {
			bound = true
		}
	}
	return bound
}

func (m *Manager) bindFlowCarrierObservation(handler outbound.Handler) {
	stockHandler, ok := handler.(*Handler)
	if !ok {
		return
	}
	release := flow_observation.BindHandlerCarrierObservation(stockHandler, stockHandler.FlowCarrierObservation())
	m.flowCarrierBindings[stockHandler] = append(m.flowCarrierBindings[stockHandler], release)
}

func (m *Manager) releaseFlowCarrierObservation(handler outbound.Handler) {
	stockHandler, ok := handler.(*Handler)
	if !ok {
		return
	}
	for _, release := range m.flowCarrierBindings[stockHandler] {
		release()
	}
	delete(m.flowCarrierBindings, stockHandler)
}

func (m *Manager) releaseAllFlowCarrierBindings() {
	for stockHandler, releases := range m.flowCarrierBindings {
		for _, release := range releases {
			release()
		}
		delete(m.flowCarrierBindings, stockHandler)
	}
}

// ListHandlers implements outbound.Manager.
func (m *Manager) ListHandlers(ctx context.Context) []outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	response := make([]outbound.Handler, len(m.untaggedHandlers))
	copy(response, m.untaggedHandlers)

	for _, v := range m.taggedHandler {
		response = append(response, v)
	}

	return response
}

// Select implements outbound.HandlerSelector.
func (m *Manager) Select(selectors []string) []string {
	key := strings.Join(selectors, ",")
	m.access.RLock()
	defer m.access.RUnlock()
	if cache, ok := m.tagsCache.Load(key); ok {
		return cache.([]string)
	}

	tags := make([]string, 0, len(selectors))

	for tag := range m.taggedHandler {
		for _, selector := range selectors {
			if strings.HasPrefix(tag, selector) {
				tags = append(tags, tag)
				break
			}
		}
	}

	sort.Strings(tags)
	m.tagsCache.Store(key, tags)

	return tags
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*proxyman.OutboundConfig))
	}))
	common.Must(common.RegisterConfig((*core.OutboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*core.OutboundHandlerConfig))
	}))
}
