package inbound

import (
	"context"
	stderrors "errors"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
)

// Manager manages all inbound handlers.
type Manager struct {
	access           sync.RWMutex
	untaggedHandlers []inbound.Handler
	taggedHandlers   map[string]inbound.Handler
	running          bool
	closeAttempts    map[inbound.Handler]*closeAttempt
	closing          bool
	closed           bool
	closeDone        chan struct{}
	closeErr         error
	tagEpoch         map[string]uint64
	nextTagEpoch     uint64
}

type closeAttempt struct {
	done chan struct{}
	err  error
}

type closeTarget struct {
	handler inbound.Handler
	attempt *closeAttempt
	owner   bool
}

// New returns a new Manager for inbound handlers.
func New(ctx context.Context, config *proxyman.InboundConfig) (*Manager, error) {
	m := &Manager{
		taggedHandlers: make(map[string]inbound.Handler),
		closeAttempts:  make(map[inbound.Handler]*closeAttempt),
		tagEpoch:       make(map[string]uint64),
	}
	return m, nil
}

// Type implements common.HasType.
func (*Manager) Type() interface{} {
	return inbound.ManagerType()
}

// AddHandler implements inbound.Manager.
func (m *Manager) AddHandler(ctx context.Context, handler inbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closing || m.closed {
		return errors.New("inbound manager is closing")
	}

	tag := handler.Tag()
	if len(tag) > 0 {
		if _, found := m.taggedHandlers[tag]; found {
			return errors.New("existing tag found: " + tag)
		}
		m.nextTagEpoch++
		m.taggedHandlers[tag] = handler
		m.tagEpoch[tag] = m.nextTagEpoch
	} else {
		m.untaggedHandlers = append(m.untaggedHandlers, handler)
	}

	if m.running {
		return handler.Start()
	}

	return nil
}

// GetHandler implements inbound.Manager.
func (m *Manager) GetHandler(ctx context.Context, tag string) (inbound.Handler, error) {
	m.access.RLock()
	defer m.access.RUnlock()

	handler, found := m.taggedHandlers[tag]
	if !found {
		return nil, errors.New("handler not found: ", tag)
	}
	return handler, nil
}

// RemoveHandler implements inbound.Manager.
func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {
	if tag == "" {
		return common.ErrNoClue
	}

	m.access.Lock()
	handler := m.taggedHandlers[tag]
	if handler == nil {
		m.access.Unlock()
		return common.ErrNoClue
	}
	epoch := m.tagEpoch[tag]
	target := m.closeTargetLocked(handler)
	m.access.Unlock()
	if err := m.runCloseTarget(target); err != nil {
		return err
	}
	m.commitTaggedRemoval(tag, handler, epoch, target.attempt)
	return nil
}

func (m *Manager) commitTaggedRemoval(tag string, handler inbound.Handler, epoch uint64, attempt *closeAttempt) {
	m.access.Lock()
	if m.taggedHandlers[tag] == handler && m.tagEpoch[tag] == epoch {
		delete(m.taggedHandlers, tag)
		delete(m.tagEpoch, tag)
		if m.closeAttempts[handler] == attempt {
			delete(m.closeAttempts, handler)
		}
	}
	m.access.Unlock()
}

// closeHandler has one receipt per exact handler, so concurrent removal and
// manager shutdown never issue duplicate Close calls or delete a replacement.
func (m *Manager) closeHandler(handler inbound.Handler) error {
	m.access.Lock()
	target := m.closeTargetLocked(handler)
	m.access.Unlock()
	return m.runCloseTarget(target)
}

func (m *Manager) closeTargetLocked(handler inbound.Handler) closeTarget {
	attempt := m.closeAttempts[handler]
	owner := attempt == nil
	if owner {
		attempt = &closeAttempt{done: make(chan struct{})}
		m.closeAttempts[handler] = attempt
	}
	return closeTarget{handler: handler, attempt: attempt, owner: owner}
}

func (m *Manager) runCloseTarget(target closeTarget) error {
	if target.owner {
		target.attempt.err = target.handler.Close()
		close(target.attempt.done)
		if target.attempt.err != nil {
			m.access.Lock()
			if m.closeAttempts[target.handler] == target.attempt {
				delete(m.closeAttempts, target.handler)
			}
			m.access.Unlock()
		}
	} else {
		<-target.attempt.done
	}
	return target.attempt.err
}

// ListHandlers implements inbound.Manager.
func (m *Manager) ListHandlers(ctx context.Context) []inbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	response := make([]inbound.Handler, len(m.untaggedHandlers))
	copy(response, m.untaggedHandlers)

	for _, v := range m.taggedHandlers {
		response = append(response, v)
	}

	return response
}

// Start implements common.Runnable.
func (m *Manager) Start() error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closing || m.closed {
		return errors.New("inbound manager is closing")
	}

	m.running = true

	for _, handler := range m.taggedHandlers {
		if err := handler.Start(); err != nil {
			return err
		}
	}

	for _, handler := range m.untaggedHandlers {
		if err := handler.Start(); err != nil {
			return err
		}
	}
	return nil
}

// Close implements common.Closable.
func (m *Manager) Close() error {
	m.access.Lock()
	if m.closing {
		done := m.closeDone
		m.access.Unlock()
		<-done
		m.access.RLock()
		err := m.closeErr
		m.access.RUnlock()
		return err
	}
	if m.closed {
		err := m.closeErr
		m.access.Unlock()
		return err
	}
	m.closing = true
	m.closeDone = make(chan struct{})
	done := m.closeDone
	m.running = false
	targets := make([]closeTarget, 0, len(m.taggedHandlers)+len(m.untaggedHandlers))
	for _, handler := range m.taggedHandlers {
		targets = append(targets, m.closeTargetLocked(handler))
	}
	for _, handler := range m.untaggedHandlers {
		targets = append(targets, m.closeTargetLocked(handler))
	}
	m.access.Unlock()

	var errs []error
	for _, target := range targets {
		if err := m.runCloseTarget(target); err != nil {
			errs = append(errs, err)
		}
	}
	err := stderrors.Join(errs...)
	m.access.Lock()
	m.closeErr = err
	m.closing = false
	if err == nil {
		m.closed = true
		m.closeAttempts = make(map[inbound.Handler]*closeAttempt)
	}
	close(done)
	m.access.Unlock()
	return err
}

// NewHandler creates a new inbound.Handler based on the given config.
func NewHandler(ctx context.Context, config *core.InboundHandlerConfig) (inbound.Handler, error) {
	rawReceiverSettings, err := config.ReceiverSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	proxySettings, err := config.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	tag := config.Tag

	receiverSettings, ok := rawReceiverSettings.(*proxyman.ReceiverConfig)
	if !ok {
		return nil, errors.New("not a ReceiverConfig").AtError()
	}

	streamSettings := receiverSettings.StreamSettings
	if streamSettings != nil && streamSettings.SocketSettings != nil {
		ctx = session.ContextWithSockopt(ctx, &session.Sockopt{
			Mark: streamSettings.SocketSettings.Mark,
		})
	}
	if streamSettings != nil && streamSettings.ProtocolName == "splithttp" {
		ctx = session.ContextWithAllowedNetwork(ctx, net.Network_UDP)
	}

	return NewAlwaysOnInboundHandler(ctx, tag, receiverSettings, proxySettings)
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*proxyman.InboundConfig))
	}))
	common.Must(common.RegisterConfig((*core.InboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*core.InboundHandlerConfig))
	}))
}
