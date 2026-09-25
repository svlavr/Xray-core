package outbound

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

type handlerEntry struct {
	handler outbound.Handler
	serial  uint64
}

// Manager is to manage all outbound handlers.
type Manager struct {
	access           sync.RWMutex
	defaultHandler   *handlerEntry
	taggedHandler    map[string]*handlerEntry
	untaggedHandlers []*handlerEntry
	nextSerial       uint64
	running          bool
	tagsCache        *sync.Map
}

// New creates a new Manager.
func New(ctx context.Context, config *proxyman.OutboundConfig) (*Manager, error) {
	m := &Manager{
		taggedHandler: make(map[string]*handlerEntry),
		tagsCache:     &sync.Map{},
	}
	return m, nil
}

// Type implements common.HasType.
func (m *Manager) Type() interface{} {
	return outbound.ManagerType()
}

// Start implements core.Feature
func (m *Manager) Start() error {
	m.access.Lock()
	defer m.access.Unlock()

	m.running = true

	for _, h := range m.taggedHandler {
		if err := h.handler.Start(); err != nil {
			return err
		}
	}

	for _, h := range m.untaggedHandlers {
		if err := h.handler.Start(); err != nil {
			return err
		}
	}

	return nil
}

// Close implements core.Feature
func (m *Manager) Close() error {
	m.access.Lock()
	defer m.access.Unlock()

	m.running = false

	var errs []error
	for _, h := range m.taggedHandler {
		errs = append(errs, h.handler.Close())
	}

	for _, h := range m.untaggedHandlers {
		errs = append(errs, h.handler.Close())
	}

	return errors.Combine(errs...)
}

// GetDefaultHandler implements outbound.Manager.
func (m *Manager) GetDefaultHandler() outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	if m.defaultHandler == nil {
		return nil
	}
	return m.defaultHandler.handler
}

// GetHandler implements outbound.Manager.
func (m *Manager) GetHandler(tag string) outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()
	if handler, found := m.taggedHandler[tag]; found {
		return handler.handler
	}
	return nil
}

// AddHandler implements outbound.Manager.
func (m *Manager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()

	m.tagsCache = &sync.Map{}
	entry := &handlerEntry{handler: handler}
	if m.defaultHandler == nil {
		m.defaultHandler = entry
	}

	tag := handler.Tag()
	if len(tag) > 0 {
		if _, found := m.taggedHandler[tag]; found {
			return errors.New("existing tag found: " + tag)
		}
		m.taggedHandler[tag] = entry
	} else {
		m.untaggedHandlers = append(m.untaggedHandlers, entry)
	}

	if m.nextSerial < math.MaxUint64 {
		m.nextSerial++
		entry.serial = m.nextSerial
	}

	if m.running {
		return handler.Start()
	}

	return nil
}

// RemoveHandler implements outbound.Manager.
func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {
	if tag == "" {
		return common.ErrNoClue
	}
	m.access.Lock()
	defer m.access.Unlock()

	m.tagsCache = &sync.Map{}

	delete(m.taggedHandler, tag)
	if m.defaultHandler != nil && m.defaultHandler.handler.Tag() == tag {
		m.defaultHandler = nil
	}

	return nil
}

// ListHandlers implements outbound.Manager.
func (m *Manager) ListHandlers(ctx context.Context) []outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	response := make([]outbound.Handler, 0, len(m.untaggedHandlers)+len(m.taggedHandler))
	for _, e := range m.untaggedHandlers {
		response = append(response, e.handler)
	}

	for _, v := range m.taggedHandler {
		response = append(response, v.handler)
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

// ResolveHandler returns the selected entry and its non-reused insertion serial
// under the same native manager lock. The empty tag selects the default entry.
func (m *Manager) ResolveHandler(tag string, useDefault bool) (outbound.Handler, uint64) {
	m.access.RLock()
	defer m.access.RUnlock()
	entry := m.taggedHandler[tag]
	if useDefault {
		entry = m.defaultHandler
	}
	if entry == nil {
		return nil, 0
	}
	return entry.handler, entry.serial
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*proxyman.OutboundConfig))
	}))
	common.Must(common.RegisterConfig((*core.OutboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*core.OutboundHandlerConfig))
	}))
}
