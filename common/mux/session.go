package mux

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/pipe"
)

type SessionManager struct {
	sync.RWMutex
	sessions map[uint16]*Session
	count    uint16
	closed   bool
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		count:    0,
		sessions: make(map[uint16]*Session, 16),
	}
}

func (m *SessionManager) Closed() bool {
	m.RLock()
	defer m.RUnlock()

	return m.closed
}

func (m *SessionManager) Size() int {
	m.RLock()
	defer m.RUnlock()

	return len(m.sessions)
}

func (m *SessionManager) Count() int {
	m.RLock()
	defer m.RUnlock()

	return int(m.count)
}

func (m *SessionManager) Allocate(Strategy *ClientStrategy) *Session {
	return m.AllocateWithLink(Strategy, nil, nil, protocol.TransferTypeStream, nil)
}

// AllocateWithLink publishes a complete, gated client session atomically.
// Input/output and the post-commit release are installed before map visibility.
func (m *SessionManager) AllocateWithLink(Strategy *ClientStrategy, input buf.Reader, output buf.Writer, transferType protocol.TransferType, release func()) *Session {
	m.Lock()
	defer m.Unlock()

	MaxConcurrency := int(Strategy.MaxConcurrency)
	MaxConnection := uint16(Strategy.MaxConnection)

	if m.closed || (MaxConcurrency > 0 && len(m.sessions) >= MaxConcurrency) || (MaxConnection > 0 && m.count >= MaxConnection) {
		return nil
	}

	m.count++
	s := &Session{
		ID:           m.count,
		parent:       m,
		done:         done.New(),
		input:        input,
		output:       output,
		transferType: transferType,
		gated:        true,
		gateDone:     make(chan struct{}),
		release:      release,
	}
	m.sessions[s.ID] = s
	return s
}

func (m *SessionManager) Add(s *Session) bool {
	m.Lock()
	defer m.Unlock()

	if s == nil || m.closed || m.sessions[s.ID] != nil {
		return false
	}

	m.count++
	m.sessions[s.ID] = s
	return true
}

// addAndPublishXUDP makes a carrier-local XUDP session visible to both its
// session manager and the global XUDP entry as one lock-ordered transition.
// SessionManager always precedes XUDPManager in this package.
func (m *SessionManager) addAndPublishXUDP(s *Session, x *XUDP, expected *Session) bool {
	if s == nil || x == nil {
		return false
	}
	m.Lock()
	defer m.Unlock()
	if m.closed || m.sessions[s.ID] != nil {
		return false
	}
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	if XUDPManager.Map[x.GlobalID] != x || x.Status != Initializing || x.Mux != expected {
		return false
	}
	s.inputStarted = true
	m.count++
	m.sessions[s.ID] = s
	x.Mux = s
	x.Status = Active
	if s.xudpBinding != nil && !s.xudpBinding.Install() {
		s.xudpBinding.Abort()
		s.xudpBinding = nil
	}
	return true
}

func (m *SessionManager) Remove(locked bool, id uint16) {
	if !locked {
		m.Lock()
		defer m.Unlock()
	}
	locked = true

	if m.closed {
		return
	}

	delete(m.sessions, id)

	/*
		if len(m.sessions) == 0 {
			m.sessions = make(map[uint16]*Session, 16)
		}
	*/
}

// removeExact removes only the session instance that the manager still owns.
// A rejected duplicate must not remove its already-live sibling by ID.
func (m *SessionManager) removeExact(locked bool, s *Session) {
	if s == nil {
		return
	}
	if !locked {
		m.Lock()
		defer m.Unlock()
	}
	if m.closed || m.sessions[s.ID] != s {
		return
	}
	delete(m.sessions, s.ID)
}

func (m *SessionManager) Get(id uint16) (*Session, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.closed {
		return nil, false
	}

	s, found := m.sessions[id]
	return s, found
}

func (m *SessionManager) CloseIfNoSessionAndIdle(checkSize int, checkCount int) bool {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return true
	}

	if len(m.sessions) != 0 || checkSize != 0 || checkCount != int(m.count) {
		return false
	}

	m.closed = true

	m.sessions = nil
	return true
}

func (m *SessionManager) Close() error {
	m.Lock()
	if m.closed {
		m.Unlock()
		return nil
	}
	m.closed = true
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = nil
	m.Unlock()
	for _, s := range sessions {
		s.Close(false)
	}
	return nil
}

// Session represents a client connection in a Mux connection.
type Session struct {
	input         buf.Reader
	output        buf.Writer
	parent        *SessionManager
	ID            uint16
	transferType  protocol.TransferType
	closed        bool
	done          *done.Instance
	XUDP          *XUDP
	inputDone     chan struct{}
	inputStarted  bool
	inputStop     sync.Once
	inputFinish   sync.Once
	flowScope     session.MuxSessionObservation
	xudpRebinding bool
	xudpBinding   session.XUDPBindingObservation
	stateMu       sync.Mutex
	gated         bool
	gateDone      chan struct{}
	release       func()
	releaseOnce   sync.Once
}

func (s *Session) startInput() bool {
	s.stateMu.Lock()
	if s.closed || !s.gated {
		s.stateMu.Unlock()
		s.releaseClaim()
		return false
	}
	s.gated = false
	s.inputStarted = true
	close(s.gateDone)
	s.stateMu.Unlock()
	return true
}

func (s *Session) waitForStart() bool {
	s.stateMu.Lock()
	done := s.gateDone
	if done == nil {
		started := s.inputStarted
		s.stateMu.Unlock()
		return started
	}
	s.stateMu.Unlock()
	<-done
	s.stateMu.Lock()
	started := s.inputStarted
	s.stateMu.Unlock()
	return started
}

func (s *Session) releaseClaim() {
	s.releaseOnce.Do(func() {
		if s.release != nil {
			s.release()
		}
	})
}

func (s *Session) inputComplete() {
	if s.inputDone != nil {
		s.inputFinish.Do(func() { close(s.inputDone) })
	}
	if s.xudpBinding != nil {
		s.xudpBinding.ReaderExited()
	}
}

func (s *Session) stopXUDPInputContext(ctx context.Context, wait bool) error {
	if !s.inputStarted {
		return nil
	}
	reader, ok := s.input.(*pipe.Reader)
	if !ok {
		return errXUDPReaderUnsupported
	}
	s.inputStop.Do(func() { reader.ReturnAnError(io.EOF) })
	if wait && s.inputStarted && s.inputDone != nil {
		select {
		case <-s.inputDone:
			// If buf.Copy stopped because the response writer failed, the EOF
			// was never consumed. Drain only after the receipt, before this
			// retained reader is published to a new binding.
			reader.Recover()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Close closes all resources associated with this session.
func (s *Session) Close(locked bool) error {
	return s.close(context.Background(), locked)
}

func (s *Session) close(ctx context.Context, locked bool) error {
	managerShutdown := s.parent.Closed()
	// Map ownership is linearized under the parent only. All externally
	// re-enterable actions happen after it is released.
	s.parent.Lock()
	s.stateMu.Lock()
	alreadyClosed := s.closed
	if !alreadyClosed {
		s.closed = true
		if s.gated {
			s.gated = false
			close(s.gateDone)
		}
		if s.done != nil {
			s.done.Close()
		}
	}
	s.stateMu.Unlock()
	if !alreadyClosed {
		if s.parent.sessions != nil && s.parent.sessions[s.ID] == s {
			delete(s.parent.sessions, s.ID)
		}
	}
	s.parent.Unlock()
	if !alreadyClosed && s.XUDP == nil {
		common.Interrupt(s.input)
		common.Close(s.output)
	}
	if !alreadyClosed && s.flowScope != nil {
		s.flowScope.AfterClose()
	}
	if s.XUDP == nil {
		return nil
	}
	// A rebinding caller waits only after releasing SessionManager. Manager
	// shutdown sends the stop signal but must not wait while it holds that lock.
	if err := s.stopXUDPInputContext(ctx, true); err != nil {
		if managerShutdown && err == errXUDPReaderUnsupported {
			var observation session.XUDPEpochObservation
			XUDPManager.Lock()
			if XUDPManager.Map[s.XUDP.GlobalID] == s.XUDP && s.XUDP.Mux == s {
				delete(XUDPManager.Map, s.XUDP.GlobalID)
				observation = s.XUDP.observation
				if s.xudpBinding != nil {
					s.xudpBinding.RevokeUnproven()
				}
			}
			XUDPManager.Unlock()
			common.Interrupt(s.input)
			common.Close(s.output)
			if observation != nil {
				observation.Terminalize()
			}
		}
		return err
	}
	XUDPManager.Lock()
	if XUDPManager.Map[s.XUDP.GlobalID] == s.XUDP && s.XUDP.Mux == s &&
		(s.XUDP.Status == Active || (s.XUDP.Status == Initializing && s.xudpRebinding)) {
		if s.XUDP.Status == Active {
			s.XUDP.Expire = time.Now().Add(time.Minute)
			s.XUDP.Status = Expiring
		}
		transition := session.XUDPDetachToExpiring
		if s.xudpRebinding {
			transition = session.XUDPDetachForRebind
		}
		if s.xudpBinding != nil {
			s.xudpBinding.Deactivate(transition)
		}
		errors.LogDebug(context.Background(), "XUDP put ", s.XUDP.GlobalID)
	}
	XUDPManager.Unlock()
	return nil
}

// NewReader creates a buf.Reader based on the transfer type of this Session.
func (s *Session) NewReader(reader *buf.BufferedReader, dest *net.Destination) buf.Reader {
	if s.transferType == protocol.TransferTypeStream {
		return NewStreamReader(reader)
	}
	return NewPacketReader(reader, dest)
}

const (
	Initializing = 0
	Active       = 1
	Expiring     = 2
)

var errXUDPReaderUnsupported = errors.New("XUDP retained reader is not a pipe reader")

type XUDP struct {
	GlobalID    [8]byte
	Status      uint64
	Expire      time.Time
	Mux         *Session
	observation session.XUDPEpochObservation
}

func (x *XUDP) Interrupt() {
	XUDPManager.Lock()
	mux := x.Mux
	XUDPManager.Unlock()
	if mux == nil {
		return
	}
	common.Interrupt(mux.input)
	common.Close(mux.output)
}

var XUDPManager struct {
	sync.Mutex
	Map map[[8]byte]*XUDP
}

func init() {
	XUDPManager.Map = make(map[[8]byte]*XUDP)
	go func() {
		for {
			time.Sleep(time.Minute)
			expireXUDP(time.Now())
		}
	}()
}

// expireXUDP removes expired XUDP entries while retaining the manager lock for
// the exact duration of the stock sweep.
func expireXUDP(now time.Time) {
	XUDPManager.Lock()
	type expiredBinding struct {
		session     *Session
		observation session.XUDPEpochObservation
	}
	var expired []expiredBinding
	for id, x := range XUDPManager.Map {
		if x.Status == Expiring && now.After(x.Expire) {
			// The lock proves this is still the exact expiring binding. The
			// retained transport is captured before deleting the authority.
			mux := x.Mux
			delete(XUDPManager.Map, id)
			if mux != nil {
				expired = append(expired, expiredBinding{session: mux, observation: x.observation})
			}
			errors.LogDebug(context.Background(), "XUDP del ", id)
		}
	}
	XUDPManager.Unlock()
	for _, expired := range expired {
		common.Interrupt(expired.session.input)
		common.Close(expired.session.output)
		// The exact map entry was removed under XUDPManager and both retained
		// endpoints have completed their local close actions.
		if expired.observation != nil {
			expired.observation.Terminalize()
		}
	}
}
