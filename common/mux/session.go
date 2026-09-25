package mux

import (
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/stats"
)

type SessionManager struct {
	sync.RWMutex
	sessions map[uint16]*Session
	active   int // closed server wire-ID reservations are not active sessions
	count    uint16
	closed   bool
	seen     []uint64 // server's peer-supplied wire IDs; at most 1024 words
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

	return m.active
}

func (m *SessionManager) Count() int {
	m.RLock()
	defer m.RUnlock()

	return int(m.count)
}

func (m *SessionManager) Allocate(Strategy *ClientStrategy) *Session {
	return m.allocate(Strategy, &Session{})
}

// allocate publishes only initialized client endpoints. Close/Get may run as
// soon as the manager lock is released.
func (m *SessionManager) allocate(Strategy *ClientStrategy, s *Session) *Session {
	m.Lock()
	defer m.Unlock()

	MaxConcurrency := int(Strategy.MaxConcurrency)
	MaxConnection := uint16(Strategy.MaxConnection)

	if m.closed || m.count == ^uint16(0) || (MaxConcurrency > 0 && m.active >= MaxConcurrency) || (MaxConnection > 0 && m.count >= MaxConnection) {
		return nil
	}

	m.count++
	s.ID = m.count
	s.parent = m
	s.done = done.New()
	m.sessions[s.ID] = s
	m.active++
	return s
}

func (m *SessionManager) Add(s *Session) bool {
	m.Lock()
	defer m.Unlock()

	if m.closed || s.closed || m.sessions[s.ID] != nil {
		return false
	}

	m.count++
	m.sessions[s.ID] = s
	m.active++
	m.markSeenLocked(s.ID)
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

	if s := m.sessions[id]; s != nil && !s.closed {
		m.active--
	}
	delete(m.sessions, id)

	/*
		if len(m.sessions) == 0 {
			m.sessions = make(map[uint16]*Session, 16)
		}
	*/
}

func (m *SessionManager) Get(id uint16) (*Session, bool) {
	s, _ := m.lookup(id, false)
	return s, s != nil
}

// lookup distinguishes an ended native child (which already owns its END)
// from an ID that this carrier never admitted. The lookup/close race is atomic.
func (m *SessionManager) lookup(id uint16, sequentialIDs bool) (*Session, bool) {
	m.RLock()
	defer m.RUnlock()
	if s := m.sessions[id]; !m.closed && s != nil && !s.closed {
		return s, true
	}
	if sequentialIDs {
		// Client IDs are nonzero, monotonic, and never wrap or reuse.
		return nil, id != 0 && id <= m.count
	}
	word := int(id) / 64
	return nil, word < len(m.seen) && m.seen[word]&(uint64(1)<<(id%64)) != 0
}

func (m *SessionManager) markSeenLocked(id uint16) {
	n := int(id)/64 + 1
	if n > cap(m.seen) {
		grown := make([]uint64, n, min(1024, max(n, 2*cap(m.seen))))
		copy(grown, m.seen)
		m.seen = grown
	} else if n > len(m.seen) {
		m.seen = m.seen[:n]
	}
	m.seen[int(id)/64] |= uint64(1) << (id % 64)
}

func (m *SessionManager) CloseIfNoSessionAndIdle(checkSize int, checkCount int) bool {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return true
	}

	if m.active != 0 || checkSize != 0 || checkCount != int(m.count) {
		return false
	}

	m.closed = true

	m.sessions = nil
	return true
}

func (m *SessionManager) Close() error {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	for _, s := range m.sessions {
		s.Close(true)
	}

	m.sessions = nil
	m.active = 0
	return nil
}

// Session represents a client connection in a Mux connection.
type Session struct {
	input        buf.Reader
	output       buf.Writer
	parent       *SessionManager
	ID           uint16
	transferType protocol.TransferType
	closed       bool
	done         *done.Instance
	XUDP         *XUDP
	xudp         *xudpBinding
	server       bool           // retain wire ID until the server response worker returns
	inspection   stats.Exchange // existing client admission; never the carrier
	cleanup      func()         // ordinary server admission, after response return
	initializing bool
	responseDone bool
}

// Close closes all resources associated with this session.
func (s *Session) Close(locked bool) error {
	if !locked {
		s.parent.Lock()
		defer s.parent.Unlock()
	}
	locked = true
	if s.closed {
		return nil
	}
	s.closed = true
	if s.parent.sessions[s.ID] == s {
		s.parent.active--
	}
	if s.done != nil {
		s.done.Close()
	}
	if s.XUDP == nil {
		common.Interrupt(s.input)
		common.Close(s.output)
	} else {
		if s.xudp != nil {
			s.xudp.cancel()
		}
		XUDPManager.Lock()
		if XUDPManager.Map[s.XUDP.GlobalID] == s.XUDP && s.XUDP.Mux == s && s.XUDP.Status == Active {
			s.XUDP.Expire = time.Now().Add(time.Minute)
			s.XUDP.Status = Expiring
		}
		XUDPManager.Unlock()
	}
	if !s.server && s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
	if !s.server && s.inspection != nil {
		s.inspection.Finish()
	}
	return nil
}

// NewReader creates a buf.Reader based on the transfer type of this Session.
func (s *Session) NewReader(reader *buf.BufferedReader, dest *net.Destination) buf.Reader {
	if s.transferType == protocol.TransferTypeStream {
		return NewStreamReader(reader)
	}
	return NewPacketReader(reader, dest)
}

// finishServer releases the wire ID only after the old response writer (including
// END) has returned. A delayed old frame must not address a new same-ID child.
func (s *Session) finishServer() {
	s.Close(false)
	s.parent.Lock()
	if s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
	s.responseDone = true
	cleanup := s.takeCleanupLocked()
	s.parent.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

func (s *Session) finishAdmission() {
	s.parent.Lock()
	s.initializing = false
	cleanup := s.takeCleanupLocked()
	s.parent.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

func (s *Session) takeCleanupLocked() func() {
	if s.initializing || !s.responseDone {
		return nil
	}
	cleanup := s.cleanup
	s.cleanup = nil
	return cleanup
}
