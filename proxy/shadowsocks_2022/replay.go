package shadowsocks_2022

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/utils"
)

const (
	swBlockBitLog = 6                                // 1<<6 == 64 bits
	swBlockBits   = 1 << swBlockBitLog               // 64
	swRingBlocks  = 1 << 7                           // 128
	swBlockMask   = swRingBlocks - 1                 // 127
	swBitMask     = swBlockBits - 1                  // 63
	swSize        = (swRingBlocks - 1) * swBlockBits // 8128
)

type SlidingWindow struct {
	last uint64
	ring [swRingBlocks]uint64
}

func (f *SlidingWindow) Reset() {
	*f = SlidingWindow{}
}

func (f *SlidingWindow) Check(counter uint64) bool {
	switch {
	case counter > f.last:
		return true
	case f.last-counter > swSize:
		return false
	}

	blockIndex := (counter >> swBlockBitLog) & swBlockMask
	bitIndex := counter & swBitMask
	return (f.ring[blockIndex]>>bitIndex)&1 == 0
}

func (f *SlidingWindow) Add(counter uint64) {
	blockIndex := counter >> swBlockBitLog

	if counter > f.last {
		lastBlockIndex := f.last >> swBlockBitLog
		diff := int(blockIndex - lastBlockIndex)
		if diff > swRingBlocks {
			diff = swRingBlocks
		}

		for i := 0; i < diff; i++ {
			lastBlockIndex = (lastBlockIndex + 1) & swBlockMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter
	}

	blockIndex &= swBlockMask
	bitIndex := counter & swBitMask
	f.ring[blockIndex] |= 1 << bitIndex
}

func (f *SlidingWindow) CheckAndAdd(counter uint64) bool {
	if !f.Check(counter) {
		return false
	}
	f.Add(counter)
	return true
}

type ServerUDPSession struct {
	sync.Mutex
	RemoteCipher atomic.Pointer[cipher.AEAD]
	Window       SlidingWindow
	LastActive   atomic.Int64 // Unix timestamp in seconds

	ServerSessionID   uint64
	ServerPacketID    atomic.Uint64
	serverBodyCipher  cipher.AEAD
	serverHeaderBlock cipher.Block
	serverChaCha      cipher.AEAD
}

func (s *ServerUDPSession) GetRemoteCipher() cipher.AEAD {
	ptr := s.RemoteCipher.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

func (s *ServerUDPSession) SetRemoteCipher(c cipher.AEAD) {
	s.RemoteCipher.Store(&c)
}

type UDPSessionManager[K comparable] struct {
	sessions  *utils.TypedSyncMap[K, *ServerUDPSession]
	timeout   time.Duration
	lastClean atomic.Int64 // Unix timestamp in seconds
}

func NewUDPSessionManager[K comparable](timeout time.Duration) *UDPSessionManager[K] {
	return &UDPSessionManager[K]{
		sessions: utils.NewTypedSyncMap[K, *ServerUDPSession](),
		timeout:  timeout,
	}
}

func (m *UDPSessionManager[K]) GetOrCreate(key K) *ServerUDPSession {
	now := time.Now().Unix()
	if s, ok := m.sessions.Load(key); ok {
		s.LastActive.Store(now)
		return s
	}

	s := new(ServerUDPSession)
	s.LastActive.Store(now)

	actual, loaded := m.sessions.LoadOrStore(key, s)
	if loaded {
		actual.LastActive.Store(now)
		return actual
	}

	// Trigger cleanup if at least 30 seconds have passed since last cleanup
	last := m.lastClean.Load()
	if now-last > 30 && m.lastClean.CompareAndSwap(last, now) {
		go m.cleanup(now)
	}

	return s
}

func (m *UDPSessionManager[K]) cleanup(now int64) {
	timeoutSec := int64(m.timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	m.sessions.Range(func(k K, v *ServerUDPSession) bool {
		if now-v.LastActive.Load() > timeoutSec {
			m.sessions.CompareAndDelete(k, v)
		}
		return true
	})
}

func (m *UDPSessionManager[K]) Delete(key K) {
	m.sessions.Delete(key)
}
