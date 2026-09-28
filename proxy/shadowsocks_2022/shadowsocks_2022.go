package shadowsocks_2022

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type udpConnEntry struct {
	sync.RWMutex
	link      *transport.Link
	timer     *signal.ActivityTimer
	closed    bool
	cancel    context.CancelFunc
	onClose   func()
	receipt   stats.Exchange
	finish    func()
	transport stat.Connection
	peer      net.Addr
}

func (e *udpConnEntry) setTransport(conn stat.Connection) {
	e.Lock()
	e.transport, e.peer = conn, conn.RemoteAddr()
	e.Unlock()
}

func (e *udpConnEntry) setTimer(timer *signal.ActivityTimer) {
	e.Lock()
	e.timer = timer
	closed := e.closed
	e.Unlock()
	if closed {
		go timer.SetTimeout(0)
	}
}

func (e *udpConnEntry) writePacket(packet []byte) (int, error) {
	e.RLock()
	conn, peer := e.transport, e.peer
	e.RUnlock()
	if writer, ok := conn.(interface {
		WriteTo([]byte, net.Addr) (int, error)
	}); ok {
		return writer.WriteTo(packet, peer)
	}
	return conn.Write(packet)
}

func (e *udpConnEntry) setObservation(receipt stats.Exchange, finish func()) {
	e.Lock()
	e.receipt, e.finish = receipt, finish
	closed := e.closed
	e.Unlock()
	if closed && finish != nil {
		finish()
	}
}

func (e *udpConnEntry) isClosed() bool {
	e.RLock()
	closed := e.closed
	e.RUnlock()
	return closed
}

func (e *udpConnEntry) bind(link *transport.Link) bool {
	e.Lock()
	closed := e.closed
	if !closed {
		e.link = link
	}
	e.Unlock()
	if closed {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	return !closed
}

// Close retires one decoded association without closing its shared listener.
func (e *udpConnEntry) Close() error {
	e.Lock()
	if e.closed {
		e.Unlock()
		return nil
	}
	e.closed = true
	link, cancel, onClose, finish, timer := e.link, e.cancel, e.onClose, e.finish, e.timer
	e.Unlock()
	if link != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	if cancel != nil {
		cancel()
	}
	if onClose != nil {
		onClose()
	}
	if finish != nil {
		finish()
	}
	if timer != nil {
		// ActivityTimer invokes its callback under its own lock. Stop it only
		// after returning from that callback, including timer-driven Close.
		go timer.SetTimeout(0)
	}
	return nil
}

const (
	HeaderTypeClient              = 0
	HeaderTypeServer              = 1
	MaxPaddingLength              = 900
	PacketNonceSize               = 24
	MaxPacketSize                 = 65535
	RequestHeaderFixedChunkLength = 1 + 8 + 2 // Type (1B) + Timestamp (8B) + VarHeaderLen (2B)
	PacketMinimalHeaderSize       = 30
	StreamNonceSize               = 12
	AESBlockSize                  = 16
	AEADTagSize                   = 16
)

var zeroPadding [MaxPaddingLength]byte

const (
	MethodAES128GCM        = "2022-blake3-aes-128-gcm"
	MethodAES256GCM        = "2022-blake3-aes-256-gcm"
	MethodChaCha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

var (
	ErrBadKey            = errors.New("bad key")
	ErrBadHeaderType     = errors.New("bad header type")
	ErrBadTimestamp      = errors.New("bad timestamp")
	ErrSaltNotUnique     = errors.New("salt not unique")
	ErrPacketIdNotUnique = errors.New("packet id not unique")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrPacketTooLarge    = errors.New("packet too large")
	ErrNoPadding         = errors.New("bad request: missing payload or padding")
	ErrInvalidRequest    = errors.New("invalid request")
)
