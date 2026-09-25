package udpnat

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type Handler interface {
	N.UDPConnectionHandler
	E.Handler
}

type Service[K comparable] struct {
	nat     *cache.LruCache[K, *conn]
	handler Handler
}

func New[K comparable](maxAge int64, handler Handler) *Service[K] {
	return &Service[K]{
		nat: cache.New(
			cache.WithAge[K, *conn](maxAge),
			cache.WithUpdateAgeOnGet[K, *conn](),
			cache.WithEvict[K, *conn](func(key K, conn *conn) {
				conn.Close()
			}),
		),
		handler: handler,
	}
}

func (s *Service[T]) WriteIsThreadUnsafe() {
}

func (s *Service[T]) NewPacketDirect(ctx context.Context, key T, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) {
	s.NewContextPacket(ctx, key, buffer, metadata, func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return ctx, &DirectBackWriter{conn, natConn}
	})
}

type DirectBackWriter struct {
	Source N.PacketConn
	Nat    N.PacketConn
}

func (w *DirectBackWriter) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	return w.Source.WritePacket(buffer, M.SocksaddrFromNet(w.Nat.LocalAddr()))
}

func (w *DirectBackWriter) Upstream() any {
	return w.Source
}

func (s *Service[T]) NewPacket(ctx context.Context, key T, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) N.PacketWriter) {
	s.NewContextPacket(ctx, key, buffer, metadata, func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return ctx, init(natConn)
	})
}

func (s *Service[T]) NewContextPacket(ctx context.Context, key T, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) (context.Context, N.PacketWriter)) {
	for {
		if common.Done(ctx) {
			buffer.Release()
			return
		}
		c, loaded := s.nat.LoadOrStore(key, func() *conn {
			c := &conn{
				data:         make(chan packet, 64),
				ready:        make(chan struct{}),
				localAddr:    metadata.Source,
				remoteAddr:   metadata.Destination,
				readDeadline: pipe.MakeDeadline(),
			}
			c.ctx, c.cancel = common.ContextWithCancelCause(ctx)
			return c
		})
		if !loaded {
			callbackContext, source := init(c)
			c.metadataAccess.Lock()
			c.source = source
			c.metadataAccess.Unlock()
			close(c.ready)
			if common.Done(c.ctx) {
				buffer.Release()
				c.Close()
				s.nat.DeleteIf(key, func(current *conn) bool { return current == c })
				return
			}
			go func() {
				err := s.handler.NewPacketConnection(callbackContext, c, metadata)
				if err != nil {
					s.handler.NewError(callbackContext, err)
				}
				c.Close()
				s.nat.DeleteIf(key, func(current *conn) bool { return current == c })
			}()
			// Retain native startup ordering and capacity: init may already have
			// enqueued packets through same-key reentry. A rejected callback
			// cancels this enqueue; it does not retry the packet indefinitely.
			c.enqueue(packet{data: buffer, destination: metadata.Destination})
			return
		}
		// Loaded ingress needs only the initialized queue/context, not source
		// publication. In particular, init may re-enter this method for its key.
		if common.Done(c.ctx) {
			s.nat.DeleteIf(key, func(current *conn) bool { return current == c })
			continue
		}
		c.metadataAccess.Lock()
		c.localAddr = metadata.Source
		c.metadataAccess.Unlock()
		c.enqueue(packet{
			data:        buffer,
			destination: metadata.Destination,
		})
		return
	}
}

// enqueue owns the packet on both success and cancellation. Close cancels before
// joining this critical section, so a full queue cannot keep ingress blocked.
func (c *conn) enqueue(p packet) bool {
	c.enqueueAccess.Lock()
	defer c.enqueueAccess.Unlock()
	if !common.Done(c.ctx) {
		select {
		case c.data <- p:
			return true
		case <-c.ctx.Done():
		}
	}
	p.data.Release()
	return false
}

type packet struct {
	data        *buf.Buffer
	destination M.Socksaddr
}

var _ N.PacketConn = (*conn)(nil)

type conn struct {
	ctx             context.Context
	cancel          common.ContextCancelCauseFunc
	data            chan packet
	localAddr       M.Socksaddr
	remoteAddr      M.Socksaddr
	source          N.PacketWriter
	readDeadline    pipe.Deadline
	readWaitOptions N.ReadWaitOptions
	ready           chan struct{}
	metadataAccess  sync.RWMutex
	enqueueAccess   sync.Mutex
	sourceCloseOnce sync.Once
	sourceCloseErr  error
}

func (c *conn) ReadPacket(buffer *buf.Buffer) (addr M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		length := p.data.Len()
		var n int
		n, err = buffer.ReadOnceFrom(p.data)
		if err == nil && n != length {
			err = io.ErrShortBuffer
		}
		p.data.Release()
		return p.destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *conn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.source.WritePacket(buffer, destination)
}

func (c *conn) Close() error {
	c.cancel(net.ErrClosed)
	c.enqueueAccess.Lock()
	for {
		select {
		case p := <-c.data:
			p.data.Release()
		default:
			c.enqueueAccess.Unlock()
			goto drained
		}
	}
drained:
	select {
	case <-c.ready:
		c.sourceCloseOnce.Do(func() {
			if sourceCloser, ok := c.source.(io.Closer); ok {
				c.sourceCloseErr = sourceCloser.Close()
			}
		})
		return c.sourceCloseErr
	default:
		// The initializer observes cancellation before publishing its callback
		// and calls Close again after publishing the source.
		return nil
	}
}

func (c *conn) LocalAddr() net.Addr {
	c.metadataAccess.RLock()
	defer c.metadataAccess.RUnlock()
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *conn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *conn) Upstream() any {
	c.metadataAccess.RLock()
	defer c.metadataAccess.RUnlock()
	return c.source
}
