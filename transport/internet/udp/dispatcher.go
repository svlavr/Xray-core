package udp

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
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type ResponseCallback func(ctx context.Context, packet *udp.Packet)

type connEntry struct {
	link      *transport.Link
	timer     *signal.ActivityTimer
	cancel    context.CancelFunc
	closed    atomic.Bool
	closeOnce sync.Once
}

func (c *connEntry) Close() error {
	c.timer.SetTimeout(0)
	c.terminate()
	return nil
}

func (c *connEntry) terminate() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.cancel()
		common.Interrupt(c.link.Reader)
		common.Interrupt(c.link.Writer)
	})
}

type Dispatcher struct {
	sync.RWMutex
	conn       *connEntry
	opening    *dispatcherOpening
	dispatcher routing.Dispatcher
	callback   ResponseCallback
	callClose  func() error
	closed     bool
	lifecycle  task.Lifecycle
	closeOnce  sync.Once
	closeDone  chan struct{}
}

type dispatcherOpening struct {
	done   chan struct{}
	cancel context.CancelFunc
}

func NewDispatcher(dispatcher routing.Dispatcher, callback ResponseCallback) *Dispatcher {
	return &Dispatcher{
		dispatcher: dispatcher,
		callback:   callback,
		closeDone:  make(chan struct{}),
	}
}

func (v *Dispatcher) RemoveRay() {
	v.SignalStop()
}

func (v *Dispatcher) SignalStop() {
	v.Lock()
	v.closed = true
	v.lifecycle.Seal()
	entry := v.conn
	opening := v.opening
	if v.conn != nil {
		v.conn = nil
	}
	v.Unlock()
	if opening != nil {
		opening.cancel()
	}
	if entry != nil {
		entry.terminate()
	}
}

func (v *Dispatcher) CloseAndWait() error {
	v.SignalStop()
	v.closeOnce.Do(func() {
		v.lifecycle.Wait()
		close(v.closeDone)
	})
	<-v.closeDone
	return nil
}

func (v *Dispatcher) getInboundRay(ctx context.Context, dest net.Destination) (*connEntry, error) {
	for {
		v.Lock()
		if v.closed {
			v.Unlock()
			return nil, errors.New("dispatcher is closed")
		}
		if v.conn != nil {
			if v.conn.closed.Load() {
				v.conn = nil
			} else {
				entry := v.conn
				v.Unlock()
				return entry, nil
			}
		}
		if v.opening != nil {
			opening := v.opening
			v.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-opening.done:
				continue
			}
		}
		if !v.lifecycle.Acquire() {
			v.Unlock()
			return nil, errors.New("dispatcher is closed")
		}
		dispatchCtx, cancel := context.WithCancel(ctx)
		opening := &dispatcherOpening{done: make(chan struct{}), cancel: cancel}
		v.opening = opening
		v.Unlock()

		errors.LogInfo(dispatchCtx, "establishing new connection for ", dest)
		link, err := v.dispatcher.Dispatch(dispatchCtx, dest)
		if err != nil {
			cancel()
			v.Lock()
			if v.opening == opening {
				v.opening = nil
				close(opening.done)
			}
			v.Unlock()
			v.lifecycle.Release()
			return nil, errors.New("failed to dispatch request to ", dest).Base(err)
		}
		entry := &connEntry{link: link, cancel: cancel}
		entry.timer = signal.CancelAfterInactivity(dispatchCtx, entry.terminate, time.Minute)
		v.Lock()
		if v.closed || v.opening != opening {
			if v.opening == opening {
				v.opening = nil
				close(opening.done)
			}
			v.Unlock()
			entry.terminate()
			v.lifecycle.Release()
			return nil, errors.New("dispatcher closed during connection publication")
		}
		v.conn = entry
		v.opening = nil
		close(opening.done)
		v.Unlock()
		go func() {
			defer v.lifecycle.Release()
			handleInput(dispatchCtx, entry, dest, v.callback, v.callClose)
		}()
		return entry, nil
	}
}

func (v *Dispatcher) Dispatch(ctx context.Context, destination net.Destination, payload *buf.Buffer) {
	// TODO: Add user to destString
	errors.LogDebug(ctx, "dispatch request to: ", destination)

	conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		payload.Release()
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		return
	}
	outputStream := conn.link.Writer
	if outputStream != nil {
		if err := outputStream.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to write first UDP payload")
			conn.Close()
			return
		}
	}
}

func handleInput(ctx context.Context, conn *connEntry, dest net.Destination, callback ResponseCallback, callClose func() error) {
	defer func() {
		conn.Close()
		if callClose != nil {
			callClose()
		}
	}()

	input := conn.link.Reader
	timer := conn.timer

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mb, err := input.ReadMultiBuffer()
		if err != nil {
			if !goerrors.Is(err, io.EOF) {
				errors.LogInfoInner(ctx, err, "failed to handle UDP input")
			}
			return
		}
		timer.Update()
		for _, b := range mb {
			if b.UDP != nil {
				dest = *b.UDP
			}
			callback(ctx, &udp.Packet{
				Payload: b,
				Source:  dest,
			})
		}
	}
}

type dispatcherConn struct {
	dispatcher *Dispatcher
	cache      chan *udp.Packet
	done       *done.Instance
	ctx        context.Context
	closeOnce  sync.Once
	closeErr   error
}

func DialDispatcher(ctx context.Context, dispatcher routing.Dispatcher) (net.PacketConn, error) {
	c := &dispatcherConn{
		cache: make(chan *udp.Packet, 16),
		done:  done.New(),
		ctx:   ctx,
	}

	d := &Dispatcher{
		dispatcher: dispatcher,
		callback:   c.callback,
		callClose:  c.closeSignal,
		closeDone:  make(chan struct{}),
	}
	c.dispatcher = d
	return c, nil
}

func (c *dispatcherConn) callback(ctx context.Context, packet *udp.Packet) {
	select {
	case <-c.done.Wait():
		packet.Payload.Release()
		return
	case c.cache <- packet:
	default:
		packet.Payload.Release()
		return
	}
}

func (c *dispatcherConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var packet *udp.Packet
s:
	select {
	case <-c.done.Wait():
		select {
		case packet = <-c.cache:
			break s
		default:
			return 0, nil, io.EOF
		}
	case packet = <-c.cache:
	}
	return copy(p, packet.Payload.Bytes()), &net.UDPAddr{
		IP:   packet.Source.Address.IP(),
		Port: int(packet.Source.Port),
	}, nil
}

func (c *dispatcherConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buffer := buf.New()
	raw := buffer.Extend(buf.Size)
	n := copy(raw, p)
	buffer.Resize(0, int32(n))

	destination := net.DestinationFromAddr(addr)
	buffer.UDP = &destination
	c.dispatcher.Dispatch(c.ctx, destination, buffer)
	return n, nil
}

func (c *dispatcherConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.closeSignal()
		c.closeErr = c.dispatcher.CloseAndWait()
	})
	return c.closeErr
}

func (c *dispatcherConn) closeSignal() error { return c.done.Close() }

func (c *dispatcherConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   []byte{0, 0, 0, 0},
		Port: 0,
	}
}

func (c *dispatcherConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetWriteDeadline(t time.Time) error {
	return nil
}
