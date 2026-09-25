package udp

import (
	"context"
	goerrors "errors"
	"io"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type ResponseCallback func(ctx context.Context, packet *udp.Packet)

type connEntry struct {
	link        *transport.Link
	timer       *signal.ActivityTimer
	cancel      context.CancelFunc
	closed      atomic.Bool
	observation *session.LogicalObservation
	done        chan struct{}
}

func (c *connEntry) Close() error {
	c.timer.SetTimeout(0)
	return nil
}

func (c *connEntry) terminate() {
	if c.closed.Swap(true) {
		panic("terminate called more than once")
	}
	c.cancel()
	common.Interrupt(c.link.Reader)
	common.Interrupt(c.link.Writer)
}

type Dispatcher struct {
	sync.RWMutex
	// Observation is the decoded association owner, set before the first
	// Dispatch. Each actual native ray captures a separate receipt binding.
	Observation stats.Exchange
	// InputAtExecution is set only for a caller-facing API association. Its
	// decoded uplink is credited when the selected handler consumes each ray.
	InputAtExecution bool
	conn             *connEntry
	dispatcher       routing.Dispatcher
	callback         ResponseCallback
	callClose        func() error
	closed           bool
}

func NewDispatcher(dispatcher routing.Dispatcher, callback ResponseCallback) *Dispatcher {
	return &Dispatcher{
		dispatcher: dispatcher,
		callback:   callback,
	}
}

func (v *Dispatcher) RemoveRay() {
	v.Lock()
	defer v.Unlock()
	v.closed = true
	if v.conn != nil {
		if observation := v.conn.observation; observation != nil && observation.ReturnedLink.CompareAndSwap(true, false) {
			observation.Exchange.Unassign()
			observation.Exchange.MarkUplinkIncomplete()
			observation.Exchange.MarkDownlinkIncomplete()
			observation.Exchange.Finish()
		}
		v.conn.Close()
		v.conn = nil
	}
}

// CloseAndWait terminates the owned ray and joins its input callback.
func (v *Dispatcher) CloseAndWait(ctx context.Context) error {
	v.Lock()
	v.closed = true
	conn := v.conn
	v.Unlock()
	if conn == nil {
		return nil
	}
	conn.Close()
	select {
	case <-conn.done:
		v.Lock()
		if v.conn == conn {
			v.conn = nil
		}
		v.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (v *Dispatcher) getInboundRay(ctx context.Context, dest net.Destination) (*connEntry, error) {
	v.Lock()
	defer v.Unlock()

	if v.closed {
		return nil, errors.New("dispatcher is closed")
	}

	if v.conn != nil {
		if v.conn.closed.Load() {
			v.conn = nil
		} else {
			return v.conn, nil
		}
	}

	errors.LogInfo(ctx, "establishing new connection for ", dest)

	ctx, cancel := context.WithCancel(ctx)
	// A retired ray may still finish while its replacement starts. Keep the
	// dispatcher/sniffer's mutable metadata local to this execution.
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) != 0 {
		outbounds = append([]*session.Outbound(nil), outbounds...)
		last := *outbounds[len(outbounds)-1]
		outbounds[len(outbounds)-1] = &last
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	if content := session.ContentFromContext(ctx); content != nil {
		local := *content
		local.Attributes = maps.Clone(content.Attributes)
		ctx = session.ContextWithContent(ctx, &local)
	}

	var observation *session.LogicalObservation
	if v.Observation != nil {
		leg := v.Observation.NewLeg()
		if leg == nil {
			cancel()
			return nil, io.ErrClosedPipe
		}
		observation = &session.LogicalObservation{Exchange: leg, InputAtExecution: v.InputAtExecution}
		observation.ReturnedLink.Store(true)
		ctx = session.ContextWithLogicalObservation(ctx, observation)
	}
	link, err := v.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		cancel()
		err = errors.New("failed to dispatch request to ", dest).Base(err)
		if observation != nil {
			observation.Exchange.Route(stats.RouteStep{Selection: stats.SelectionRejected, Original: dest, SelectedTarget: dest})
			observation.Exchange.BindRoute()
			observation.Exchange.SetEndReason(stats.EndReasonRejected)
			observation.Exchange.Finish()
			return &connEntry{observation: observation}, err
		}
		return nil, err
	}

	entry := &connEntry{
		link:        link,
		cancel:      cancel,
		observation: observation,
		done:        make(chan struct{}),
	}

	entry.timer = signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)
	v.conn = entry
	go handleInput(ctx, entry, dest, v.callback, v.callClose)
	return entry, nil
}

func (v *Dispatcher) Dispatch(ctx context.Context, destination net.Destination, payload *buf.Buffer) {
	// TODO: Add user to destString
	errors.LogDebug(ctx, "dispatch request to: ", destination)

	conn, err := v.getInboundRay(ctx, destination)
	if conn != nil && conn.observation != nil && !v.InputAtExecution {
		flow := conn.observation.Exchange
		packetDestination := destination
		if payload.UDP != nil {
			packetDestination = *payload.UDP
		}
		flow.PacketDestination(packetDestination)
		flow.AddUplink(uint64(payload.Len()))
	}
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		payload.Release()
		return
	}
	outputStream := conn.link.Writer
	if outputStream != nil {
		if err := outputStream.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to write first UDP payload")
			conn.Close()
			return
		}
	} else {
		payload.Release()
	}
}

func handleInput(ctx context.Context, conn *connEntry, dest net.Destination, callback ResponseCallback, callClose func() error) {
	defer func() {
		conn.Close()
		if callClose != nil {
			callClose()
		}
		if conn.observation != nil {
			if conn.observation.ReturnedLink.Load() {
				conn.observation.Exchange.Unassign()
				conn.observation.Exchange.MarkUplinkIncomplete()
				conn.observation.Exchange.MarkDownlinkIncomplete()
			}
			conn.observation.Exchange.Finish()
		}
		if conn.done != nil {
			close(conn.done)
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
		if err != nil {
			if !goerrors.Is(err, io.EOF) {
				errors.LogInfoInner(ctx, err, "failed to handle UDP input")
			}
			return
		}
	}
}

type dispatcherConn struct {
	dispatcher  *Dispatcher
	cache       chan dispatcherPacket
	done        *done.Instance
	ctx         context.Context
	observation stats.Exchange
	mu          sync.Mutex
	closed      bool
	finish      sync.Once
}

type dispatcherPacket struct {
	packet  *udp.Packet
	receipt stats.Exchange
}

func DialDispatcher(ctx context.Context, dispatcher routing.Dispatcher) (net.PacketConn, error) {
	c := &dispatcherConn{
		cache: make(chan dispatcherPacket, 16),
		done:  done.New(),
		ctx:   ctx,
	}

	d := &Dispatcher{
		dispatcher: dispatcher,
		callback:   c.callback,
		callClose:  c.endRay,
	}
	if observation := session.LogicalObservationFromContext(ctx); observation != nil && observation.ReturnedLink.CompareAndSwap(true, false) {
		d.Observation = observation.Exchange
		d.InputAtExecution = observation.InputAtExecution
		c.observation = observation.Exchange
	}
	c.dispatcher = d
	return c, nil
}

func (c *dispatcherConn) callback(ctx context.Context, packet *udp.Packet) {
	var receipt stats.Exchange
	if observation := session.LogicalObservationFromContext(ctx); observation != nil {
		receipt = observation.Exchange
	}
	c.mu.Lock()
	if c.closed {
		if receipt != nil {
			receipt.MarkDownlinkIncomplete()
		}
		packet.Payload.Release()
		c.mu.Unlock()
		return
	}
	select {
	case c.cache <- dispatcherPacket{packet: packet, receipt: receipt}:
	default:
		if receipt != nil {
			receipt.MarkDownlinkIncomplete()
		}
		packet.Payload.Release()
	}
	c.mu.Unlock()
}

func (c *dispatcherConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var cached dispatcherPacket
	for {
		select {
		case cached = <-c.cache:
			goto packet
		default:
		}
		if c.done.Done() {
			c.finishRoot()
			return 0, nil, io.EOF
		}
		select {
		case cached = <-c.cache:
			goto packet
		case <-c.done.Wait():
		}
	}

packet:
	packet := cached.packet
	c.mu.Lock()
	if c.closed {
		if cached.receipt != nil {
			cached.receipt.MarkDownlinkIncomplete()
		}
		packet.Payload.Release()
		c.mu.Unlock()
		return 0, nil, io.EOF
	}
	n := copy(p, packet.Payload.Bytes())
	source := packet.Source
	if cached.receipt != nil && n > 0 {
		cached.receipt.AddDownlink(uint64(n))
	}
	packet.Payload.Release()
	c.mu.Unlock()
	return n, &net.UDPAddr{
		IP:   source.Address.IP(),
		Port: int(source.Port),
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
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	for {
		select {
		case cached := <-c.cache:
			if cached.receipt != nil {
				cached.receipt.MarkDownlinkIncomplete()
			}
			cached.packet.Payload.Release()
		default:
			c.mu.Unlock()
			c.dispatcher.RemoveRay()
			err := c.done.Close()
			c.finishRoot()
			return err
		}
	}
}

func (c *dispatcherConn) endRay() error {
	c.dispatcher.RemoveRay()
	return c.done.Close()
}

func (c *dispatcherConn) finishRoot() {
	if c.observation != nil {
		c.finish.Do(c.observation.Finish)
	}
}

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
