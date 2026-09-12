package udphop

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	"math"
	mrand "math/rand"
	gonet "net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

var pool = sync.Pool{
	New: func() any {
		return make([]byte, finalmask.UDPSize)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
	err  error
}

type udpHopConn struct {
	ctx        context.Context
	cancel     context.CancelFunc
	conn       net.PacketConn
	localAddr  net.Addr
	dial       func(context.Context, net.Destination, *internet.SocketConfig) (net.Conn, error)
	sockopt    *internet.SocketConfig
	local      bool
	remote     bool
	remoteOnce bool

	intervalMin int64
	intervalMax int64
	remotePorts []uint32
	remoteIPs   []netip.Prefix

	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	pre         net.PacketConn
	cur         net.PacketConn
	addr        *net.UDPAddr
	readCh      chan packet
	closeCh     chan struct{}
	closeDone   chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	rotationMu  sync.Mutex
	signalOnce  sync.Once
	closeOnce   sync.Once
	closeErr    error
	closeErrors []error
	unregister  func()
	closing     bool
}

func NewUDPHopConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewUDPHopConnContext(context.Background(), c, raw)
}

func NewUDPHopConnContext(ctx context.Context, c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if c == nil || raw == nil {
		return nil, errors.New("udphop requires config and packet connection")
	}
	maxIntervalSeconds := int64(math.MaxInt64/int64(time.Second)) - 1
	if c.IntervalMin < 5 || c.IntervalMax < c.IntervalMin || c.IntervalMax > maxIntervalSeconds {
		return nil, errors.New("invalid interval")
	}
	remoteIPs := make([]netip.Prefix, 0, len(c.RemoteIPs))
	for _, ip := range c.RemoteIPs {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, errors.New("invalid remote prefix: ", ip).Base(err)
		}
		remoteIPs = append(remoteIPs, prefix)
	}
	for _, port := range c.RemotePorts {
		if port > math.MaxUint16 {
			return nil, errors.New("invalid remote port: ", port)
		}
	}
	owner := internet.ResourceLifecycleFromContext(ctx)
	ownerCtx := ctx
	if owner != nil {
		ownerCtx = owner.Context()
	}
	ownerCtx, cancel := context.WithCancel(ownerCtx)
	conn := &udpHopConn{
		ctx:        ownerCtx,
		cancel:     cancel,
		conn:       raw,
		localAddr:  raw.LocalAddr(),
		dial:       internet.DialSystem,
		sockopt:    c.Sockopt,
		local:      c.Local,
		remote:     c.Remote,
		remoteOnce: c.RemoteOnce,

		intervalMin: c.IntervalMin,
		intervalMax: c.IntervalMax,
		remotePorts: c.RemotePorts,
		remoteIPs:   remoteIPs,

		readCh:    make(chan packet),
		closeCh:   make(chan struct{}),
		closeDone: make(chan struct{}),
		cur:       raw,
	}
	if owner != nil {
		err := owner.RegisterBound(conn, func(unregister func()) {
			conn.unregister = unregister
		})
		if err != nil {
			cancel()
			return nil, err
		}
	}
	conn.wg.Add(2)
	go conn.recv(raw)
	go conn.hopLoop()
	return conn, nil
}

func (c *udpHopConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *udpHopConn) hop(addr *net.UDPAddr) error {
	if addr == nil {
		return nil
	}
	c.rotationMu.Lock()
	defer c.rotationMu.Unlock()
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return gonet.ErrClosed
	}
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	newAddr := &net.UDPAddr{IP: addr.IP, Port: addr.Port}
	var newConn net.PacketConn
	if c.remote || c.remoteOnce && c.addr == nil {
		if len(c.remotePorts) > 0 {
			newAddr.Port = int(c.remotePorts[mrand.Intn(len(c.remotePorts))])
		}
		if len(c.remoteIPs) > 0 {
			newAddr.IP = randPrefix(c.remoteIPs[mrand.Intn(len(c.remoteIPs))])
		}
	}
	if c.local {
		raw, err := c.dial(c.ctx, net.UDPDestination(net.IPAddress(newAddr.IP), net.Port(newAddr.Port)), c.sockopt)
		if err != nil {
			return errors.New("hop dial failed").Base(err)
		}
		newConn, _, err = internet.PacketConnView(raw)
		if err != nil {
			_ = raw.Close()
			return err
		}
		c.mu.Lock()
		deadline, readDeadline, writeDeadline := c.deadline, c.readDeadline, c.writeDeadline
		c.mu.Unlock()
		if err := newConn.SetDeadline(deadline); err != nil {
			_ = newConn.Close()
			return err
		}
		_ = newConn.SetReadDeadline(readDeadline)
		_ = newConn.SetWriteDeadline(writeDeadline)
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		if newConn != nil {
			_ = newConn.Close()
		}
		return gonet.ErrClosed
	}
	oldPre := c.pre
	if c.local {
		c.pre = c.cur
		c.cur = newConn
		c.wg.Add(1)
	}
	c.addr = newAddr
	c.mu.Unlock()
	if oldPre != nil {
		_ = oldPre.Close()
	}
	if newConn != nil {
		go c.recv(newConn)
	}
	return nil
}

func (c *udpHopConn) recv(conn net.PacketConn) {
	defer c.wg.Done()

	for {
		if c.closed() {
			return
		}
		p := pool.Get().([]byte)
		n, addr, err := conn.ReadFrom(p)
		if err != nil {
			pool.Put(p[:cap(p)])
			if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, gonet.ErrClosed) {
				break
			}
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{err: err}:
				case <-c.closeCh:
					return
				}
			}
			errors.LogErrorInner(context.Background(), err, "recv err")
			continue
		}
		select {
		case c.readCh <- packet{p: p[:n], addr: addr}:
		case <-c.closeCh:
			pool.Put(p[:cap(p)])
			return
		}
	}
}

func (c *udpHopConn) hopLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ticker.Reset(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
			c.mu.Lock()
			addr := c.addr
			c.mu.Unlock()
			if err := c.hop(addr); err != nil && !goerrors.Is(err, gonet.ErrClosed) && !goerrors.Is(err, context.Canceled) {
				errors.LogErrorInner(c.ctx, err, "hop err")
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *udpHopConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.readCh:
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p[:cap(packet.p)])
		}
		return n, packet.addr, packet.err
	case <-c.closeCh:
		return 0, nil, io.EOF
	}
}

func (c *udpHopConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return 0, errors.New("udphop requires UDP destination")
	}
	c.mu.Lock()
	first := c.addr == nil
	closing := c.closing
	c.mu.Unlock()
	if closing {
		return 0, gonet.ErrClosed
	}
	if first {
		if err := c.hop(udpAddr); err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	if c.closing || c.cur == nil || c.addr == nil {
		c.mu.Unlock()
		return 0, gonet.ErrClosed
	}
	current, target := c.cur, c.addr
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	_, err = current.WriteTo(p, target)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
		return 0, err
	}
	return len(p), nil
}

func (c *udpHopConn) Close() error {
	c.SignalStop()
	c.closeOnce.Do(func() {
		c.wg.Wait()
		for {
			select {
			case pending := <-c.readCh:
				if pending.p != nil {
					pool.Put(pending.p[:cap(pending.p)])
				}
			default:
				c.mu.Lock()
				c.sockopt = nil
				c.dial = nil
				c.remoteIPs = nil
				c.remotePorts = nil
				c.ctx = nil
				c.closeErr = errors.Combine(c.closeErrors...)
				unregister := c.unregister
				c.unregister = nil
				c.mu.Unlock()
				if unregister != nil {
					unregister()
				}
				close(c.closeDone)
				return
			}
		}
	})
	<-c.closeDone
	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()
	return err
}

// SignalStop seals work and starts lower I/O closure without joining it.
func (c *udpHopConn) SignalStop() {
	if c == nil {
		return
	}
	c.signalOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		close(c.closeCh)
		connections := uniquePacketConns(c.conn, c.pre, c.cur)
		c.conn, c.pre, c.cur = nil, nil, nil
		cancel := c.cancel
		c.wg.Add(len(connections))
		c.mu.Unlock()
		cancel()
		for _, connection := range connections {
			go func() {
				defer c.wg.Done()
				if err := connection.Close(); err != nil {
					c.mu.Lock()
					c.closeErrors = append(c.closeErrors, err)
					c.mu.Unlock()
				}
			}()
		}
	})
}

func uniquePacketConns(connections ...net.PacketConn) []net.PacketConn {
	unique := make([]net.PacketConn, 0, len(connections))
	for _, connection := range connections {
		if connection == nil {
			continue
		}
		duplicate := false
		for _, existing := range unique {
			connectionType := reflect.TypeOf(connection)
			if connectionType == reflect.TypeOf(existing) && connectionType.Comparable() && existing == connection {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, connection)
		}
	}
	return unique
}

func (c *udpHopConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpHopConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	connections := uniquePacketConns(c.pre, c.cur)
	c.mu.Unlock()
	var setErrors []error
	for _, connection := range connections {
		setErrors = append(setErrors, connection.SetDeadline(t))
	}
	return errors.Combine(setErrors...)
}

func (c *udpHopConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	connections := uniquePacketConns(c.pre, c.cur)
	c.mu.Unlock()
	var setErrors []error
	for _, connection := range connections {
		setErrors = append(setErrors, connection.SetReadDeadline(t))
	}
	return errors.Combine(setErrors...)
}

func (c *udpHopConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	connections := uniquePacketConns(c.pre, c.cur)
	c.mu.Unlock()
	var setErrors []error
	for _, connection := range connections {
		setErrors = append(setErrors, connection.SetWriteDeadline(t))
	}
	return errors.Combine(setErrors...)
}

func randPrefix(p netip.Prefix) []byte {
	if p.IsSingleIP() {
		return p.Addr().AsSlice()
	}
	b := p.Addr().AsSlice()
	prefix := p.Bits()
	var new [16]byte
	common.Must2(rand.Read(new[:len(b)]))
	i := prefix / 8
	j := prefix % 8
	if i+1 < len(b) {
		copy(b[i+1:], new[i+1:])
	}
	mask := byte(0xff << (8 - j))
	b[i] = (b[i] & mask) | (new[i] &^ mask)
	return b
}
