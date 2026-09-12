package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	numPadding          = 3
	numPaddingForPoll   = 8
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsConnClient struct {
	net.PacketConn

	resolverAddrs []*net.UDPAddr
	resolverTypes []uint16
	resolverIdx   uint32
	resolverSend  map[string]*atomic.Uint32

	clientID []byte
	domains  []Name

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	ctx    context.Context
	cancel context.CancelFunc
	tasks  task.Lifecycle

	closed       atomic.Bool
	mutex        sync.Mutex
	stopOnce     sync.Once
	rawCloseOnce sync.Once
	closeOnce    sync.Once
	rawCloseDone chan struct{}
	closeDone    chan struct{}
	rawCloseErr  error
	closeErr     error
	unregister   func()
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClientContext(context.Background(), c, raw)
}

func NewConnClientContext(ctx context.Context, c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Resolvers) == 0 {
		return nil, errors.New("empty resolvers")
	}

	var domains []Name
	var servers []string
	var resolverTypes []uint16
	for _, rs := range c.Resolvers {
		domain, server, resolverType, err := parseResolver(rs)
		if err != nil {
			return nil, errors.New("invalid resolvers").Base(err)
		}
		domains = append(domains, domain)
		servers = append(servers, server)
		resolverTypes = append(resolverTypes, resolverType)
	}

	var resolverAddrs []*net.UDPAddr
	resolverSend := make(map[string]*atomic.Uint32)
	for _, rs := range servers {
		h, p, err := net.SplitHostPort(rs)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(h)
		if ip == nil {
			return nil, errors.New("invalid ip address")
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, errors.New("invalid port").Base(err)
		}
		addr := &net.UDPAddr{IP: ip, Port: port}
		resolverAddrs = append(resolverAddrs, addr)
		resolverSend[addr.String()] = &atomic.Uint32{}
	}

	owner := internet.ResourceLifecycleFromContext(ctx)
	parentCtx := ctx
	if owner != nil {
		parentCtx = owner.Context()
	}
	connCtx, cancel := context.WithCancel(parentCtx)
	conn := &xdnsConnClient{
		PacketConn: raw,

		resolverAddrs: resolverAddrs,
		resolverTypes: resolverTypes,
		resolverIdx:   0,
		resolverSend:  resolverSend,

		clientID: make([]byte, 8),
		domains:  domains,

		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, 256),
		writeQueue: make(chan *packet, 256),
		ctx:        connCtx,
		cancel:     cancel,

		rawCloseDone: make(chan struct{}),
		closeDone:    make(chan struct{}),
	}

	common.Must2(rand.Read(conn.clientID))
	for range 3 {
		if !conn.tasks.Acquire() {
			panic("fresh xdns client lifecycle rejected loop reservation")
		}
	}
	if owner != nil {
		if err := owner.RegisterBound(conn, func(unregister func()) { conn.unregister = unregister }); err != nil {
			conn.tasks.Seal()
			for range 3 {
				conn.tasks.Release()
			}
			cancel()
			return nil, err
		}
	}

	go func() {
		defer conn.tasks.Release()
		<-connCtx.Done()
		if parentCtx.Err() != nil {
			conn.SignalStop()
		}
	}()
	go func() {
		defer conn.tasks.Release()
		conn.recvLoop()
	}()
	go func() {
		defer conn.tasks.Release()
		conn.sendLoop()
	}()

	return conn, nil
}

func (c *xdnsConnClient) recvLoop() {
	var buf [finalmask.UDPSize]byte

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if c.ctx.Err() != nil || go_errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}

		if addr == nil {
			continue
		}

		send := c.resolverSend[addr.String()]
		if send == nil {
			continue
		}

		resp, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domains)

		r := bytes.NewReader(payload)
		anyPacket := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			anyPacket = true

			buf := make([]byte, len(p))
			copy(buf, p)
			select {
			case c.readQueue <- &packet{
				p:    buf,
				addr: addr,
			}:
			case <-c.ctx.Done():
				return
			default:
				errors.LogDebug(context.Background(), addr, " mask read err queue full")
			}
		}

		if anyPacket {
			send.Store(0)
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}

	errors.LogDebug(context.Background(), "xdns closed")
}

func (c *xdnsConnClient) sendLoop() {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
	for {
		var p *packet
		pollTimerExpired := false

		select {
		case p = <-c.writeQueue:
		case <-c.ctx.Done():
			return
		default:
			select {
			case p = <-c.writeQueue:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			case <-c.ctx.Done():
				return
			}
		}

		if p != nil {
			select {
			case <-c.pollChan:
			case <-c.ctx.Done():
				return
			default:
			}
		} else {
			c.mutex.Lock()
			idx := c.resolverIdx
			domain, resolverType := c.domains[idx], c.resolverTypes[idx]
			c.mutex.Unlock()
			encoded, _ := encode(nil, c.clientID, domain, resolverType)
			p = &packet{
				p: encoded,
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if c.closed.Load() {
			return
		}

		c.mutex.Lock()
		cur := c.resolverIdx
		curSend := c.resolverSend[c.resolverAddrs[cur].String()].Add(1)
		resolverAddr := c.resolverAddrs[cur]
		for {
			c.resolverIdx += 1
			c.resolverIdx %= uint32(len(c.resolverAddrs))
			if c.resolverIdx == cur {
				break
			}
			if c.resolverSend[c.resolverAddrs[c.resolverIdx].String()].Load() < curSend {
				break
			}
		}
		c.mutex.Unlock()
		_, _ = c.PacketConn.WriteTo(p.p, resolverAddr)
	}
}

func (c *xdnsConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	var packet *packet
	var ok bool
	select {
	case packet, ok = <-c.readQueue:
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.closeDone:
		return 0, nil, net.ErrClosed
	}
	if !ok || packet == nil {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(packet.p) {
		errors.LogDebug(context.Background(), packet.addr, " mask read err short buffer ", len(p), " ", len(packet.p))
		return 0, packet.addr, nil
	}
	copy(p, packet.p)
	return len(packet.p), packet.addr, nil
}

func (c *xdnsConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	idx := c.resolverIdx % uint32(len(c.resolverAddrs))
	encoded, err := encode(p, c.clientID, c.domains[idx], c.resolverTypes[idx])
	if err != nil {
		errors.LogDebug(context.Background(), addr, " xdns wireformat err ", err, " ", len(p))
		return 0, nil
	}

	select {
	case c.writeQueue <- &packet{
		p:    encoded,
		addr: addr,
	}:
		return len(p), nil
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	default:
		errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, nil
	}
}

func (c *xdnsConnClient) SignalStop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.closed.Store(true)
		c.tasks.Seal()
		c.cancel()
		c.rawCloseOnce.Do(func() {
			go func() {
				err := c.PacketConn.Close()
				c.mutex.Lock()
				c.rawCloseErr = err
				c.mutex.Unlock()
				close(c.rawCloseDone)
			}()
		})
	})
}

func (c *xdnsConnClient) Close() error {
	c.SignalStop()
	c.closeOnce.Do(func() {
		<-c.rawCloseDone
		c.tasks.Wait()
		close(c.readQueue)
		c.mutex.Lock()
		c.closeErr = c.rawCloseErr
		unregister := c.unregister
		c.unregister = nil
		c.mutex.Unlock()
		if unregister != nil {
			unregister()
		}
		close(c.closeDone)
	})
	<-c.closeDone
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.closeErr
}

func encode(p []byte, clientID []byte, domain Name, qtype uint16) ([]byte, error) {
	var decoded []byte
	{
		if len(p) >= 224 {
			return nil, errors.New("too long")
		}
		var buf bytes.Buffer
		buf.Write(clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		buf.WriteByte(byte(224 + n))
		_, _ = io.CopyN(&buf, rand.Reader, int64(n))
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, domain...)
	name, err := NewName(labels)
	if err != nil {
		return nil, err
	}

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &Message{
		ID:    id,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  name,
				Type:  qtype,
				Class: ClassIN,
			},
		},
		Additional: []RR{
			{
				Name:  Name{},
				Type:  RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}

	buf, err := query.WireFormat()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

func dnsResponsePayload(resp *Message, domains []Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != RcodeNoError {
		return nil
	}

	if len(resp.Answer) == 0 {
		return nil
	}

	for _, answer := range resp.Answer {
		var ok bool
		for _, domain := range domains {
			_, ok = answer.Name.TrimSuffix(domain)
			if ok {
				break
			}
		}
		if !ok {
			return nil
		}
	}

	return decodeResponsePayload(resp.Answer)
}
