package xdns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	idleTimeout      = 10 * time.Second
	responseTTL      = 60
	maxResponseDelay = 1 * time.Second
)

var (
	maxUDPPayload         = 1280 - 40 - 8
	maxEncodedPayloadTXT  = computeMaxEncodedPayloadForType(maxUDPPayload, RRTypeTXT)
	maxEncodedPayloadA    = computeMaxEncodedPayloadForType(maxUDPPayload, RRTypeA)
	maxEncodedPayloadAAAA = computeMaxEncodedPayloadForType(maxUDPPayload, RRTypeAAAA)
)

func clientIDToAddr(clientID [8]byte) *net.UDPAddr {
	ip := make(net.IP, 16)

	copy(ip, []byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0})
	copy(ip[8:], clientID[:])

	return &net.UDPAddr{
		IP: ip,
	}
}

type record struct {
	Resp *Message
	Addr net.Addr
	// ClientID [8]byte
	ClientAddr net.Addr
}

type queue struct {
	key        string
	last       time.Time
	rrType     uint16
	queue      chan []byte
	stash      chan []byte
	retired    bool
	retireDone chan struct{}
}

type xdnsConnServer struct {
	net.PacketConn

	domains []domainSpec

	ch            chan *record
	readQueue     chan *packet
	writeQueueMap map[string]*queue

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

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnServerContext(context.Background(), c, raw)
}

func NewConnServerContext(ctx context.Context, c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
	}
	domains := make([]domainSpec, 0, len(c.Domains))
	for _, domain := range c.Domains {
		domain, err := parseDomainSpec(domain, "")
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}

	owner := internet.ResourceLifecycleFromContext(ctx)
	parentCtx := ctx
	if owner != nil {
		parentCtx = owner.Context()
	}
	connCtx, cancel := context.WithCancel(parentCtx)
	conn := &xdnsConnServer{
		PacketConn: raw,

		domains: domains,

		ch:            make(chan *record, 500),
		readQueue:     make(chan *packet, 512),
		writeQueueMap: make(map[string]*queue),
		ctx:           connCtx,
		cancel:        cancel,

		rawCloseDone: make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
	for range 4 {
		if !conn.tasks.Acquire() {
			panic("fresh xdns server lifecycle rejected loop reservation")
		}
	}
	if owner != nil {
		if err := owner.RegisterBound(conn, func(unregister func()) { conn.unregister = unregister }); err != nil {
			conn.tasks.Seal()
			for range 4 {
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
		conn.clean()
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

func (c *xdnsConnServer) clean() {
	timer := time.NewTimer(idleTimeout / 2)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			c.retireIdleQueues(time.Now())
			timer.Reset(idleTimeout / 2)
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *xdnsConnServer) retireIdleQueues(now time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for key, q := range c.writeQueueMap {
		if now.Sub(q.last) >= idleTimeout {
			c.retireQueueLocked(key, q)
		}
	}
}

func (c *xdnsConnServer) retireQueueLocked(key string, q *queue) {
	if q == nil || q.retired || c.writeQueueMap[key] != q {
		return
	}
	q.retired = true
	delete(c.writeQueueMap, key)
	close(q.retireDone)
}

func (c *xdnsConnServer) ensureQueue(addr net.Addr) *queue {
	if c.closed.Load() {
		return nil
	}

	q, ok := c.writeQueueMap[addr.String()]
	if !ok {
		q = &queue{
			key:        addr.String(),
			queue:      make(chan []byte, 512),
			stash:      make(chan []byte, 1),
			retireDone: make(chan struct{}),
		}
		c.writeQueueMap[addr.String()] = q
	}
	q.last = time.Now()

	return q
}

func (c *xdnsConnServer) stash(queue *queue, p []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed.Load() || queue.retired || c.writeQueueMap[queue.key] != queue {
		return
	}

	select {
	case queue.stash <- p:
	default:
	}
}

func (c *xdnsConnServer) recvLoop() {
	var buf [finalmask.UDPSize]byte

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if c.ctx.Err() != nil || go_errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}

		query, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		resp, payload := responseFor(&query, c.domains)

		var clientID [8]byte
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacketServer(r)
				if err != nil {
					break
				}

				buf := make([]byte, len(p))
				copy(buf, p)
				select {
				case c.readQueue <- &packet{
					p:    buf,
					addr: clientIDToAddr(clientID),
				}:
				case <-c.ctx.Done():
					return
				default:
					errors.LogDebug(context.Background(), addr, " ", clientID, " mask read err queue full")
				}
			}
		} else {
			if resp != nil && resp.Rcode() == RcodeNoError {
				resp.Flags |= RcodeNameError
			}
		}

		if resp != nil {
			select {
			case c.ch <- &record{resp, addr, clientIDToAddr(clientID)}:
			case <-c.ctx.Done():
				return
			default:
				errors.LogDebug(context.Background(), addr, " ", clientID, " mask read err record queue full")
			}
		}
	}

	errors.LogDebug(context.Background(), "xdns closed")
}

func (c *xdnsConnServer) sendLoop() {
	var nextRec *record
	for {
		var err error
		rec := nextRec
		nextRec = nil

		if rec == nil {
			select {
			case rec = <-c.ch:
			case <-c.ctx.Done():
				return
			}
		}

		if rec.Resp.Rcode() == RcodeNoError && len(rec.Resp.Question) == 1 {
			var payload bytes.Buffer
			limit := maxEncodedPayloadForType(rec.Resp.Question[0].Type)
			timer := time.NewTimer(maxResponseDelay)

			for {
				c.mutex.Lock()
				q := c.ensureQueue(rec.ClientAddr)
				if q == nil {
					c.mutex.Unlock()
					return
				}
				if !q.retired && c.writeQueueMap[q.key] == q {
					q.rrType = rec.Resp.Question[0].Type
				}
				c.mutex.Unlock()

				var p []byte

				select {
				case p = <-q.stash:
				case <-q.retireDone:
				default:
					select {
					case p = <-q.stash:
					case p = <-q.queue:
					case <-q.retireDone:
					default:
						select {
						case p = <-q.stash:
						case p = <-q.queue:
						case <-timer.C:
						case nextRec = <-c.ch:
						case <-q.retireDone:
						case <-c.ctx.Done():
							if !timer.Stop() {
								select {
								case <-timer.C:
								default:
								}
							}
							return
						}
					}
				}

				timer.Reset(0)

				if len(p) != 0 {
					c.mutex.Lock()
					current := !q.retired && c.writeQueueMap[q.key] == q
					c.mutex.Unlock()
					if !current {
						p = nil
					}
				}
				if len(p) == 0 {
					break
				}

				limit -= 2 + len(p)
				if limit < 0 {
					if payload.Len() == 0 {
						errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns payload too large for rrtype ", rec.Resp.Question[0].Type, " ", len(p))
						continue
					}
					c.stash(q, p)
					break
				}

				// if len(p) > 65535 {
				// 	panic(len(p))
				// }

				_ = binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}

			timer.Stop()
			rec.Resp.Answer, err = answersForPayload(rec.Resp.Question[0], responseTTL, payload.Bytes())
			if err != nil {
				errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns encode err ", err)
				continue
			}
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns wireformat err ", err)
			continue
		}

		if len(buf) > maxUDPPayload {
			errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns truncate ", len(buf))
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02
		}

		if c.closed.Load() {
			return
		}

		_, err = c.PacketConn.WriteTo(buf, rec.Addr)
		if go_errors.Is(err, net.ErrClosed) {
			c.SignalStop()
			break
		}
	}
}

func (c *xdnsConnServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (c *xdnsConnServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	q := c.ensureQueue(addr)
	if q == nil {
		return 0, io.ErrClosedPipe
	}
	limit := maxEncodedPayloadForType(q.rrType)
	if q.rrType == 0 {
		limit = maxEncodedPayloadTXT
	}
	if len(p)+2 > limit {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", len(p), "+2 > ", limit)
		return 0, nil
	}

	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case q.queue <- buf:
		return len(p), nil
	case <-q.retireDone:
		return 0, io.ErrClosedPipe
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	default:
		// errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, nil
	}
}

func (c *xdnsConnServer) SignalStop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.closed.Store(true)
		c.tasks.Seal()
		c.mutex.Lock()
		for key, q := range c.writeQueueMap {
			c.retireQueueLocked(key, q)
		}
		c.mutex.Unlock()
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

func (c *xdnsConnServer) Close() error {
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

func nextPacketServer(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

func responseFor(query *Message, domains []domainSpec) (*Message, []byte) {
	resp := &Message{
		ID:       query.ID,
		Flags:    0x8000,
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		return nil, nil
	}

	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= RcodeFormatError
			return resp, nil
		}
		resp.Additional = append(resp.Additional, RR{
			Name:  Name{},
			Type:  RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= ExtendedRcodeBadVers & 0xf
			additional.TTL = (ExtendedRcodeBadVers >> 4) << 24
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}

	if len(query.Question) != 1 {
		resp.Flags |= RcodeFormatError
		return resp, nil
	}
	question := query.Question[0]

	var (
		prefix Name
		ok     bool
		match  domainSpec
	)
	for _, domain := range domains {
		prefix, ok = question.Name.TrimSuffix(domain.name)
		if ok {
			match = domain
			break
		}
	}
	if !ok {
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	resp.Flags |= 0x0400

	if query.Opcode() != 0 {
		resp.Flags |= RcodeNotImplemented
		return resp, nil
	}

	switch question.Type {
	case RRTypeTXT, RRTypeA, RRTypeAAAA:
	default:
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	if match.rrType != 0 && question.Type != match.rrType {
		resp.Flags |= RcodeNameError
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	payload = payload[:n]

	if payloadSize < maxUDPPayload {
		resp.Flags |= RcodeFormatError
		return resp, nil
	}

	return resp, payload
}
