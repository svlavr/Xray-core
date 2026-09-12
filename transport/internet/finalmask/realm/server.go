package realm

import (
	"context"
	go_errors "errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

const (
	defaultEventBuffer       = 16
	defaultStunCacheTTL      = time.Second * 10
	defaultHeartbeatInterval = time.Second * 15
)

type PunchPacketEvent struct {
	Addr   netip.AddrPort
	Packet PunchPacket
}

type STUNPacketEvent struct {
	Message *stun.Message
	Addr    netip.AddrPort
}

type realmConnServer struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	net.PacketConn

	realmClient   *Client
	realmID       string
	stunServers   []string
	family        Family
	mapper        *PortMapper
	stunTimeout   time.Duration
	punchTimeout  time.Duration
	punchInterval time.Duration

	events map[PunchMetadata]chan PunchPacketEvent
	stun   chan STUNPacketEvent
	mu     sync.Mutex

	locals     []netip.AddrPort
	localsMu   sync.Mutex
	localsLast time.Time
	lower      *contextCloser
	closeOnce  sync.Once
	closeErr   error
	cleanupMu  sync.Mutex
	cleanups   []sessionCleanupReceipt
	cleanupTTL time.Duration
}

type sessionCleanupReceipt struct {
	sessionID string
	confirmed bool
	err       error
}

type sessionEpoch struct {
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	err      chan error
	streamMu sync.Mutex
	stream   *EventStream
	sealed   bool
}

func newSessionEpoch(parent context.Context) *sessionEpoch {
	ctx, cancel := context.WithCancel(parent)
	return &sessionEpoch{ctx: ctx, cancel: cancel, err: make(chan error, 1)}
}

func (e *sessionEpoch) fail(err error) {
	select {
	case e.err <- err:
	default:
	}
	e.cancel()
	e.closeStream()
}

func (e *sessionEpoch) setStream(s *EventStream) bool {
	e.streamMu.Lock()
	if e.sealed {
		e.streamMu.Unlock()
		if s != nil {
			_ = s.Close()
		}
		return false
	}
	e.stream = s
	e.streamMu.Unlock()
	return true
}

func (e *sessionEpoch) clearStream(s *EventStream) {
	e.streamMu.Lock()
	if e.stream == s {
		e.stream = nil
	}
	e.streamMu.Unlock()
}

func (e *sessionEpoch) closeStream() {
	e.streamMu.Lock()
	e.sealed = true
	stream := e.stream
	e.stream = nil
	e.streamMu.Unlock()
	if stream != nil {
		_ = stream.Close()
	}
}

func (e *sessionEpoch) startChild(run func()) bool {
	e.streamMu.Lock()
	if e.sealed {
		e.streamMu.Unlock()
		return false
	}
	e.wg.Add(1)
	e.streamMu.Unlock()
	go func() {
		defer e.wg.Done()
		run()
	}()
	return true
}

func NewConnServer(config *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnServerContext(context.Background(), config, raw)
}

func NewConnServerContext(owner context.Context, config *Config, raw net.PacketConn) (net.PacketConn, error) {
	ctx, cancel := context.WithCancel(owner)
	lower := newContextCloser(ctx, raw)
	rollback := func() {
		cancel()
		_ = lower.Close()
		lower.StopAndJoin()
	}

	family := Family_Dual
	switch config.IPMode {
	case "dual":
	case "v4":
		family = Family_V4
	case "v6":
		family = Family_V6
	}

	var mapper *PortMapper
	if config.PortMapping != nil && config.PortMapping.Enabled {
		var err error
		start := time.Now()
		portMapConfig, err := portMapConfigFromProto(config.PortMapping)
		if err != nil {
			rollback()
			return nil, err
		}
		udpAddr, ok := raw.LocalAddr().(*net.UDPAddr)
		if !ok {
			rollback()
			return nil, errors.New("realm requires UDP packet connection")
		}
		mapper, err = NewPortMapper(ctx, udpAddr.Port, portMapConfig)
		if err != nil {
			rollback()
			return nil, errors.New("realm port mapping init failed").Base(err)
		} else {
			errors.LogDebug(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] gateway ", mapper.GatewayType(), ", external ", mapper.ExternalAddr())
			errors.LogDebug(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] init success with ", time.Since(start))
		}
	}

	conn := &realmConnServer{
		ctx:        ctx,
		cancel:     cancel,
		PacketConn: raw,

		realmClient:   NewClient(config.Scheme, config.Host, config.Port, config.Token, config.TlsConfig),
		realmID:       config.ID,
		stunServers:   config.StunServers,
		family:        family,
		mapper:        mapper,
		stunTimeout:   defaultSTUNTimeout,
		punchTimeout:  defaultPunchTimeout,
		punchInterval: defaultPunchInterval,
		lower:         lower,

		events: make(map[PunchMetadata]chan PunchPacketEvent),
		stun:   make(chan STUNPacketEvent, defaultEventBuffer),

		cleanupTTL: defaultPortMapTimeout,
	}

	if mapper != nil {
		conn.wg.Add(1)
		go portMapLoop(ctx, mapper, conn.wg.Done)
	}

	conn.wg.Add(1)
	go conn.run()

	return conn, nil
}

func (c *realmConnServer) addSTUN(packet []byte) bool {
	if !stun.IsMessage(packet) {
		return false
	}
	msg, addr, err := parseSTUNBindingResponse(packet)
	if err != nil {
		return false
	}
	select {
	case c.stun <- STUNPacketEvent{Message: msg, Addr: addr}:
	default:
	}
	return true
}

func (c *realmConnServer) addPunch(packet []byte, addr net.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for meta, ch := range c.events {
		punchPacket, err := DecodePunchPacket(packet, meta)
		if err != nil {
			continue
		}
		select {
		case ch <- PunchPacketEvent{
			Addr:   addr.(*net.UDPAddr).AddrPort(),
			Packet: punchPacket,
		}:
		default:
		}
		return true
	}
	return false
}

func (c *realmConnServer) waitctx(ctx context.Context, t time.Duration) bool {
	timer := time.NewTimer(t)
	defer timer.Stop()
	select {
	case <-timer.C:
		return false
	case <-ctx.Done():
		return true
	}
}

func (c *realmConnServer) discover(ctx context.Context, servers []*net.UDPAddr) []netip.AddrPort {
	transactionIDs := make(map[[stun.TransactionIDSize]byte]struct{}, len(servers))
	for _, server := range servers {
		msg := common.Must2(stun.Build(stun.TransactionID, stun.BindingRequest))
		transactionIDs[msg.TransactionID] = struct{}{}
		_, _ = c.PacketConn.WriteTo(msg.Raw, server)
	}

	deadline := time.NewTimer(c.stunTimeout)
	results := make([]netip.AddrPort, 0, len(servers))
	for len(transactionIDs) > 0 {
		select {
		case <-ctx.Done():
			goto end
		case <-deadline.C:
			goto end
		case ev := <-c.stun:
			if _, ok := transactionIDs[ev.Message.TransactionID]; ok {
				delete(transactionIDs, ev.Message.TransactionID)
				results = append(results, ev.Addr)
			}
		}
	}
end:
	deadline.Stop()
	if c.mapper != nil {
		results = insertAddr(results, c.mapper.ExternalAddr())
	}
	slices.SortFunc(results, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})

	return results
}

func (c *realmConnServer) getlocals(ctx context.Context, force bool) []netip.AddrPort {
	c.localsMu.Lock()
	if force || time.Since(c.localsLast) > defaultStunCacheTTL {
		start := time.Now()
		servers := resolveSTUNServers(ctx, c.PacketConn.LocalAddr().(*net.UDPAddr).IP, c.stunServers, c.family)
		errors.LogDebug(context.Background(), "[realm] update stun servers ", servers, " with ", time.Since(start))
		if len(servers) > 0 {
			start = time.Now()
			locals := c.discover(ctx, servers)
			errors.LogDebug(context.Background(), "[realm] update stun locals ", locals, " with ", time.Since(start))
			if len(locals) > 0 {
				c.locals = locals
				c.localsLast = time.Now()
			}
		}
	}
	locals := append([]netip.AddrPort(nil), c.locals...)
	c.localsMu.Unlock()
	return locals
}

func (c *realmConnServer) punch(ctx context.Context, meta PunchMetadata, peers []netip.AddrPort) {
	c.mu.Lock()
	if _, ok := c.events[meta]; ok {
		c.mu.Unlock()
		return
	}
	ch := make(chan PunchPacketEvent, defaultEventBuffer)
	c.events[meta] = ch
	c.mu.Unlock()

	start := time.Now()
	for _, peer := range peers {
		packet := common.Must2(EncodePunchPacket(PunchPacketHello, meta))
		_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(peer))
	}
	deadline := time.NewTimer(c.punchTimeout)
	ticker := time.NewTicker(c.punchInterval)
	for {
		select {
		case <-ctx.Done():
			errors.LogDebug(context.Background(), "[realm] punch ", meta.Nonce, " FAIL > session end")
			goto end
		case <-deadline.C:
			errors.LogDebug(context.Background(), "[realm] punch ", meta.Nonce, " FAIL > timeout")
			goto end
		case <-ticker.C:
			for _, peer := range peers {
				packet := common.Must2(EncodePunchPacket(PunchPacketHello, meta))
				_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(peer))
			}
		case event := <-ch:
			if event.Packet.Type == PunchPacketHello {
				packet := common.Must2(EncodePunchPacket(PunchPacketAck, meta))
				_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(event.Addr))
			}
			errors.LogDebug(context.Background(), "[realm] punch ", meta.Nonce, " SUCCESS ", event.Addr, " with ", time.Since(start))
			goto end
		}
	}
end:
	deadline.Stop()
	ticker.Stop()

	c.mu.Lock()
	delete(c.events, meta)
	close(ch)
	c.mu.Unlock()
}

func (c *realmConnServer) run() {
	defer c.wg.Done()
	backoff := time.Second
retry:
	resp, err := c.realmClient.Register(c.ctx, c.realmID, addrPortStrings(c.getlocals(c.ctx, false)))
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[realm] ", c.realmID, " register session err retry in ", backoff)
		if c.waitctx(c.ctx, backoff) {
			return
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		goto retry
	}
	backoff = time.Second
	errors.LogDebug(context.Background(), "[realm] ", c.realmID, " sesssion ", resp.SessionID, " ", resp.TTL, " registered")

	e := newSessionEpoch(c.ctx)
	e.wg.Add(2)
	go func() { defer e.wg.Done(); c.heartbeatLoop(e, resp.SessionID, resp.TTL) }()
	go func() { defer e.wg.Done(); c.eventsLoop(e, resp.SessionID, resp.TTL) }()
	select {
	case <-c.ctx.Done():
	case err = <-e.err:
	}
	e.cancel()
	e.closeStream()
	e.wg.Wait()
	errors.LogDebugInner(context.Background(), err, "[realm] session ", resp.SessionID, " end")
	deregisterErr := c.deregisterSession(resp.SessionID)
	if deregisterErr != nil {
		errors.LogDebugInner(context.Background(), deregisterErr, "[realm] ", c.realmID, " ", resp.SessionID, " deregister unconfirmed")
	} else {
		errors.LogDebug(context.Background(), "[realm] ", c.realmID, " ", resp.SessionID, " deregistered")
	}

	select {
	case <-c.ctx.Done():
		return
	default:
		goto retry
	}
}

func (c *realmConnServer) deregisterSession(sessionID string) error {
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), c.cleanupTTL)
	err := c.realmClient.Deregister(cleanupCtx, c.realmID, sessionID)
	cleanupCancel()
	c.cleanupMu.Lock()
	c.cleanups = append(c.cleanups, sessionCleanupReceipt{sessionID: sessionID, confirmed: err == nil, err: err})
	c.cleanupMu.Unlock()
	return err
}

func (c *realmConnServer) heartbeatLoop(e *sessionEpoch, sid string, ttl int) {
	ctx := e.ctx
	interval := defaultHeartbeatInterval
	if ttl > 0 {
		interval = time.Second * time.Duration(ttl) / 2
	}

	last := time.Now()
	cur := c.getlocals(ctx, false)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req := HeartbeatRequest{}
			if new := c.getlocals(ctx, false); !slices.Equal(cur, new) {
				cur = new
				req.Addresses = addrPortStrings(cur)
			}
			start := time.Now()
			resp, err := c.realmClient.Heartbeat(ctx, c.realmID, sid, req)
			if err != nil {
				var statusErr *StatusError
				if go_errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound) {
					e.fail(errors.New("session invalid"))
					return
				}
				if time.Since(last) > time.Second*time.Duration(ttl) {
					e.fail(errors.New("session lost"))
					return
				}
				continue
			}
			last = start
			errors.LogDebug(context.Background(), "[realm] heartbeat ", resp.TTL, " with ", time.Since(start))
			if resp.TTL > 0 && resp.TTL != ttl {
				ttl = resp.TTL
				ticker.Reset(time.Second * time.Duration(ttl) / 2)
			}
		}
	}
}

func (c *realmConnServer) eventsLoop(e *sessionEpoch, sid string, ttl int) {
	ctx := e.ctx
	backoff := time.Second
	last := time.Now()
	for {
		start := time.Now()
		stream, err := c.realmClient.Events(ctx, c.realmID, sid)
		if err != nil {
			var statusErr *StatusError
			if go_errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound) {
				e.fail(errors.New("session invalid"))
				return
			}
			if time.Since(last) > time.Second*time.Duration(ttl) {
				e.fail(errors.New("session lost"))
				return
			}
			errors.LogDebugInner(context.Background(), err, "[realm] ", sid, " open stream err retry in ", backoff)
			if c.waitctx(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		last = start
		if !e.setStream(stream) {
			return
		}
		errors.LogDebug(context.Background(), "[realm] open stream with ", time.Since(start))
		for {
			ev, err := stream.Next()
			if err != nil {
				_ = stream.Close()
				e.clearStream(stream)
				break
			}
			if ctx.Err() != nil {
				_ = stream.Close()
				e.clearStream(stream)
				return
			}
			last = time.Now()
			if !e.startChild(func() { c.punchEvent(ctx, sid, ev) }) {
				return
			}
		}
	}
}

func (c *realmConnServer) punchEvent(ctx context.Context, sid string, ev *PunchEvent) {
	errors.LogDebug(context.Background(), "[realm] start punch event ", ev.Nonce, " ", ev.Addresses)

	locals := c.getlocals(ctx, false)

	peers, _ := parseAddrPorts(ev.Addresses)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " update peers ", peers)
	filteredPeers, seen := candidatePunchAddrs(locals, peers, c.family)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " filtered peers ", filteredPeers)
	expandedPeers := expandSymmetricNATCandidates(filteredPeers, seen)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " expanded peers ", expandedPeers)

	if len(expandedPeers) == 0 {
		errors.LogDebug(context.Background(), "[realm] punch ", ev.Nonce, " FAIL > empty peers")
		return
	}

	start := time.Now()
	err := c.realmClient.ConnectResponse(ctx, c.realmID, sid, ev.Nonce, addrPortStrings(locals))
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "[realm] ", ev.Nonce, " connect response err")
	}
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " connect response ", locals, " with ", time.Since(start))

	c.punch(ctx, ev.PunchMetadata, expandedPeers)
}

func (c *realmConnServer) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.addSTUN(p[:n]) {
			continue
		}
		if c.addPunch(p[:n], addr) {
			continue
		}
		return n, addr, nil
	}
}

func (c *realmConnServer) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.closeErr = c.lower.Close()
		c.lower.StopAndJoin()
		c.wg.Wait()
		c.realmClient.Close()
	})
	return c.closeErr
}
