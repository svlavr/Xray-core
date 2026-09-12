package hysteria

import (
	"context"
	go_tls "crypto/tls"
	stdnet "net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type client struct {
	mu sync.Mutex

	dest           net.Destination
	config         *Config
	tlsConfig      *go_tls.Config
	socketConfig   *internet.SocketConfig
	udpmaskManager *finalmask.UdpmaskManager
	quicParams     *internet.QuicParams

	conn       *quic.Conn
	tr         *quic.Transport
	h3         *http3.Transport
	pktConn    net.PacketConn
	udpSM      *udpSessionManager
	ctx        context.Context
	manager    *clientManager
	sealed     bool
	dialing    bool
	dialDone   chan struct{}
	uses       map[*clientUse]struct{}
	stopErr    error
	stopDone   chan struct{}
	signalOnce sync.Once
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
}

var (
	errClientGenerationClosed   = errors.New("hysteria client generation is closed")
	errClientGenerationInactive = errors.New("hysteria cached client became inactive")
	errClientManagerClosed      = errors.New("hysteria client manager is closed")
)

// clientUse retains the exact client until the returned stream or datagram is
// closed. It is deliberately a concrete wrapper: callers keep the stock
// net.Conn surface while lifecycle shutdown can still interrupt blocked I/O.
type clientUse struct {
	stat.Connection
	client *client
	once   sync.Once
	done   chan struct{}
	err    error
}

func (u *clientUse) UnwrapConnection() stdnet.Conn { return u.Connection }

func (u *clientUse) Close() error {
	u.once.Do(func() {
		u.err = u.Connection.Close()
		u.client.releaseUse(u)
	})
	return u.err
}

func closeConcurrently(closers ...func() error) error {
	results := make(chan error, len(closers))
	for _, closeResource := range closers {
		closeResource := closeResource
		go func() { results <- closeResource() }()
	}
	closeErrors := make([]error, 0, len(closers))
	for range closers {
		closeErrors = append(closeErrors, <-results)
	}
	return errors.Combine(closeErrors...)
}

func closeClientResources(conn *quic.Conn, tr *quic.Transport, h3 *http3.Transport, pktConn net.PacketConn, uses []*clientUse) error {
	closers := make([]func() error, 0, len(uses)+3)
	if pktConn != nil {
		closers = append(closers, pktConn.Close)
	}
	if conn != nil {
		closers = append(closers, func() error { return conn.CloseWithError(closeErrCodeOK, "") })
	}
	if h3 != nil || tr != nil {
		closers = append(closers, func() error {
			var closeErrors []error
			if h3 != nil {
				closeErrors = append(closeErrors, h3.Close())
			}
			if tr != nil {
				closeErrors = append(closeErrors, tr.Close())
			}
			return errors.Combine(closeErrors...)
		})
	}
	for _, use := range uses {
		use := use
		closers = append(closers, use.Close)
	}
	return closeConcurrently(closers...)
}

func (c *client) status() status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked()
}

func (c *client) statusLocked() status {
	if c.conn == nil {
		return StatusNull
	}
	select {
	case <-c.conn.Context().Done():
		return StatusInactive
	default:
		return StatusActive
	}
}

func (c *client) acquireUse(conn stat.Connection) (stat.Connection, error) {
	c.mu.Lock()
	if c.sealed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, errClientGenerationClosed
	}
	u := &clientUse{Connection: conn, client: c, done: make(chan struct{})}
	c.uses[u] = struct{}{}
	c.mu.Unlock()
	return u, nil
}

func (c *client) releaseUse(u *clientUse) {
	c.mu.Lock()
	if _, ok := c.uses[u]; ok {
		delete(c.uses, u)
		close(u.done)
	}
	c.mu.Unlock()
}

func (c *client) ensureDial(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.sealed {
			c.mu.Unlock()
			return errClientGenerationClosed
		}
		if c.statusLocked() == StatusActive {
			c.mu.Unlock()
			return nil
		}
		if c.conn != nil {
			c.mu.Unlock()
			c.SignalStop()
			return errClientGenerationInactive
		}
		if c.dialing {
			done := c.dialDone
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
				continue
			}
		}
		c.dialing = true
		c.dialDone = make(chan struct{})
		c.mu.Unlock()
		return c.dial(ctx)
	}
}

func (c *client) dial(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			c.mu.Lock()
			c.dialing = false
			close(c.dialDone)
			c.dialDone = nil
			c.mu.Unlock()
			c.SignalStop()
		}
	}()

	quicParams := c.quicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		ChromeParrot:                   !quicParams.DisableChromeParrot,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           MaxDatagramFrameSize,
		OmitMaxDatagramFrameSize:       time.Now().After(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)),
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = 8388608
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = 8388608
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	// if quicParams.KeepAlivePeriod == 0 {
	// 	quicConfig.KeepAlivePeriod = 10 * time.Second
	// }

	dialCtx, cancelDial := context.WithCancel(ctx)
	stopOwner := func() bool { return false }
	if c.ctx != nil {
		stopOwner = context.AfterFunc(c.ctx, cancelDial)
	}
	defer func() {
		stopOwner()
		cancelDial()
	}()
	raw, err := internet.DialSystem(dialCtx, c.dest, c.socketConfig)
	if err != nil {
		return errors.New("failed to dial to dest").Base(err)
	}
	pktConn, udpAddr, err := internet.PacketConnView(raw)
	if err != nil {
		_ = raw.Close()
		return err
	}
	var conn *quic.Conn
	var tr *quic.Transport
	var rt *http3.Transport
	published := false
	defer func() {
		if published {
			return
		}
		if cleanupErr := closeClientResources(conn, tr, rt, pktConn, nil); cleanupErr != nil {
			err = errors.Combine(err, errors.New("failed to roll back Hysteria client setup").Base(cleanupErr))
		}
	}()

	if c.udpmaskManager != nil {
		newConn, err := c.udpmaskManager.WrapPacketConnClientContext(dialCtx, pktConn)
		if err != nil {
			return errors.New("mask err").Base(err)
		}
		pktConn = newConn
	}

	tr = &quic.Transport{Conn: pktConn, DisableGSO: quicParams.DisableGSO}

	if !quicParams.DisableChromeParrot {
		tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
		c.tlsConfig.GetCertificate = nil
	}

	rt = &http3.Transport{
		TLSClientConfig: c.tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *go_tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   URLHost,
			Path:   URLPath,
		},
		Header: http.Header{
			RequestHeaderAuth:   []string{c.config.Auth},
			CommonHeaderCCRX:    []string{strconv.FormatUint(quicParams.BrutalDown, 10)},
			CommonHeaderPadding: []string{AuthRequestPadding.String()},
		},
	}
	resp, err := rt.RoundTrip(req.WithContext(dialCtx))
	if err != nil {
		return err
	}
	if resp.StatusCode != StatusAuthOK {
		_ = resp.Body.Close()
		return errors.New("auth failed code ", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if err := dialCtx.Err(); err != nil {
		return err
	}

	// udp, _ := strconv.ParseBool(resp.Header.Get(ResponseHeaderUDPEnabled))
	down, _ := strconv.ParseUint(resp.Header.Get(CommonHeaderCCRX), 10, 64)
	errors.LogDebug(context.Background(), "ECHAccepted ", conn.ConnectionState().TLS.ECHAccepted)

	switch quicParams.Congestion {
	case "reno":
	case "bbr":
		congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
	case "", "brutal":
		if quicParams.BrutalUp == 0 || down == 0 {
			congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
		} else {
			congestion.UseBrutal(conn, min(quicParams.BrutalUp, down), quicParams.BrutalDisableLossCompensation)
		}
	case "force-brutal":
		congestion.UseBrutal(conn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
	default:
		return errors.New("unsupported hysteria congestion ", quicParams.Congestion)
	}

	udpSM := &udpSessionManager{
		conn: conn,
		m:    make(map[uint32]*InterConn),
		next: 1,
		ctx:  c.ctx,
		done: make(chan struct{}),
	}
	c.mu.Lock()
	if c.sealed {
		c.mu.Unlock()
		return errClientGenerationClosed
	}
	c.pktConn, c.tr, c.h3, c.conn, c.udpSM = pktConn, tr, rt, conn, udpSM
	c.dialing = false
	close(c.dialDone)
	c.dialDone = nil
	c.mu.Unlock()
	published = true
	go udpSM.run()

	return nil
}

func (c *client) tcp(ctx context.Context) (stat.Connection, error) {
	err := c.ensureDial(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	conn := c.conn
	sealed := c.sealed
	c.mu.Unlock()
	if sealed || conn == nil {
		return nil, errClientGenerationClosed
	}
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return c.acquireUse(&interConn{
		stream: stream,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),

		client: true,
	})
}

func (c *client) udp(ctx context.Context) (stat.Connection, error) {
	err := c.ensureDial(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	udpSM := c.udpSM
	sealed := c.sealed
	c.mu.Unlock()
	if sealed || udpSM == nil {
		return nil, errClientGenerationClosed
	}
	conn, err := udpSM.udp()
	if err != nil {
		return nil, err
	}
	return c.acquireUse(conn)
}

func (c *client) clean() {
	if c.status() == StatusInactive {
		c.SignalStop()
	}
}

func (c *client) SignalStop() {
	if c == nil {
		return
	}
	c.signalOnce.Do(func() {
		c.mu.Lock()
		c.sealed = true
		if c.stopDone == nil {
			c.stopDone = make(chan struct{})
		}
		conn, tr, h3, pktConn := c.conn, c.tr, c.h3, c.pktConn
		uses := make([]*clientUse, 0, len(c.uses))
		for use := range c.uses {
			uses = append(uses, use)
		}
		stopDone := c.stopDone
		c.mu.Unlock()
		go func() {
			stopErr := closeClientResources(conn, tr, h3, pktConn, uses)
			c.mu.Lock()
			c.stopErr = stopErr
			close(stopDone)
			c.mu.Unlock()
		}()
		go func() { _ = c.Close() }()
	})
}

func (c *client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.SignalStop()
		c.mu.Lock()
		dialDone := c.dialDone
		stopDone := c.stopDone
		c.mu.Unlock()
		if dialDone != nil {
			<-dialDone
		}
		if stopDone != nil {
			<-stopDone
		}
		c.mu.Lock()
		udpSM := c.udpSM
		stopErr := c.stopErr
		uses := make([]*clientUse, 0, len(c.uses))
		for use := range c.uses {
			uses = append(uses, use)
		}
		c.mu.Unlock()
		closeErrors := []error{stopErr}
		for _, use := range uses {
			_ = use.Close()
			<-use.done
		}
		if udpSM != nil && udpSM.done != nil {
			<-udpSM.done
		}
		c.closeErr = errors.Combine(closeErrors...)
		c.mu.Lock()
		c.conn, c.tr, c.h3, c.pktConn, c.udpSM = nil, nil, nil, nil, nil
		c.uses = nil
		c.mu.Unlock()
		close(c.closeDone)
		if c.manager != nil {
			c.manager.remove(c, c.closeErr)
		}
	})
	<-c.closeDone
	return c.closeErr
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
	owner *internet.ResourceLifecycle
}

type clientManager struct {
	mu         sync.Mutex
	key        dialerConf
	owner      *internet.ResourceLifecycle
	ctx        context.Context
	cancel     context.CancelFunc
	current    *client
	clients    map[*client]struct{}
	clientWG   sync.WaitGroup
	clientErrs []error
	unregister func()
	sealed     bool
	stopOnce   sync.Once
	closeOnce  sync.Once
	startOnce  sync.Once
	tickDone   chan struct{}
	closeDone  chan struct{}
	closeErr   error
}

func (m *clientManager) start() {
	m.startOnce.Do(func() {
		m.mu.Lock()
		sealed := m.sealed
		m.mu.Unlock()
		if sealed {
			close(m.tickDone)
			return
		}
		go m.clean()
	})
}

func (m *clientManager) SignalStop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.sealed = true
		clients := make([]*client, 0, len(m.clients))
		for client := range m.clients {
			clients = append(clients, client)
		}
		m.mu.Unlock()
		m.cancel()
		for _, client := range clients {
			client.SignalStop()
		}
	})
}

func (m *clientManager) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	defer close(m.tickDone)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		}
		m.mu.Lock()
		clients := make([]*client, 0, len(m.clients))
		for c := range m.clients {
			clients = append(clients, c)
		}
		m.mu.Unlock()
		for _, c := range clients {
			c.clean()
		}
	}
}

func (m *clientManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.SignalStop()
		m.start()
		<-m.tickDone
		m.clientWG.Wait()
		m.mu.Lock()
		m.closeErr = errors.Combine(m.clientErrs...)
		m.current = nil
		m.clients = nil
		m.clientErrs = nil
		m.mu.Unlock()
		registry.mu.Lock()
		if registry.managers[m.key] == m {
			delete(registry.managers, m.key)
		}
		registry.mu.Unlock()
		if m.unregister != nil {
			m.unregister()
		}
		close(m.closeDone)
	})
	<-m.closeDone
	return m.closeErr
}

func (m *clientManager) remove(c *client, closeErr error) {
	m.mu.Lock()
	_, removed := m.clients[c]
	if removed {
		delete(m.clients, c)
		if closeErr != nil {
			m.clientErrs = append(m.clientErrs, closeErr)
		}
	}
	if m.current == c {
		m.current = nil
	}
	empty, legacy := len(m.clients) == 0, m.owner == nil
	startClose := empty && legacy && !m.sealed
	if startClose {
		m.sealed = true
	}
	m.mu.Unlock()
	if removed {
		m.clientWG.Done()
	}
	if startClose {
		go func() { _ = m.Close() }()
	}
}

var registry = struct {
	mu       sync.Mutex
	managers map[dialerConf]*clientManager
}{managers: make(map[dialerConf]*clientManager)}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	datagram := DatagramFromContext(ctx)
	dest.Network = net.Network_UDP

	owner := streamSettings.ResourceLifecycle
	if owner == nil {
		owner = internet.ResourceLifecycleFromContext(ctx)
	}
	key := dialerConf{Destination: dest, MemoryStreamConfig: streamSettings, owner: owner}
	for {
		manager, err := managerFor(ctx, key)
		if err != nil {
			return nil, err
		}
		c, err := manager.client(ctx, streamSettings, tlsConfig)
		if err == errClientManagerClosed {
			if owner != nil && owner.Context().Err() != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var connection stat.Connection
		if datagram {
			connection, err = c.udp(ctx)
		} else {
			connection, err = c.tcp(ctx)
		}
		if err == errClientGenerationInactive || err == errClientGenerationClosed {
			if owner != nil && owner.Context().Err() != nil {
				return nil, err
			}
			continue
		}
		return connection, err
	}
}

func managerFor(ctx context.Context, key dialerConf) (*clientManager, error) {
	registry.mu.Lock()
	manager := registry.managers[key]
	registry.mu.Unlock()
	if manager != nil {
		manager.mu.Lock()
		sealed := manager.sealed
		manager.mu.Unlock()
		if !sealed {
			return manager, nil
		}
	}

	resourceCtx := context.WithoutCancel(ctx)
	if key.owner != nil {
		resourceCtx = key.owner.Context()
	}
	resourceCtx, cancel := context.WithCancel(resourceCtx)
	provisional := &clientManager{key: key, owner: key.owner, ctx: resourceCtx, cancel: cancel, clients: make(map[*client]struct{}), tickDone: make(chan struct{}), closeDone: make(chan struct{})}
	if key.owner != nil {
		if err := key.owner.RegisterBound(provisional, func(unregister func()) { provisional.unregister = unregister }); err != nil {
			_ = provisional.Close()
			return nil, err
		}
	}
	registry.mu.Lock()
	winner := registry.managers[key]
	if winner != nil {
		winner.mu.Lock()
		winnerSealed := winner.sealed
		winner.mu.Unlock()
		if winnerSealed {
			winner = nil
		}
	}
	provisional.mu.Lock()
	provisionalSealed := provisional.sealed
	if winner == nil && !provisionalSealed {
		registry.managers[key] = provisional
	}
	provisional.mu.Unlock()
	registry.mu.Unlock()
	if winner != nil {
		// Registration happened before publication; a racing loser is rolled
		// back outside the registry lock.
		_ = provisional.Close()
		return winner, nil
	}
	if provisionalSealed {
		_ = provisional.Close()
		return nil, errClientManagerClosed
	}
	provisional.start()
	return provisional, nil
}

func (m *clientManager) client(ctx context.Context, settings *internet.MemoryStreamConfig, tlsConfig *tls.Config) (*client, error) {
	m.mu.Lock()
	if m.sealed {
		m.mu.Unlock()
		return nil, errClientManagerClosed
	}
	retired := m.current
	if current := retired; current != nil {
		current.mu.Lock()
		active := !current.sealed && current.statusLocked() != StatusInactive
		current.mu.Unlock()
		if active {
			m.mu.Unlock()
			return current, nil
		}
		m.current = nil
	}
	resourceCtx := m.ctx
	if resourceCtx == nil {
		resourceCtx = ctx
	}
	c := &client{dest: m.key.Destination, config: settings.ProtocolSettings.(*Config), tlsConfig: tlsConfig.GetTLSConfigContext(resourceCtx, tls.WithDestination(m.key.Destination)), socketConfig: settings.SocketSettings, udpmaskManager: settings.UdpmaskManager, quicParams: settings.QuicParams, ctx: resourceCtx, manager: m, uses: make(map[*clientUse]struct{}), closeDone: make(chan struct{})}
	m.clientWG.Add(1)
	m.current = c
	m.clients[c] = struct{}{}
	m.mu.Unlock()
	if retired != nil {
		go func() { _ = retired.Close() }()
	}
	return c, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
