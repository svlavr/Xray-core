package kcp

import (
	"context"
	gotls "crypto/tls"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type ConnectionID struct {
	Remote net.Address
	Port   net.Port
	Conv   uint16
}

// Listener defines a server listening for connections
type Listener struct {
	sync.Mutex
	sessions    map[ConnectionID]*Connection
	owned       map[*Connection]struct{}
	handoffs    map[*Connection]*internet.InboundHandoff
	hub         *udp.Hub
	tlsConfig   *gotls.Config
	config      *Config
	reader      PacketReader
	addConn     internet.ConnHandler
	lifecycle   *internet.InboundLifecycle
	joined      bool
	closed      bool
	packetDone  chan struct{}
	stopOnce    sync.Once
	stopDone    chan struct{}
	stopErr     error
	closing     []*Connection
	waitOnce    sync.Once
	waitDone    chan struct{}
	waitErr     error
	releaseOnce sync.Once
	releaseDone chan struct{}
	releaseErr  error
}

func NewListener(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (*Listener, error) {
	kcpSettings := streamSettings.ProtocolSettings.(*Config)

	l := &Listener{
		reader:      &KCPPacketReader{},
		sessions:    make(map[ConnectionID]*Connection),
		owned:       make(map[*Connection]struct{}),
		handoffs:    make(map[*Connection]*internet.InboundHandoff),
		config:      kcpSettings,
		addConn:     addConn,
		lifecycle:   internet.InboundLifecycleFromContext(ctx),
		packetDone:  make(chan struct{}),
		stopDone:    make(chan struct{}),
		waitDone:    make(chan struct{}),
		releaseDone: make(chan struct{}),
	}
	l.joined = l.lifecycle != nil && l.lifecycle.Tasks != nil

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
	}

	hub, err := udp.ListenUDP(ctx, address, port, streamSettings, udp.HubCapacity(1024))
	if err != nil {
		return nil, err
	}
	l.Lock()
	l.hub = hub
	l.Unlock()
	errors.LogInfo(ctx, "listening on ", address, ":", port)

	if l.joined && !l.lifecycle.Acquire() {
		_ = hub.Close()
		return nil, errors.New("inbound listener is closing")
	}
	go func() {
		if l.joined {
			defer l.lifecycle.Release()
		}
		defer close(l.packetDone)
		l.handlePackets()
	}()

	return l, nil
}

func (l *Listener) handlePackets() {
	receive := l.hub.Receive()
	for payload := range receive {
		l.OnReceive(payload.Payload, payload.Source)
	}
}

func (l *Listener) OnReceive(payload *buf.Buffer, src net.Destination) {
	segments := l.reader.Read(payload.Bytes())
	payload.Release()

	if len(segments) == 0 {
		errors.LogInfo(context.Background(), "discarding invalid payload from ", src)
		return
	}

	conv := segments[0].Conversation()
	cmd := segments[0].Command()

	id := ConnectionID{
		Remote: src.Address,
		Port:   src.Port,
		Conv:   conv,
	}

	l.Lock()
	if l.closed {
		l.Unlock()
		releaseSegments(segments)
		return
	}

	conn, found := l.sessions[id]

	if !found {
		if cmd == CommandTerminate {
			l.Unlock()
			releaseSegments(segments)
			return
		}
		if l.joined && !l.lifecycle.Acquire() {
			l.Unlock()
			releaseSegments(segments)
			return
		}
		writer := &Writer{
			id:       id,
			hub:      l.hub,
			dest:     src,
			listener: l,
		}
		remoteAddr := &net.UDPAddr{
			IP:   src.Address.IP(),
			Port: int(src.Port),
		}
		localAddr := l.hub.Addr()
		conn = NewConnection(ConnMetadata{
			LocalAddr:    localAddr,
			RemoteAddr:   remoteAddr,
			Conversation: conv,
		}, writer, writer, l.config)
		writer.connection = conn
		conn.releaseHook = func() { l.removeOwned(conn) }
		var netConn stat.Connection = conn
		if l.tlsConfig != nil {
			netConn = tls.Server(conn, l.tlsConfig)
		}
		if !l.joined {
			l.addConn(netConn)
			l.sessions[id] = conn
			l.owned[conn] = struct{}{}
			l.Unlock()
			conn.Input(segments)
			return
		}
		handoff := new(internet.InboundHandoff)
		netConn = &inboundConnection{Connection: netConn, handoff: handoff}
		if !conn.tasks.Acquire() {
			l.lifecycle.Release()
			l.Unlock()
			releaseSegments(segments)
			_ = conn.Release()
			return
		}
		l.sessions[id] = conn
		l.owned[conn] = struct{}{}
		l.handoffs[conn] = handoff
		conn.Input(segments)
		l.Unlock()
		go func() {
			defer l.lifecycle.Release()
			defer conn.tasks.Release()
			defer l.removeHandoff(conn)
			l.addConn(netConn)
		}()
		return
	}
	l.Unlock()
	conn.Input(segments)
}

func releaseSegments(segments []Segment) {
	for _, seg := range segments {
		seg.Release()
	}
}

func (l *Listener) Remove(id ConnectionID, conn *Connection) {
	l.Lock()
	if l.sessions[id] == conn {
		delete(l.sessions, id)
	}
	l.Unlock()
}

func (l *Listener) removeHandoff(conn *Connection) {
	l.Lock()
	delete(l.handoffs, conn)
	l.Unlock()
}

func (l *Listener) removeOwned(conn *Connection) {
	l.Lock()
	delete(l.owned, conn)
	l.Unlock()
}

// Stop seals ingress and unblocks every KCP-owned peer without waiting.
func (l *Listener) Stop() error {
	l.stopOnce.Do(func() {
		l.Lock()
		l.closed = true
		l.closing = make([]*Connection, 0, len(l.owned))
		for conn := range l.owned {
			l.closing = append(l.closing, conn)
		}
		for _, handoff := range l.handoffs {
			handoff.Reject()
		}
		l.Unlock()

		hubErr := l.hub.Close()
		closeErrs := []error{hubErr}
		for _, conn := range l.closing {
			if err := conn.Stop(); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
		l.stopErr = errors.Combine(closeErrs...)
		close(l.stopDone)
	})
	<-l.stopDone
	return l.stopErr
}

// Wait joins listener/session work but retains buffers needed by callbacks.
func (l *Listener) Wait() error {
	_ = l.Stop()
	l.waitOnce.Do(func() {
		l.hub.Wait()
		<-l.packetDone
		for _, conn := range l.closing {
			_ = conn.Wait()
		}
		l.waitErr = l.stopErr
		close(l.waitDone)
	})
	<-l.waitDone
	return l.waitErr
}

// Release drops session buffers after the external callback barrier has joined.
func (l *Listener) Release() error {
	_ = l.Wait()
	l.releaseOnce.Do(func() {
		for _, conn := range l.closing {
			_ = conn.Release()
		}
		l.Lock()
		clear(l.sessions)
		clear(l.owned)
		clear(l.handoffs)
		l.Unlock()
		l.releaseErr = l.waitErr
		close(l.releaseDone)
	})
	<-l.releaseDone
	return l.releaseErr
}

// Close is the standalone seal/stop/join/release path. Proxyman uses the
// phased methods so every worker is stopped before any callback join begins.
func (l *Listener) Close() error {
	if err := l.Stop(); !l.joined {
		for _, conn := range l.closing {
			go conn.Terminate()
		}
		return err
	}
	_ = l.Wait()
	l.lifecycle.Tasks.Wait()
	return l.Release()
}

func (l *Listener) ActiveConnections() int {
	l.Lock()
	defer l.Unlock()

	return len(l.sessions)
}

// Addr returns the listener's network address, The Addr returned is shared by all invocations of Addr, so do not modify it.
func (l *Listener) Addr() net.Addr {
	return l.hub.Addr()
}

type Writer struct {
	id         ConnectionID
	dest       net.Destination
	hub        *udp.Hub
	listener   *Listener
	connection *Connection
}

func (w *Writer) Write(payload []byte) (int, error) {
	return w.hub.WriteTo(payload, w.dest)
}

func (w *Writer) Close() error {
	w.listener.Remove(w.id, w.connection)
	return nil
}

type inboundConnection struct {
	stat.Connection
	handoff *internet.InboundHandoff
}

func (c *inboundConnection) AcceptInboundHandoff() bool { return c.handoff.Accept() }
func (c *inboundConnection) RejectInboundHandoff()      { c.handoff.Reject() }
func (c *inboundConnection) UnwrapConnection() net.Conn { return c.Connection }

func ListenKCP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	return NewListener(ctx, address, port, streamSettings, addConn)
}

func init() {
	common.Must(internet.RegisterTransportListener(ProtocolName, ListenKCP))
}
