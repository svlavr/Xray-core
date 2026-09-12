package udp

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
)

type HubOption func(h *Hub)

func HubCapacity(capacity int) HubOption {
	return func(h *Hub) {
		h.capacity = capacity
	}
}

func HubReceiveOriginalDestination(r bool) HubOption {
	return func(h *Hub) {
		h.recvOrigDest = r
	}
}

type Hub struct {
	conn         net.PacketConn
	udpConn      *net.UDPConn
	cache        chan *udp.Packet
	capacity     int
	recvOrigDest bool
	lifecycle    *internet.InboundLifecycle
	mu           sync.Mutex
	closed       bool
	activeWrites int
	writeDone    chan struct{}
	closeDone    chan struct{}
	closeErr     error
}

func ListenUDP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, options ...HubOption) (*Hub, error) {
	hub := &Hub{
		capacity:     256,
		recvOrigDest: false,
	}
	hub.lifecycle = internet.InboundLifecycleFromContext(ctx)
	for _, opt := range options {
		opt(hub)
	}

	if address.Family().IsDomain() && address.Domain() == "localhost" {
		address = net.LocalHostIP
	}

	if address.Family().IsDomain() {
		return nil, errors.New("domain address is not allowed for listening: ", address.Domain())
	}

	var sockopt *internet.SocketConfig
	if streamSettings != nil {
		sockopt = streamSettings.SocketSettings
	}
	if sockopt != nil && sockopt.ReceiveOriginalDestAddress {
		hub.recvOrigDest = true
	}

	var err error
	hub.conn, err = internet.ListenSystemPacket(ctx, &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, sockopt)
	if err != nil {
		return nil, err
	}

	raw := hub.conn

	if streamSettings.UdpmaskManager != nil {
		hub.conn, err = streamSettings.UdpmaskManager.WrapPacketConnServerContext(ctx, raw)
		if err != nil {
			raw.Close()
			return nil, errors.New("mask err").Base(err)
		}
	}

	errors.LogInfo(ctx, "listening UDP on ", address, ":", port)
	hub.udpConn, _ = hub.conn.(*net.UDPConn)
	hub.cache = make(chan *udp.Packet, hub.capacity)

	if !hub.lifecycle.Acquire() {
		hub.conn.Close()
		return nil, errors.New("inbound listener is closing")
	}
	go func() {
		defer hub.lifecycle.Release()
		hub.start()
	}()
	return hub, nil
}

// Close implements net.Listener.
func (h *Hub) Close() error {
	h.mu.Lock()
	if h.closed {
		done := h.closeDone
		h.mu.Unlock()
		if done != nil {
			<-done
		}
		h.mu.Lock()
		err := h.closeErr
		h.mu.Unlock()
		return err
	}
	h.closed = true
	h.closeDone = make(chan struct{})
	conn := h.conn
	h.mu.Unlock()
	err := conn.Close()
	h.mu.Lock()
	h.closeErr = err
	close(h.closeDone)
	h.mu.Unlock()
	return err
}

func (h *Hub) WriteTo(payload []byte, dest net.Destination) (int, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return 0, errors.New("UDP hub is closed")
	}
	if h.activeWrites == 0 {
		h.writeDone = make(chan struct{})
	}
	h.activeWrites++
	conn := h.conn
	h.mu.Unlock()
	defer h.releaseWrite()
	return conn.WriteTo(payload, &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	})
}

func (h *Hub) releaseWrite() {
	h.mu.Lock()
	h.activeWrites--
	if h.activeWrites == 0 {
		close(h.writeDone)
		h.writeDone = nil
	}
	h.mu.Unlock()
}

// Wait joins writes admitted before Close without delaying the stop signal.
func (h *Hub) Wait() {
	h.mu.Lock()
	done := h.writeDone
	h.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (h *Hub) start() {
	c := h.cache
	defer close(c)

	oobBytes := make([]byte, 256)

	for {
		buffer := buf.New()
		var noob int
		var udpAddr *net.UDPAddr
		rawBytes := buffer.Extend(buf.Size)

		var n int
		var err error
		if h.udpConn != nil {
			n, noob, _, udpAddr, err = ReadUDPMsg(h.udpConn, rawBytes, oobBytes)
		} else {
			var addr net.Addr
			n, addr, err = h.conn.ReadFrom(rawBytes)
			if err == nil {
				udpAddr = addr.(*net.UDPAddr)
			}
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to read UDP msg")
			buffer.Release()
			break
		}
		buffer.Resize(0, int32(n))

		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}

		payload := &udp.Packet{
			Payload: buffer,
			Source:  net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port)),
		}
		if h.recvOrigDest && noob > 0 {
			payload.Target = RetrieveOriginalDest(oobBytes[:noob])
			if payload.Target.IsValid() {
				errors.LogDebug(context.Background(), "UDP original destination: ", payload.Target)
			} else {
				errors.LogInfo(context.Background(), "failed to read UDP original destination")
			}
		}

		select {
		case c <- payload:
		default:
			buffer.Release()
			payload.Payload = nil
		}
	}
}

// Addr implements net.Listener.
func (h *Hub) Addr() net.Addr {
	return h.conn.LocalAddr()
}

func (h *Hub) Receive() <-chan *udp.Packet {
	return h.cache
}
