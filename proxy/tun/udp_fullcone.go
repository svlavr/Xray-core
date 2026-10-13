package tun

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.RWMutex

	udpConns map[net.Destination]*udpConn
	closed   bool

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		udpConns:         make(map[net.Destination]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source addr:port
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data *buf.Buffer) {
	data.UDP = &dst

	u.RLock()
	if u.closed {
		u.RUnlock()
		data.Release()
		return
	}
	conn, found := u.udpConns[src]
	if found {
		select {
		case conn.egress <- data:
		default:
			errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
			data.Release()
		}
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()
	if u.closed {
		data.Release()
		return
	}

	conn, found = u.udpConns[src]
	if !found {
		egress := make(chan *buf.Buffer, 1024)
		conn = &udpConn{handler: u, egress: egress, src: src, dst: dst}
		u.udpConns[src] = conn

		go u.handleConnection(conn, dst)
	}

	// send packet data to the egress channel, if it has buffer, or discard
	select {
	case conn.egress <- data:
	default:
		errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full 2")
		data.Release()
	}
}

func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	u.Lock()
	// Close runs twice per flow; a newer conn may already own this src.
	if u.udpConns[conn.src] == conn {
		delete(u.udpConns, conn.src)
		close(conn.egress)
		for b := range conn.egress {
			b.Release()
		}
	}
	u.Unlock()
}

// Close seals UDP admission and releases packets whose reader has not taken custody.
func (u *udpConnectionHandler) Close() error {
	u.Lock()
	defer u.Unlock()
	u.closed = true
	for src, conn := range u.udpConns {
		delete(u.udpConns, src)
		close(conn.egress)
		for b := range conn.egress {
			b.Release()
		}
	}
	return nil
}

// udp connection abstraction
type udpConn struct {
	handler *udpConnectionHandler

	egress  chan *buf.Buffer
	src     net.Destination
	dst     net.Destination
	receipt stats.Exchange
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, ok := <-c.egress
	if !ok {
		return nil, io.EOF
	}
	return buf.MultiBuffer{b}, nil
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	b, ok := <-c.egress
	if !ok {
		return 0, io.EOF
	}
	defer b.Release()
	n := copy(p, b.Bytes())
	if n != int(b.Len()) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		err := c.handler.writePacket(b.Bytes(), dst, c.src)
		proxy.RecordPacketOutcome(c.receipt, uint64(b.Len()), err == nil)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	// sending packets back mean sending payload with source/destination reversed
	err := c.handler.writePacket(p, c.dst, c.src)
	proxy.RecordPacketOutcome(c.receipt, uint64(len(p)), err == nil)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) WithWriterReceipt(receipt stats.Exchange) buf.Writer {
	c.receipt = receipt
	return c
}

func (c *udpConn) WriterReceipt() stats.Exchange {
	return c.receipt
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *udpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}
