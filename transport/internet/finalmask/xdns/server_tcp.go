package xdns

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsTCPTimeout           = time.Minute
	maxTCPConnections       = 256
	maxPendingResponses     = 256
	maxPendingResponseBytes = 16 * maxDNSMessageSize
)

type tcpServerConn struct {
	net.Conn
	send         chan []byte
	done         chan struct{}
	once         sync.Once
	pendingBytes atomic.Int32
}

func (c *tcpServerConn) Network() string { return "tcp" }
func (c *tcpServerConn) String() string  { return c.RemoteAddr().String() }

func (c *tcpServerConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		_ = c.Conn.Close()
	})
	return nil
}

func (c *xdnsServer) acceptTCP() {
	defer c.wg.Done()
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			return
		}
		tcp := &tcpServerConn{Conn: conn, send: make(chan []byte, maxPendingResponses), done: make(chan struct{})}
		c.mu.Lock()
		if c.closed() || len(c.conns) >= maxTCPConnections {
			c.mu.Unlock()
			_ = conn.Close()
			continue
		}
		c.conns[tcp] = struct{}{}
		c.wg.Add(2)
		c.mu.Unlock()
		go c.readTCP(tcp)
		go c.writeTCP(tcp)
	}
}

func (c *xdnsServer) readTCP(conn *tcpServerConn) {
	defer c.wg.Done()
	defer func() {
		_ = conn.Close()
		c.mu.Lock()
		delete(c.conns, conn)
		c.mu.Unlock()
	}()
	var buf [512]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dnsTCPTimeout))
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(buf[:2]))
		if n == 0 {
			return
		}
		if n > len(buf) {
			if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
				return
			}
			continue
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return
		}
		c.read(buf[:n], conn)
	}
}

func (c *xdnsServer) writeTCP(conn *tcpServerConn) {
	defer c.wg.Done()
	defer conn.Close()
	for {
		select {
		case <-conn.done:
			return
		case p := <-conn.send:
			_ = conn.SetWriteDeadline(time.Now().Add(dnsTCPTimeout))
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], uint16(len(p)))
			buffers := net.Buffers{prefix[:], p}
			_, err := buffers.WriteTo(conn.Conn)
			conn.pendingBytes.Add(-int32(len(p)))
			if err != nil {
				return
			}
		}
	}
}

func (c *xdnsServer) writeDNS(p []byte, addr net.Addr) {
	if conn, ok := addr.(*tcpServerConn); ok {
		if c.closed() || len(p) == 0 || len(p) > maxDNSMessageSize {
			return
		}
		select {
		case <-conn.done:
			return
		default:
		}
		size := int32(len(p))
		if conn.pendingBytes.Add(size) > maxPendingResponseBytes {
			conn.pendingBytes.Add(-size)
			_ = conn.Close()
			return
		}
		// A slow TCP reader must not hold the shared response workers. The writer
		// owns a bounded copy because send/dr reuse their encoding buffers.
		select {
		case <-conn.done:
			conn.pendingBytes.Add(-size)
		case conn.send <- append([]byte(nil), p...):
		default:
			conn.pendingBytes.Add(-size)
			_ = conn.Close()
		}
		return
	}
	_, _ = c.PacketConn.WriteTo(p, addr)
}
