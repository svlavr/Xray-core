package websocket

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
)

var _ buf.Writer = (*connection)(nil)

// connection is a wrapper for net.Conn over WebSocket connection.
// remoteAddr is used to pass "virtual" remote IP addresses in X-Forwarded-For.
// so we shouldn't directly read it form conn.
type connection struct {
	conn          *websocket.Conn
	reader        io.Reader
	remoteAddr    net.Addr
	heartbeatStop chan struct{}
	heartbeatDone chan struct{}
	heartbeatOnce sync.Once
	handoff       *internet.InboundHandoff
	closeOnce     sync.Once
	closeErr      error
}

func NewConnection(conn *websocket.Conn, remoteAddr net.Addr, extraReader io.Reader, heartbeatPeriod uint32) *connection {
	return newConnection(conn, remoteAddr, extraReader, heartbeatPeriod, nil)
}

func newConnection(conn *websocket.Conn, remoteAddr net.Addr, extraReader io.Reader, heartbeatPeriod uint32, handoff *internet.InboundHandoff) *connection {
	connection := &connection{
		conn:       conn,
		remoteAddr: remoteAddr,
		reader:     extraReader,
		handoff:    handoff,
	}
	if heartbeatPeriod != 0 {
		connection.heartbeatStop = make(chan struct{})
		connection.heartbeatDone = make(chan struct{})
		go func() {
			defer close(connection.heartbeatDone)
			ticker := time.NewTicker(time.Duration(heartbeatPeriod) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-connection.heartbeatStop:
					return
				case <-ticker.C:
				}
				if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Time{}); err != nil {
					break
				}
			}
		}()
	}

	return connection
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Cause(err) == io.EOF {
			c.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (c *connection) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.conn.NextReader()
	if err != nil {
		return nil, err
	}
	c.reader = reader
	return reader, nil
}

// Write implements io.Writer.
func (c *connection) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *connection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *connection) Close() error {
	c.closeOnce.Do(func() {
		c.stopHeartbeat()
		var errs []interface{}
		if err := c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5)); err != nil {
			errs = append(errs, err)
		}
		if err := c.conn.Close(); err != nil {
			errs = append(errs, err)
		}
		if c.heartbeatDone != nil {
			<-c.heartbeatDone
		}
		if len(errs) > 0 {
			c.closeErr = errors.New("failed to close connection").Base(errors.New(serial.Concat(errs...)))
		}
	})
	return c.closeErr
}

func (c *connection) Abort() error {
	c.stopHeartbeat()
	err := c.conn.Close()
	c.waitHeartbeat()
	return err
}

func (c *connection) stopHeartbeat() {
	if c.heartbeatStop != nil {
		c.heartbeatOnce.Do(func() { close(c.heartbeatStop) })
	}
}

func (c *connection) waitHeartbeat() {
	if c.heartbeatDone != nil {
		<-c.heartbeatDone
	}
}

func (c *connection) AcceptInboundHandoff() bool { return c.handoff.Accept() }
func (c *connection) RejectInboundHandoff()      { c.handoff.Reject() }

func (c *connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
