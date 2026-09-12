package stat

import (
	"net"
	"reflect"

	"github.com/xtls/xray-core/features/stats"
)

type Connection interface {
	net.Conn
}

// ConnectionUnwrapper exposes one transparent connection wrapper layer.
// Implementations must return a stable underlying connection and must not
// perform I/O or transfer ownership from this method.
type ConnectionUnwrapper interface {
	UnwrapConnection() net.Conn
}

type CounterConnection struct {
	Connection
	ReadCounter  stats.Counter
	WriteCounter stats.Counter
}

func (c *CounterConnection) Read(b []byte) (int, error) {
	nBytes, err := c.Connection.Read(b)
	if c.ReadCounter != nil {
		c.ReadCounter.Add(int64(nBytes))
	}

	return nBytes, err
}

func (c *CounterConnection) Write(b []byte) (int, error) {
	nBytes, err := c.Connection.Write(b)
	if c.WriteCounter != nil {
		c.WriteCounter.Add(int64(nBytes))
	}
	return nBytes, err
}

func (c *CounterConnection) UnwrapConnection() net.Conn { return c.Connection }

func TryUnwrapStatsConn(conn net.Conn) net.Conn {
	seen := make(map[any]struct{})
	for conn != nil {
		if !reflect.TypeOf(conn).Comparable() {
			return conn
		}
		if _, ok := seen[conn]; ok {
			return conn
		}
		seen[conn] = struct{}{}
		unwrapper, ok := conn.(ConnectionUnwrapper)
		if !ok {
			return conn
		}
		next := unwrapper.UnwrapConnection()
		if next == nil {
			return nil
		}
		conn = next
	}
	return conn
}
