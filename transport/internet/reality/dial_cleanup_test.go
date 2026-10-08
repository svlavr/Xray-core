package reality

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type failedDialConn struct {
	net.Conn
	input    io.Reader
	writeErr error
	closed   bool
}

func (c *failedDialConn) Read(p []byte) (int, error) {
	if c.input != nil {
		return c.input.Read(p)
	}
	return 0, io.EOF
}

func (c *failedDialConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}
func (c *failedDialConn) Close() error                     { c.closed = true; return nil }
func (c *failedDialConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *failedDialConn) SetDeadline(time.Time) error      { return nil }
func (c *failedDialConn) SetReadDeadline(time.Time) error  { return nil }
func (c *failedDialConn) SetWriteDeadline(time.Time) error { return nil }
func TestFailedRealityPreparationClosesConnection(t *testing.T) {
	for _, fingerprint := range []string{"nonexistent-fingerprint", "chrome"} {
		t.Run(fingerprint, func(t *testing.T) {
			c := new(failedDialConn)
			conn, err := UClient(c, &Config{Fingerprint: fingerprint, PublicKey: []byte{1}}, context.Background(), net.TCPDestination(net.LocalHostIP, 443))
			if err == nil || conn != nil || !c.closed {
				t.Fatalf("failure ownership: err=%v closed=%v", err, c.closed)
			}
		})
	}
}
