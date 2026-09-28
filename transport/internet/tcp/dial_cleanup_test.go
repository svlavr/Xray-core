package tcp

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/tls"
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
func failedDialSettings(c *failedDialConn) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{ProtocolSettings: &Config{}, FinalMask: finalmask.NewFinalMask(nil, nil, func(context.Context, net.Destination) (net.Conn, error) { return c, nil }, nil, nil, nil)}
}

func TestFailedDialClosesAcquiredConnection(t *testing.T) {
	for _, kind := range []string{"tls", "header-decode", "header-auth", "success"} {
		t.Run(kind, func(t *testing.T) {
			c := new(failedDialConn)
			settings := failedDialSettings(c)
			switch kind {
			case "tls":
				settings.SecuritySettings = &tls.Config{}
			case "header-decode":
				settings.ProtocolSettings = &Config{HeaderSettings: &serial.TypedMessage{Type: "missing.invalid"}}
			case "header-auth":
				settings.ProtocolSettings = &Config{HeaderSettings: serial.ToTypedMessage(&Config{})}
			}
			conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, 443), settings)
			if kind == "success" {
				if err != nil || conn == nil || c.closed {
					t.Fatalf("success ownership: conn=%v err=%v closed=%v", conn, err, c.closed)
				}
				conn.Close()
			} else if err == nil || conn != nil || !c.closed {
				t.Fatalf("failure ownership: conn=%v err=%v closed=%v", conn, err, c.closed)
			}
		})
	}
}
