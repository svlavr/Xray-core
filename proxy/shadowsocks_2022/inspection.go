package shadowsocks_2022

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

// The native decoded connection closes the same transport directly and through
// its reader/writer. Preserve the first physical result for those aliases and
// concurrent copy cleanup/exact-stop calls. No codec or dependency is replaced.
type inspectionEndpoint struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *inspectionEndpoint) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (c *inspectionEndpoint) Upstream() any { return c.Conn }

// dispatchTCP serves only decoded single/multi-user callbacks. Relay callbacks
// still carry ciphertext and must not acquire this logical admission.
func dispatchTCP(ctx context.Context, manager stats.Manager, inboundConn, conn net.Conn, destination net.Destination) error {
	endpoint := conn
	if upstream, ok := conn.(interface{ Upstream() any }); ok {
		if owned, ok := upstream.Upstream().(*inspectionEndpoint); ok {
			endpoint = owned
		}
	}
	ctx, observation, finish := proxy.BeginReturnedObservation(ctx, manager, endpoint, destination, stats.FlowKindTCP)
	if finish != nil {
		defer finish()
		observed := &inspectionConn{Conn: conn, endpoint: endpoint, receipt: observation.Exchange}
		// After the native group joins, its existing timer may still retain the
		// connection for Close. It must not retain this finished flow's receipt.
		defer func() { observed.receipt = nil }()
		conn = observed
	}
	link, err := session.DispatcherFromContext(ctx).Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	return singbridge.CopyConn(ctx, inboundConn, link, conn)
}

// The current sing copy path uses scalar Read/Write on the decoded serverConn.
// It exposes no cached/vector/raw capability that this wrapper would suppress.
type inspectionConn struct {
	net.Conn
	endpoint net.Conn
	receipt  stats.Exchange
}

// Preserve sing's native half-close discovery. Reader/WriterReplaceable are
// deliberately absent, so copy cannot unwrap away the decoded I/O receipts.
func (c *inspectionConn) Upstream() any { return c.Conn }

func (c *inspectionConn) Close() error {
	if c.endpoint != nil {
		// Codec reader/writer Close only rediscover this same transport. Avoid
		// reading lazily initialized codec fields while a write is unwinding.
		return c.endpoint.Close()
	}
	return c.Conn.Close()
}

func (c *inspectionConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.receipt.AddUplink(uint64(n))
	}
	if err == io.EOF {
		c.receipt.SetEndReason(stats.EndReasonEOF)
	} else if err != nil {
		c.receipt.SetEndReason(stats.EndReasonReadError)
	}
	return n, err
}

func (c *inspectionConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.receipt.AddDownlink(uint64(n))
	}
	if err != nil || n != len(p) {
		if n < len(p) {
			// The opaque codec proves prior completed plaintext units through n,
			// but exposes no lower result for its failing unit. Never guess it.
			c.receipt.MarkDownlinkIncomplete()
		}
		c.receipt.SetEndReason(stats.EndReasonWriteError)
	}
	return n, err
}
