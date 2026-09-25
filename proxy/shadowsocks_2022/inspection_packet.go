package shadowsocks_2022

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

func dispatchPacket(ctx context.Context, manager stats.Manager, conn N.PacketConn, destination net.Destination, writeAccess *sync.Mutex) error {
	ctx, observation, finish := proxy.BeginReturnedObservation(ctx, manager, conn, destination, stats.FlowKindUDPAssociation)
	observed := &inspectionPacketConn{PacketConn: conn, writeAccess: writeAccess}
	if finish != nil {
		defer finish()
		observed.receipt = observation.Exchange
	}
	conn = observed
	if waiter, ok := observed.PacketConn.(N.PacketReadWaiter); ok {
		conn = &inspectionPacketWaiter{inspectionPacketConn: observed, waiter: waiter}
	}
	link, err := session.DispatcherFromContext(ctx).Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	out := &singbridge.PacketConnWrapper{
		Reader: link.Reader, Writer: link.Writer, Dest: destination,
		T: signal.CancelAfterInactivity(ctx, func() { common.Interrupt(link.Reader) }, 300*time.Second),
	}
	// The native group owns both pumps and joins them after endpoint cleanup.
	return bufio.CopyPacketConn(ctx, conn, out)
}

type inspectionPacketConn struct {
	N.PacketConn
	receipt     stats.Exchange
	writeAccess *sync.Mutex
	closed      atomic.Bool
}

// Preserve codec headroom discovery, without declaring reads/writes replaceable.
func (c *inspectionPacketConn) Upstream() any { return c.PacketConn }

func (c *inspectionPacketConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

func (c *inspectionPacketConn) readResult(n int, destination M.Socksaddr, err error) {
	if err == nil || n > 0 {
		if target, conversionErr := singbridge.ToDestination(destination, net.Network_UDP); conversionErr == nil {
			c.receipt.PacketDestination(target)
		}
		c.receipt.AddUplink(uint64(n))
	}
	if err != nil {
		if errors.Is(err, io.ErrShortBuffer) {
			c.receipt.MarkUplinkIncomplete()
		}
		c.receipt.SetEndReason(stats.EndReasonReadError)
	}
}

func (c *inspectionPacketConn) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	if c.receipt == nil {
		return c.PacketConn.ReadPacket(buffer)
	}
	before := buffer.Len()
	destination, err := c.PacketConn.ReadPacket(buffer)
	c.readResult(buffer.Len()-before, destination, err)
	return destination, err
}

func (c *inspectionPacketConn) WritePacket(buffer *B.Buffer, destination M.Socksaddr) error {
	// Retired and replacement NAT generations can share the codec session's
	// mutable nonce reader. Keep their encoders serialized at the service owner.
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.closed.Load() {
		buffer.Release()
		return io.ErrClosedPipe
	}
	if c.receipt == nil {
		return c.PacketConn.WritePacket(buffer, destination)
	}
	payload := uint64(buffer.Len())
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		c.receipt.AddDownlink(payload)
	} else {
		c.receipt.MarkDownlinkIncomplete()
		c.receipt.SetEndReason(stats.EndReasonWriteError)
	}
	return err
}

type inspectionPacketWaiter struct {
	*inspectionPacketConn
	waiter N.PacketReadWaiter
}

func (c *inspectionPacketWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	return c.waiter.InitializeReadWaiter(options)
}

func (c *inspectionPacketWaiter) WaitReadPacket() (*B.Buffer, M.Socksaddr, error) {
	if c.receipt == nil {
		return c.waiter.WaitReadPacket()
	}
	buffer, destination, err := c.waiter.WaitReadPacket()
	var n int
	if buffer != nil {
		n = buffer.Len()
	}
	c.readResult(n, destination, err)
	return buffer, destination, err
}
