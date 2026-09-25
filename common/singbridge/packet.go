package singbridge

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

func CopyPacketConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, destination net.Destination, serverConn net.PacketConn) error {
	cancel := func() {
		common.Interrupt(link.Reader)
		common.Interrupt(serverConn)
	}
	conn := &PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
		Conn:   inboundConn,
		T:      signal.CancelAfterInactivity(ctx, cancel, 300*time.Second),
	}
	return ReturnError(bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(serverConn)))
}

type PacketConnWrapper struct {
	buf.Reader
	buf.Writer
	net.Conn
	Dest      net.Destination
	cached    buf.MultiBuffer
	readMu    sync.Mutex
	readErr   error
	closed    atomic.Bool
	closeOnce sync.Once

	// A simple patch to avoid goroutine leak since sing infra cannot awake read block by write err
	T *signal.ActivityTimer
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (addr M.Socksaddr, err error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	if w.closed.Load() {
		return M.Socksaddr{}, io.ErrClosedPipe
	}
	w.T.Update()
	defer func() {
		if err != nil {
			// uplinkonly
			w.T.SetTimeout(2 * time.Second)
		}
	}()
	var bb *buf.Buffer
	for bb == nil {
		if len(w.cached) != 0 {
			w.cached, bb = buf.SplitFirst(w.cached)
			continue
		}
		if w.readErr != nil {
			return M.Socksaddr{}, w.readErr
		}
		w.cached, w.readErr = w.ReadMultiBuffer()
		if w.closed.Load() {
			w.cached = buf.ReleaseMulti(w.cached)
			return M.Socksaddr{}, io.ErrClosedPipe
		}
	}
	defer bb.Release()
	destination := w.Dest
	if bb.UDP != nil {
		destination = *bb.UDP
	}
	n, err := buffer.Write(bb.Bytes())
	if err == nil && n != int(bb.Len()) {
		err = io.ErrShortBuffer
	}
	return ToSocksaddr(destination), err
}

func (w *PacketConnWrapper) WritePacket(buffer *B.Buffer, destination M.Socksaddr) (err error) {
	// PacketWriter takes custody even when conversion or the pipe write fails.
	defer buffer.Release()
	if w.closed.Load() {
		return io.ErrClosedPipe
	}
	w.T.Update()
	defer func() {
		if err != nil {
			// downlinkonly
			w.T.SetTimeout(5 * time.Second)
		}
	}()
	endpoint, err := ToDestination(destination, net.Network_UDP)
	if err != nil {
		return err
	}
	var vBuf *buf.Buffer
	if buffer.Len() > buf.Size {
		vBuf = buf.NewWithSize(int32(buffer.Len()))
	} else {
		vBuf = buf.New()
	}
	if _, err = vBuf.Write(buffer.Bytes()); err != nil {
		vBuf.Release()
		return err
	}
	vBuf.UDP = &endpoint
	return w.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (w *PacketConnWrapper) Close() error {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		// Unblock the native copy tasks before joining cached-buffer access.
		common.Interrupt(w.Reader)
		common.Interrupt(w.Writer)
		w.readMu.Lock()
		w.cached = buf.ReleaseMulti(w.cached)
		w.readErr = nil
		w.readMu.Unlock()
		if w.T != nil {
			w.T.SetTimeout(0)
		}
	})
	return nil
}
