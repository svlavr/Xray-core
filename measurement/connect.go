package measurement

import (
	"context"
	"errors"
	"net/netip"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// TCPConnectRequest names one numeric destination. There is no DNS, application
// write, TLS handshake, retry or proxy-carrier measurement in this operation.
type TCPConnectRequest struct {
	Route       Route
	Destination netip.AddrPort
	Timeout     time.Duration // Positive; includes slot wait.
}

// TCPConnectReceipt reports a matching native TCP socket, never a logical pipe.
// NativeDialElapsed measures the native dial call, including platform
// controller work; it is not a SYN-only timing. It is absent if that
// native owner is unsupported. Elapsed is the returned native dial duration;
// socket close and queue waiting are excluded.
type TCPConnectReceipt struct {
	DestinationConnected bool
	NativeDialElapsed    *time.Duration
	Elapsed              time.Duration
}

// TCPConnect observes DIRECT destination establishment only. Exact outbounds
// lack a demonstrated target-ready boundary and stop before dispatch. Alternative
// system dialers cannot certify fresh establishment and stop before invocation.
func (e *Executor) TCPConnect(ctx context.Context, request TCPConnectRequest) (receipt TCPConnectReceipt, resultErr error) {
	if ctx == nil || !request.Destination.IsValid() || request.Destination.Addr().Zone() != "" || request.Timeout <= 0 || !request.Route.valid() {
		return receipt, errors.New("invalid TCP connect request")
	}
	if request.Route.Kind == ExactOutbound {
		return receipt, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	select {
	case e.slots <- struct{}{}:
	case <-ctx.Done():
		return receipt, ctx.Err()
	}
	defer func() { <-e.slots }()
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	started := time.Now()
	dest := xnet.TCPDestination(xnet.IPAddress(request.Destination.Addr().AsSlice()), xnet.Port(request.Destination.Port()))
	conn, err := internet.DialSystemTCPConnect(ctx, dest)
	elapsed := time.Since(started)
	receipt.Elapsed = elapsed
	if errors.Is(err, internet.ErrTCPConnectUnsupported) {
		return receipt, ErrUnsupported
	}
	receipt.NativeDialElapsed = &elapsed
	if err == nil {
		receipt.DestinationConnected = true
		_ = conn.Close()
	}
	return receipt, err
}
