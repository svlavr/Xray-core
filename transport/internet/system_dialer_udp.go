package internet

import (
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"

	"github.com/xtls/xray-core/common/net"
)

// Darwin's dual-stack port-zero allocator can select an occupied IPv4 port.
// Reserve through the IPv4 allocator, then bind the original native socket to
// that port while the reservation is held. Darwin permits this order for two
// wildcard sockets of different families; reversing it is not permitted.
func listenSystemUDP(ctx context.Context, lc *net.ListenConfig, source *net.UDPAddr) (net.PacketConn, error) {
	if runtime.GOOS != "darwin" || source.Port != 0 || !source.IP.IsUnspecified() {
		return lc.ListenPacket(ctx, source.Network(), source.String())
	}
	// Only allocation conflicts are reselected. This bounds scratch socket work
	// even for a caller without a deadline; no datagram has been sent yet.
	const bindAttempts = 8
	var err error
	for range bindAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reservation, reserveErr := new(net.ListenConfig).ListenPacket(ctx, "udp4", "0.0.0.0:0")
		if reserveErr != nil {
			return nil, reserveErr
		}
		var packet net.PacketConn
		packet, err = listenReservedUDP(ctx, lc, source, reservation)
		var syscallErr *os.SyscallError
		if !errors.Is(err, syscall.EADDRINUSE) || !errors.As(err, &syscallErr) || syscallErr.Syscall != "bind" {
			return packet, err
		}
	}
	return nil, err
}

// listenReservedUDP owns reservation on every return. The returned PacketConn
// is the ordinary native socket: no packet wrapper, receive worker or second
// live traffic socket is introduced.
func listenReservedUDP(ctx context.Context, lc *net.ListenConfig, source *net.UDPAddr, reservation net.PacketConn) (net.PacketConn, error) {
	closeReservation := func() error {
		if reservation == nil {
			return nil
		}
		guard := reservation
		reservation = nil
		return guard.Close()
	}
	defer closeReservation()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bind := *source
	bind.Port = reservation.LocalAddr().(*net.UDPAddr).Port
	config := *lc
	config.Control = func(network, _ string, raw syscall.RawConn) error {
		if network == "udp4" {
			// Go can select an IPv4 socket if dual stack is unavailable. Its
			// explicit bind checks occupancy itself, so release before bind.
			if err := closeReservation(); err != nil {
				return err
			}
		}
		if lc.Control != nil {
			// Keep the actual family and original requested port-zero address
			// seen by controllers; outbound options retain their destination.
			return lc.Control(network, source.String(), raw)
		}
		return nil
	}
	packet, err := config.ListenPacket(ctx, source.Network(), bind.String())
	if err != nil {
		return nil, err
	}
	if err := closeReservation(); err != nil {
		packet.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		packet.Close()
		return nil, err
	}
	return packet, nil
}
