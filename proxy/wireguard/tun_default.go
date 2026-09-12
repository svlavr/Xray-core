//go:build !linux

package wireguard

import (
	"context"
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

func createKernelTun(context.Context, []netip.Addr, []netip.Addr, int) (tdev tun.Device, tnet *Net, err error) {
	return nil, nil, errors.New("not implemented")
}

func KernelTunSupported() (bool, error) {
	return false, nil
}
