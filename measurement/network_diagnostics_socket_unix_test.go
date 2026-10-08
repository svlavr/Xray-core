//go:build darwin || linux

package measurement_test

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func networkDiagnosticSocketFlags(pc net.PacketConn) map[string]any {
	flags := make(map[string]any)
	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return map[string]any{"error": "socket exposes no SyscallConn"}
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	err = raw.Control(func(fd uintptr) {
		for _, option := range []struct {
			name          string
			level, number int
		}{{"reuse_addr", unix.SOL_SOCKET, unix.SO_REUSEADDR}, {"reuse_port", unix.SOL_SOCKET, unix.SO_REUSEPORT}, {"ipv6_only", unix.IPPROTO_IPV6, unix.IPV6_V6ONLY}} {
			value, err := unix.GetsockoptInt(int(fd), option.level, option.number)
			flags[option.name] = value
			if err != nil {
				flags[option.name+"_error"] = fmt.Sprint(err)
			}
		}
	})
	if err != nil {
		flags["control_error"] = err.Error()
	}
	return flags
}
