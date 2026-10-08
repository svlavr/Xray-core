//go:build !darwin && !linux

package measurement_test

import "net"

func networkDiagnosticSocketFlags(net.PacketConn) map[string]any {
	return map[string]any{"availability": "socket flag inspection is limited to Darwin and Linux"}
}
