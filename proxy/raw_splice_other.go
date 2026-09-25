//go:build !linux && !android

package proxy

import "net"

func copySpliceProgress(_ *net.TCPConn, _ net.Conn, _ *rawCopyReceipt) (written int64, handled bool, err error) {
	return 0, false, nil
}
