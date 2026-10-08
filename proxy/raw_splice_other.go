//go:build !linux && !android

package proxy

import "net"

func copySpliceProgress(_ *net.TCPConn, _ net.Conn, _ *rawCopyReceipt) (handled bool, err error) {
	return false, nil
}
