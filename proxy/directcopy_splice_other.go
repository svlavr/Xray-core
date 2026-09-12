//go:build !linux && !android

package proxy

import (
	"io"
	"net"
)

// Non-Linux platforms retain the exact stock Xray ReadFrom path and never
// publish a kernel-direct-copy claim.
func copyRawConnSplice(writer *net.TCPConn, reader io.Reader, _ directCopyProgress) (int64, bool, error) {
	written, err := writer.ReadFrom(reader)
	return written, false, err
}

func supportsDirectCopySpliceProgress(io.Reader) bool {
	return false
}
