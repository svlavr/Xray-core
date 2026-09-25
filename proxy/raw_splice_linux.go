//go:build linux || android

package proxy

import (
	"errors"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const rawSpliceChunk = 1 << 20

// copySpliceProgress copies one eligible raw stream through a private pipe.
// handled is false only while fallback remains safe because src was untouched.
func copySpliceProgress(dst *net.TCPConn, src net.Conn, receipt *rawCopyReceipt) (written int64, handled bool, err error) {
	if dst == nil || src == nil || !rawSpliceSource(src) {
		return 0, false, nil
	}
	srcConn, ok := src.(syscall.Conn)
	if !ok {
		return 0, false, nil
	}
	srcRaw, err := srcConn.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	dstRaw, err := dst.SyscallConn()
	if err != nil {
		return 0, false, err
	}

	pipe := []int{-1, -1}
	if err := unix.Pipe2(pipe, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return 0, false, err
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	// Match the native Go splice batch capacity when the kernel permits it.
	// A smaller default pipe is still correct; resizing failure is nonfatal.
	_, _ = unix.FcntlInt(uintptr(pipe[0]), unix.F_SETPIPE_SZ, rawSpliceChunk)

	handled = true
	consumed := false
	var buffered int64
	// RawConn retains its callback through poll waits. Bind the two callbacks
	// and their result slots once, rather than allocating them for each pump.
	var moved, pumped int64
	var readErr, writeErr error
	drain := func(fd uintptr) bool {
		for {
			n, callErr := unix.Splice(int(fd), nil, pipe[1], nil, rawSpliceChunk, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			moved, readErr = int64(n), callErr
			if moved > 0 {
				return true
			}
			if readErr == syscall.EINTR {
				continue
			}
			return readErr != syscall.EAGAIN
		}
	}
	pump := func(fd uintptr) bool {
		for {
			n, callErr := unix.Splice(pipe[0], nil, int(fd), nil, int(buffered), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			pumped, writeErr = int64(n), callErr
			if pumped > 0 {
				return true
			}
			if writeErr == syscall.EINTR {
				continue
			}
			return writeErr != syscall.EAGAIN
		}
	}
	for {
		moved, readErr = 0, nil
		if err := srcRaw.Read(drain); err != nil {
			readErr = err
		}
		if moved > 0 {
			consumed = true
			buffered += moved
		}
		if readErr != nil && !consumed && unsupportedSpliceError(readErr) {
			return 0, false, nil
		}

		for buffered > 0 {
			pumped, writeErr = 0, nil
			if err := dstRaw.Write(pump); err != nil {
				writeErr = err
			}
			if pumped > 0 {
				buffered -= pumped
				written += pumped
				receipt.add(pumped)
			}
			if writeErr != nil {
				receipt.markWriteError(writeErr)
				return written, true, writeErr
			}
			if pumped == 0 {
				err := io.ErrShortWrite
				receipt.markWriteError(err)
				return written, true, err
			}
		}

		if readErr != nil {
			receipt.markReadError(readErr)
			return written, true, readErr
		}
		if moved == 0 {
			return written, true, nil
		}
	}
}

func rawSpliceSource(src net.Conn) bool {
	switch conn := src.(type) {
	case *net.TCPConn:
		return conn != nil
	case *net.UnixConn:
		if conn == nil {
			return false
		}
		address := conn.LocalAddr()
		return address != nil && address.Network() == "unix"
	default:
		return false
	}
}

func unsupportedSpliceError(err error) bool {
	return errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EXDEV)
}
