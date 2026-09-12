//go:build linux || android

package proxy

import (
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type directCopySpliceCall func(rfd int, roff *int64, wfd int, woff *int64, length int, flags int) (int64, error)

type directCopySpliceTransfer struct {
	splice    directCopySpliceCall
	pipe      [2]int
	drained   int64
	drainErr  error
	remaining int64
	pumped    int64
	pumpErr   error
}

func (t *directCopySpliceTransfer) closePipe() {
	for index := range t.pipe {
		if t.pipe[index] >= 0 {
			_ = unix.Close(t.pipe[index])
			t.pipe[index] = -1
		}
	}
}

func (t *directCopySpliceTransfer) drain(sourceFD uintptr) bool {
	for {
		t.drained, t.drainErr = t.splice(int(sourceFD), nil, t.pipe[1], nil, directCopySpliceQuantum, unix.SPLICE_F_NONBLOCK)
		if t.drainErr == syscall.EINTR {
			continue
		}
		return t.drainErr != syscall.EAGAIN
	}
}

func (t *directCopySpliceTransfer) pump(destinationFD uintptr) bool {
	for t.remaining > 0 {
		var accepted int64
		accepted, t.pumpErr = t.splice(t.pipe[0], nil, int(destinationFD), nil, int(t.remaining), unix.SPLICE_F_NONBLOCK)
		if accepted > 0 {
			t.pumped += accepted
			t.remaining -= accepted
		}
		if t.pumpErr == syscall.EINTR {
			continue
		}
		if t.pumpErr == syscall.EAGAIN {
			return false
		}
		if t.pumpErr != nil || accepted == 0 {
			return true
		}
	}
	return true
}

func systemDirectCopySplice(rfd int, roff *int64, wfd int, woff *int64, length int, flags int) (int64, error) {
	written, err := unix.Splice(rfd, roff, wfd, woff, length, flags)
	return int64(written), err
}

func copyRawConnSplice(writer *net.TCPConn, reader io.Reader, progress directCopyProgress) (int64, bool, error) {
	written, direct, err := copyRawConnSpliceWith(writer, reader, progress, systemDirectCopySplice)
	if direct && err != nil {
		network := "tcp"
		if address := writer.LocalAddr(); address != nil {
			network = address.Network()
		}
		err = &net.OpError{Op: "readfrom", Net: network, Addr: writer.RemoteAddr(), Err: err}
	}
	return written, direct, err
}

func copyRawConnSpliceWith(writer *net.TCPConn, reader io.Reader, progress directCopyProgress, splice directCopySpliceCall) (int64, bool, error) {
	source, ok := reader.(syscall.Conn)
	if !ok {
		written, err := writer.ReadFrom(reader)
		return written, false, err
	}
	sourceRaw, err := source.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	destinationRaw, err := writer.SyscallConn()
	if err != nil {
		return 0, false, err
	}

	transfer := directCopySpliceTransfer{splice: splice, pipe: [2]int{-1, -1}}
	if err := unix.Pipe2(transfer.pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		written, fallbackErr := writer.ReadFrom(reader)
		return written, false, fallbackErr
	}
	defer transfer.closePipe()
	_, _ = unix.FcntlInt(uintptr(transfer.pipe[0]), unix.F_SETPIPE_SZ, directCopySpliceQuantum)
	drain := transfer.drain
	pump := transfer.pump

	var total int64
	for {
		transfer.drained = 0
		transfer.drainErr = nil
		rawErr := sourceRaw.Read(drain)
		if rawErr != nil {
			return total, true, rawErr
		}
		if transfer.drainErr == syscall.EINVAL && total == 0 && transfer.drained == 0 {
			transfer.closePipe()
			written, fallbackErr := writer.ReadFrom(reader)
			return written, false, fallbackErr
		}
		if transfer.drained == 0 {
			if transfer.drainErr != nil {
				return total, true, transfer.drainErr
			}
			return total, true, nil
		}

		transfer.remaining = transfer.drained
		transfer.pumped = 0
		transfer.pumpErr = nil
		rawErr = destinationRaw.Write(pump)
		if transfer.pumped > 0 {
			total += transfer.pumped
			if progress != nil {
				progress.Progress(uint64(transfer.pumped))
			}
		}
		if rawErr != nil {
			return total, true, rawErr
		}
		if transfer.pumpErr != nil {
			return total, true, transfer.pumpErr
		}
		if transfer.remaining != 0 {
			return total, true, io.ErrNoProgress
		}
		if transfer.drainErr != nil {
			return total, true, transfer.drainErr
		}
	}
}

func supportsDirectCopySpliceProgress(reader io.Reader) bool {
	switch connection := reader.(type) {
	case *net.TCPConn:
		return true
	case *net.UnixConn:
		address := connection.LocalAddr()
		return address != nil && address.Network() == "unix"
	default:
		return false
	}
}
