package measurement

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

var ErrUDPReplyLimit = errors.New("UDP reply observation limit exceeded")

// UDPEchoRequest describes a fixed numeric destination and a finite train.
// PacketBytes includes the 24-byte wire prefix: "MUE1", 16 random nonce bytes,
// then a big-endian uint32 sequence (zero based). The remainder is random and
// identical across this train. The endpoint must echo the entire datagram.
type UDPEchoRequest struct {
	Route       Route
	Destination netip.AddrPort
	Count       int           // Positive, representable by the uint32 sequence.
	PacketBytes int           // 24..65535, bounded by native packet framing.
	Interval    time.Duration // Caller-selected spacing; zero sends without delay.
	ReplyWait   time.Duration // Observation window after the final successful write.
	Timeout     time.Duration // Positive; includes slot wait and open.
	MaxReplies  int           // Caller-selected limit, including invalid datagrams.
}

// UDPSendRecord retains attempted writes. WriterBytes is the writer's returned
// count when WriterBytesObserved is true; otherwise it is only the supplied
// length for an error-only multibuffer writer, including on error. Neither is a
// physical-send or remote-acceptance certificate. Replies can precede return.
type UDPSendRecord struct {
	Sequence            uint32
	Scheduled           time.Duration // Absolute schedule from train start, after open.
	WriteStarted        time.Duration // Offset from operation admission.
	WriteReturned       *time.Duration
	WriterBytes         int
	WriterBytesObserved bool
	Error               error
}

type UDPReplyIssue uint8

const (
	UDPReplyValid UDPReplyIssue = iota
	UDPReplyWrongSource
	UDPReplyMalformed
	UDPReplyWrongNonce
	UDPReplyUnsentSequence
)

// UDPReplyRecord stores visible datagrams without retaining response payload.
// Sequence is present only for the matching nonce/header. Valid means source,
// nonce, attempted sequence, length and all echoed bytes matched. Duplicate
// means a previous valid reply for that sequence; Late compares observation
// against WriteStarted+ReplyWait, not a network/kernel timestamp. RoundTrip is
// present only for valid replies and measures that same writer-start boundary.
type UDPReplyRecord struct {
	Observed  time.Duration
	Bytes     int
	Source    netip.AddrPort // Native socket metadata, or VLESS peer-reported IP/port.
	Sequence  *uint32
	Issue     UDPReplyIssue
	Duplicate bool
	Late      bool
	RoundTrip *time.Duration
}

// UDPEchoReceipt describes only native-visible events. Exact Freedom's native
// relay omits zero-length datagrams; this API cannot count those unseen events.
// No matching reply is a raw absence within the observation window, not an
// operation failure, loss percentage, endpoint health or cleanup certificate.
type UDPEchoReceipt struct {
	Nonce          [16]byte
	Sends          []UDPSendRecord
	Replies        []UDPReplyRecord
	ReplyLimitHit  bool
	WindowComplete bool // The complete post-final-write ReplyWait was observed.
	OutboundError  error
	Elapsed        time.Duration
}

func validateUDPEcho(r UDPEchoRequest) error {
	if !r.Destination.IsValid() || r.Destination.Addr().Zone() != "" || !r.Route.valid() {
		return errors.New("invalid UDP destination/route")
	}
	if r.Count < 1 || uint64(r.Count) > 1<<32 || r.PacketBytes < 24 || r.PacketBytes > 65535 || r.MaxReplies < 1 || r.Interval < 0 || r.ReplyWait < 0 || r.Timeout <= 0 {
		return errors.New("invalid UDP train budget")
	}
	if r.Interval > 0 && uint64(r.Count-1) > uint64(math.MaxInt64/int64(r.Interval)) {
		return errors.New("UDP train schedule overflows duration")
	}
	return nil
}

func (e *Executor) UDPEcho(ctx context.Context, request UDPEchoRequest) (receipt UDPEchoReceipt, resultErr error) {
	if ctx == nil {
		return receipt, errors.New("nil request context")
	}
	if err := validateUDPEcho(request); err != nil {
		return receipt, err
	}
	request.Destination = netip.AddrPortFrom(request.Destination.Addr().Unmap(), request.Destination.Port())
	o, err := e.begin(ctx, request.Timeout)
	if err != nil {
		return receipt, err
	}
	defer o.end()
	ctx = o
	started := o.started
	payload := make([]byte, request.PacketBytes)
	if _, err := rand.Read(payload); err != nil {
		return receipt, err
	}
	copy(payload, "MUE1")
	copy(receipt.Nonce[:], payload[4:20])
	receipt.Replies = make([]UDPReplyRecord, 0)
	defer func() {
		finalizeUDPReplies(&receipt, request)
		receipt.Elapsed = time.Since(started)
		receipt.OutboundError = o.outboundError()
	}()
	dest := xnet.UDPDestination(xnet.IPAddress(request.Destination.Addr().AsSlice()), xnet.Port(request.Destination.Port()))
	conn, err := e.open(ctx, request.Route, dest)
	if err != nil {
		return receipt, err
	}
	resultErr = runUDPTrain(ctx, conn, request, payload, started, &receipt)
	return receipt, errors.Join(resultErr, ctx.Err())
}

func observeUDPReply(receipt *UDPEchoReceipt, packet []byte, source netip.AddrPort, r UDPEchoRequest, payload []byte, started time.Time) error {
	v := UDPReplyRecord{Observed: time.Since(started), Bytes: len(packet), Source: source}
	if len(receipt.Replies) == r.MaxReplies {
		receipt.ReplyLimitHit = true
		return ErrUDPReplyLimit
	}
	switch {
	case len(packet) < 24 || !bytes.Equal(packet[:4], payload[:4]):
		v.Issue = UDPReplyMalformed
	case !bytes.Equal(packet[4:20], payload[4:20]):
		v.Issue = UDPReplyWrongNonce
	default:
		seq := binary.BigEndian.Uint32(packet[20:24])
		v.Sequence = &seq
		if source == r.Destination && (len(packet) != len(payload) || !bytes.Equal(packet[24:], payload[24:])) {
			v.Issue = UDPReplyMalformed
		}
	}
	if source != r.Destination {
		v.Issue = UDPReplyWrongSource
	}
	receipt.Replies = append(receipt.Replies, v)
	return nil
}

func finalizeUDPReplies(receipt *UDPEchoReceipt, r UDPEchoRequest) {
	matched := make(map[uint32]bool)
	for i := range receipt.Replies {
		v := &receipt.Replies[i]
		if v.Sequence == nil || v.Issue == UDPReplyWrongSource {
			continue
		}
		seq := *v.Sequence
		if uint64(seq) >= uint64(len(receipt.Sends)) || v.Observed < receipt.Sends[seq].WriteStarted {
			v.Issue = UDPReplyUnsentSequence
		} else if v.Issue == UDPReplyValid {
			elapsed := v.Observed - receipt.Sends[seq].WriteStarted
			v.RoundTrip, v.Late = &elapsed, elapsed > r.ReplyWait
			v.Duplicate = matched[seq]
			matched[seq] = true
		}
	}
}

// Receiver alone owns Replies; caller alone owns Sends. Correlation follows join.
func runUDPTrain(ctx context.Context, conn net.Conn, r UDPEchoRequest, payload []byte, started time.Time, receipt *UDPEchoReceipt) error {
	if !packetReadable(conn) {
		_ = conn.Close()
		return ErrUnsupported
	}
	ioCtx, cancel := context.WithCancel(ctx)
	closeConn := closeOnCancel(ioCtx, conn)
	received := make(chan error, 1)
	packet := make([]byte, 65536)
	go func() {
		var readErr error
		defer func() {
			cancel()
			received <- readErr
		}()
		for ioCtx.Err() == nil {
			hadData, nativeErr, visitErr := readPacketBatch(conn, packet, func(packet []byte, source netip.AddrPort) error {
				return observeUDPReply(receipt, packet, source, r, payload, started)
			}, false)
			if visitErr != nil || nativeErr != nil {
				if hadData || ioCtx.Err() == nil || visitErr != nil {
					readErr = errors.Join(nativeErr, visitErr)
				}
				return
			}
		}
	}()
	sendErr := sendUDPTrain(ioCtx, conn, r, payload, started, receipt)
	var resultErr error
	if sendErr == nil && ioCtx.Err() == nil {
		window := time.NewTimer(r.ReplyWait)
		select {
		case <-window.C:
			receipt.WindowComplete = true
		case <-ioCtx.Done():
			resultErr = ctx.Err()
		}
		window.Stop()
	}
	cancel()
	closeConn()
	readErr := <-received
	// Receiver-induced local cancellation is cleanup, not caller cancellation.
	if sendErr == errUDPSenderStopped {
		sendErr = nil
	}
	return errors.Join(resultErr, sendErr, readErr, ctx.Err())
}

var errUDPSenderStopped = errors.New("local UDP sender stopped")

func sendUDPTrain(ctx context.Context, conn net.Conn, r UDPEchoRequest, payload []byte, started time.Time, receipt *UDPEchoReceipt) error {
	trainStart := time.Now()
	wire := append([]byte(nil), payload...)
	for i := range r.Count {
		scheduled := time.Duration(i) * r.Interval
		if delay := time.Until(trainStart.Add(scheduled)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return errUDPSenderStopped
			}
		}
		if err := ctx.Err(); err != nil {
			return errUDPSenderStopped
		}
		binary.BigEndian.PutUint32(wire[20:24], uint32(i))
		receipt.Sends = append(receipt.Sends, UDPSendRecord{Sequence: uint32(i), Scheduled: scheduled, WriteStarted: time.Since(started)})
		n, observed, err := writeUDPPacket(conn, wire)
		if err == nil && n != len(wire) {
			err = io.ErrShortWrite
		}
		elapsed := time.Since(started)
		record := &receipt.Sends[i]
		record.WriteReturned, record.WriterBytes, record.Error, record.WriterBytesObserved = &elapsed, n, err, observed
		if err != nil {
			return err
		}
	}
	return nil
}
