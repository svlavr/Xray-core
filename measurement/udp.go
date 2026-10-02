package measurement

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/xtls/xray-core/common/buf"
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

// UDPSendRecord retains actual attempted writes only. WriterBytes is the native
// return count, also on error; it is NOT a physical-send or remote-acceptance
// certificate. A reply can precede WriteReturned, especially on a logical pipe.
type UDPSendRecord struct {
	Sequence      uint32
	Scheduled     time.Duration // Absolute schedule from train start, after open.
	WriteStarted  time.Duration // Offset from operation admission.
	WriteReturned *time.Duration
	WriterBytes   int
	Error         error
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
	// The train prefix has 24 bytes and a uint32 sequence. Native packet
	// framing uses a uint16 length; remaining budgets belong to the caller.
	if r.Count < 1 || uint64(r.Count) > 1<<32 || r.PacketBytes < 24 || r.PacketBytes > 65535 || r.MaxReplies < 1 || r.Interval < 0 || r.ReplyWait < 0 || r.Timeout <= 0 {
		return errors.New("invalid UDP train budget")
	}
	return nil
}

// UDPEcho executes the native packet route and keeps its reported addresses.
// Unsupported or addressless native paths do not synthesize a valid reply.
func (e *Executor) UDPEcho(ctx context.Context, request UDPEchoRequest) (receipt UDPEchoReceipt, resultErr error) {
	if ctx == nil {
		return receipt, errors.New("nil request context")
	}
	if err := validateUDPEcho(request); err != nil {
		return receipt, err
	}
	request.Destination = netip.AddrPortFrom(request.Destination.Addr().Unmap(), request.Destination.Port())
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	select {
	case e.slots <- struct{}{}:
	case <-ctx.Done():
		return receipt, ctx.Err()
	}
	defer func() { <-e.slots }()
	started := time.Now()
	o := new(operation)
	ctx = measurementContext(ctx, o)
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
		o.mu.Lock()
		receipt.OutboundError = o.nativeError
		o.mu.Unlock()
	}()
	dest := xnet.UDPDestination(xnet.IPAddress(request.Destination.Addr().AsSlice()), xnet.Port(request.Destination.Port()))
	conn, err := e.open(ctx, request.Route, dest)
	if err != nil {
		return receipt, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	defer conn.Close()
	resultErr = runUDPTrain(ctx, conn, request, payload, started, &receipt)
	return receipt, errors.Join(resultErr, ctx.Err())
}

// Only the receiver writes Replies and ReplyLimitHit while I/O is live.
func observeUDPReply(receipt *UDPEchoReceipt, packet []byte, source netip.AddrPort, r UDPEchoRequest, payload []byte, started time.Time) error {
	v := UDPReplyRecord{Observed: time.Since(started), Bytes: len(packet), Source: source}
	if len(receipt.Replies) == r.MaxReplies {
		receipt.ReplyLimitHit = true
		return ErrUDPReplyLimit
	}
	switch {
	case source != r.Destination:
		v.Issue = UDPReplyWrongSource
	case len(packet) < 24 || !bytes.Equal(packet[:4], payload[:4]):
		v.Issue = UDPReplyMalformed
	case !bytes.Equal(packet[4:20], payload[4:20]):
		v.Issue = UDPReplyWrongNonce
	default:
		seq := binary.BigEndian.Uint32(packet[20:24])
		v.Sequence = &seq
		// The matching header already checked the immutable nonce and magic.
		if len(packet) != len(payload) || !bytes.Equal(packet[24:], payload[24:]) {
			v.Issue = UDPReplyMalformed
		}
	}
	receipt.Replies = append(receipt.Replies, v)
	return nil
}

// Correlate only after both workers join; the sender owns Sends until then.
func finalizeUDPReplies(receipt *UDPEchoReceipt, r UDPEchoRequest) {
	matched := make(map[uint32]bool)
	for i := range receipt.Replies {
		v := &receipt.Replies[i]
		if v.Sequence == nil {
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

func runUDPTrain(ctx context.Context, conn net.Conn, r UDPEchoRequest, payload []byte, started time.Time, receipt *UDPEchoReceipt) error {
	pc, packetConn := conn.(net.PacketConn)
	reader, multi := conn.(buf.Reader)
	if !packetConn && !multi {
		return ErrUnsupported
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sent, received := make(chan error, 1), make(chan error, 1)
	go func() {
		trainStart := time.Now()
		wire := append([]byte(nil), payload...)
		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		for i := range r.Count {
			scheduled := time.Duration(i) * r.Interval
			if delay := time.Until(trainStart.Add(scheduled)); delay > 0 {
				timer.Reset(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					sent <- ctx.Err()
					return
				}
			}
			if err := ctx.Err(); err != nil {
				sent <- err
				return
			}
			binary.BigEndian.PutUint32(wire[20:24], uint32(i))
			// Only the sender writes Sends until its completion notification.
			receipt.Sends = append(receipt.Sends, UDPSendRecord{Sequence: uint32(i), Scheduled: scheduled, WriteStarted: time.Since(started)})
			n, err := writeUDPPacket(conn, wire)
			if err == nil && n != len(wire) {
				err = io.ErrShortWrite
			}
			elapsed := time.Since(started)
			record := &receipt.Sends[i]
			record.WriteReturned, record.WriterBytes, record.Error = &elapsed, n, err
			if err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()
	go func() {
		var readErr error
		defer func() { received <- readErr }()
		if packetConn {
			packet := make([]byte, 65536) // Detect full oversized datagrams without truncation.
			for ctx.Err() == nil {
				n, addr, err := pc.ReadFrom(packet)
				if err != nil {
					if ctx.Err() == nil {
						readErr = err
					}
					return
				}
				var source netip.AddrPort
				if udp, ok := addr.(*net.UDPAddr); ok {
					a := udp.AddrPort()
					source = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
				}
				if readErr = observeUDPReply(receipt, packet[:n], source, r, payload, started); readErr != nil {
					return
				}
			}
			return
		}
		for ctx.Err() == nil {
			mb, err := reader.ReadMultiBuffer()
			for _, b := range mb {
				var source netip.AddrPort
				if b.UDP != nil && b.UDP.Address.Family().IsIP() {
					ip, ok := netip.AddrFromSlice(b.UDP.Address.IP())
					if ok {
						source = netip.AddrPortFrom(ip.Unmap(), uint16(b.UDP.Port))
					}
				}
				if readErr = observeUDPReply(receipt, b.Bytes(), source, r, payload, started); readErr != nil {
					break
				}
			}
			buf.ReleaseMulti(mb) // Every member is returned, including error/limit batches.
			if readErr != nil {
				// A native batch can contain packets and an error together. Hitting
				// our observation ceiling must not erase that independent failure.
				readErr = errors.Join(readErr, err)
				return
			}
			if err != nil {
				if ctx.Err() == nil {
					readErr = err
				}
				return
			}
		}
	}()
	var sendErr, readErr, resultErr error
	var window *time.Timer
	var windowDone <-chan time.Time
	for {
		select {
		case sendErr = <-sent:
			sent = nil
			if sendErr != nil {
				resultErr = sendErr
				goto stop
			}
			window = time.NewTimer(r.ReplyWait)
			windowDone = window.C
		case readErr = <-received:
			received = nil
			resultErr = readErr
			goto stop
		case <-windowDone:
			receipt.WindowComplete = true
			goto stop
		case <-ctx.Done():
			resultErr = ctx.Err()
			goto stop
		}
	}
stop:
	if window != nil {
		window.Stop()
	}
	cancel()
	_ = conn.Close()
	// Join the two live I/O workers after ordinary connection Close.
	if sent != nil {
		sendErr = <-sent
	}
	if received != nil {
		readErr = <-received
	}
	return errors.Join(resultErr, sendErr, readErr)
}

// Preserve one datagram per native buffer even when a caller chooses a payload
// larger than buf.Size. cnc.Connection.Write otherwise splits it into buffers.
func writeUDPPacket(conn net.Conn, packet []byte) (int, error) {
	if writer, ok := conn.(buf.Writer); ok {
		b := buf.NewWithSize(int32(len(packet)))
		_, _ = b.Write(packet)
		return len(packet), writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	return conn.Write(packet)
}
