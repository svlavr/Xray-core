package measurement

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

type udpTestConn struct {
	write  func([]byte) (int, error)
	read   func() (buf.MultiBuffer, error)
	closed chan struct{}
	once   sync.Once
}

func (c *udpTestConn) Write(p []byte) (int, error)               { return c.write(p) }
func (c *udpTestConn) Read([]byte) (int, error)                  { panic("must preserve packet batches") }
func (c *udpTestConn) ReadMultiBuffer() (buf.MultiBuffer, error) { return c.read() }
func (c *udpTestConn) Close() error                              { c.once.Do(func() { close(c.closed) }); return nil }
func (c *udpTestConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *udpTestConn) RemoteAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *udpTestConn) SetDeadline(time.Time) error               { return nil }
func (c *udpTestConn) SetReadDeadline(time.Time) error           { return nil }
func (c *udpTestConn) SetWriteDeadline(time.Time) error          { return nil }

type udpTestPacketConn struct {
	*udpTestConn
	readFrom func([]byte) (int, net.Addr, error)
}

func (c *udpTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error)  { return c.readFrom(p) }
func (c *udpTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func TestUDPPacketReadPreservesDataWithError(t *testing.T) {
	native := errors.New("native packet read failure")
	for _, mode := range []string{"packet", "packet-cancel", "empty-error", "reply-limit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), Count: 1, PacketBytes: 32, ReplyWait: time.Second, MaxReplies: 1}
			payload := make([]byte, r.PacketBytes)
			copy(payload, "MUE1")
			written := make(chan struct{})
			c := &udpTestPacketConn{udpTestConn: &udpTestConn{closed: make(chan struct{})}}
			c.write = func(p []byte) (int, error) { close(written); return len(p), nil }
			c.readFrom = func(p []byte) (int, net.Addr, error) {
				<-written
				if mode == "packet-cancel" {
					cancel()
				}
				n := copy(p, payload)
				if mode == "empty-error" {
					n = 0
				}
				return n, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, native
			}
			var receipt UDPEchoReceipt
			if mode == "reply-limit" {
				receipt.Replies = []UDPReplyRecord{{Issue: UDPReplyMalformed}}
			}
			err := runUDPTrain(ctx, c, r, payload, time.Now(), &receipt)
			finalizeUDPReplies(&receipt, r)
			if !errors.Is(err, native) || receipt.WindowComplete || len(receipt.Sends) != 1 || receipt.Sends[0].WriteReturned == nil {
				t.Fatalf("native read facts: %+v, %v", receipt, err)
			}
			if mode == "empty-error" {
				if len(receipt.Replies) != 0 {
					t.Fatal("fabricated a datagram from a pure read error")
				}
			} else if mode == "reply-limit" {
				if !errors.Is(err, ErrUDPReplyLimit) || !receipt.ReplyLimitHit || len(receipt.Replies) != 1 {
					t.Fatalf("lost reply-limit/native errors: %+v, %v", receipt, err)
				}
			} else if len(receipt.Replies) != 1 || receipt.Replies[0].Bytes != len(payload) || receipt.Replies[0].Source != r.Destination || receipt.Replies[0].Issue != UDPReplyValid || receipt.Replies[0].Sequence == nil || *receipt.Replies[0].Sequence != 0 || receipt.Replies[0].RoundTrip == nil {
				t.Fatalf("lost datagram with native error: %+v, %v", receipt, err)
			}
		})
	}
}

func TestUDPTrainPartialFailedWritesAndBatchError(t *testing.T) {
	native := errors.New("native packet failure")
	for _, mode := range []string{"partial", "error-count", "batch-error", "batch-limit"} {
		t.Run(mode, func(t *testing.T) {
			r := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), Count: 1, PacketBytes: 32, ReplyWait: 40 * time.Millisecond, MaxReplies: 4}
			payload := make([]byte, 32)
			copy(payload, "MUE1")
			var got UDPEchoReceipt
			started := time.Now()
			written := make(chan struct{})
			c := &udpTestConn{closed: make(chan struct{})}
			c.write = func(p []byte) (int, error) {
				close(written)
				if mode == "partial" {
					return 7, nil
				}
				if mode == "error-count" {
					return len(p), native
				} // CNC semantics.
				return len(p), nil
			}
			var packetBuffers []*buf.Buffer
			c.read = func() (buf.MultiBuffer, error) {
				if mode == "partial" || mode == "error-count" {
					<-c.closed
					return nil, io.ErrClosedPipe
				}
				<-written
				mb := make(buf.MultiBuffer, 3)
				for i := range mb {
					mb[i] = buf.New()
					mb[i].Write(payload)
					dest := xnet.UDPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 9)
					mb[i].UDP = &dest
				}
				packetBuffers = append(packetBuffers, mb...)
				return mb, native
			}
			if mode == "batch-limit" {
				r.MaxReplies = 2
			}
			err := runUDPTrain(context.Background(), c, r, payload, started, &got)
			finalizeUDPReplies(&got, r)
			switch mode {
			case "partial":
				if !errors.Is(err, io.ErrShortWrite) || got.Sends[0].WriterBytes != 7 || got.Sends[0].WriteReturned == nil {
					t.Fatalf("partial %+v %v", got, err)
				}
			case "error-count":
				if !errors.Is(err, native) || got.Sends[0].WriterBytes != 32 || !errors.Is(got.Sends[0].Error, native) {
					t.Fatalf("logical write error %+v %v", got, err)
				}
			case "batch-error":
				if !errors.Is(err, native) || len(got.Replies) != 3 || !got.Replies[1].Duplicate {
					t.Fatalf("batch %+v %v", got, err)
				}
			case "batch-limit":
				if !errors.Is(err, ErrUDPReplyLimit) || !errors.Is(err, native) || !got.ReplyLimitHit || len(got.Replies) != 2 {
					t.Fatalf("bounded batch %+v %v", got, err)
				}
			}
			for _, b := range packetBuffers {
				if b.Len() != 0 || b.UDP != nil {
					t.Fatal("packet batch not fully released")
				}
			}
		})
	}
}

func TestUDPTrainReplyBeforeWriteReturnAndJoin(t *testing.T) {
	r := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), Count: 1, PacketBytes: 32, ReplyWait: 40 * time.Millisecond, MaxReplies: 4}
	payload := make([]byte, 32)
	copy(payload, "MUE1")
	var got UDPEchoReceipt
	c := &udpTestConn{closed: make(chan struct{})}
	written, release := make(chan struct{}), make(chan struct{})
	c.write = func([]byte) (int, error) { close(written); <-release; return 32, nil }
	reads := 0
	observed := make(chan struct{})
	c.read = func() (buf.MultiBuffer, error) {
		if reads == 0 {
			reads++
			<-written
			b := buf.FromBytes(append([]byte(nil), payload...))
			dest := xnet.UDPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 9)
			b.UDP = &dest
			return buf.MultiBuffer{b}, nil
		}
		close(observed)
		<-c.closed
		return nil, io.ErrClosedPipe
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runUDPTrain(ctx, c, r, payload, time.Now(), &got) }()
	<-observed
	cancel()
	// Close returns but an actually blocked write has not joined.
	select {
	case <-done:
		t.Fatal("reported I/O join before write returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	finalizeUDPReplies(&got, r)
	if len(got.Replies) != 1 || got.Replies[0].Issue != UDPReplyValid || got.Sends[0].WriteReturned == nil || got.Replies[0].Observed > *got.Sends[0].WriteReturned || got.WindowComplete {
		t.Fatalf("early response %+v", got)
	}
}

func TestUDPReplyUnsentSequenceDoesNotBecomeValidAfterLaterWrite(t *testing.T) {
	r := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), MaxReplies: 4}
	payload := make([]byte, 32)
	copy(payload, "MUE1")
	var got UDPEchoReceipt
	packet := append([]byte(nil), payload...)
	binary.BigEndian.PutUint32(packet[20:24], 1)
	if err := observeUDPReply(&got, packet, r.Destination, r, payload, time.Now()); err != nil {
		t.Fatal(err)
	}
	got.Sends = []UDPSendRecord{{Sequence: 0}, {Sequence: 1, WriteStarted: time.Second}}
	finalizeUDPReplies(&got, r)
	if got.Replies[0].Issue != UDPReplyUnsentSequence || got.Replies[0].RoundTrip != nil {
		t.Fatalf("unsent reply %+v", got)
	}
}

func TestUDPReplyClassificationRetainsHeaderFactsAndPrecedence(t *testing.T) {
	destination := netip.MustParseAddrPort("127.0.0.1:9")
	r := UDPEchoRequest{Destination: destination, MaxReplies: 4, ReplyWait: time.Second}
	payload := make([]byte, 32)
	copy(payload, "MUE1")
	for _, tc := range []struct {
		name        string
		source      netip.AddrPort
		change      func([]byte) []byte
		issue       UDPReplyIssue
		hasSequence bool
		sequence    uint32
	}{
		{"wrong-source-short", netip.MustParseAddrPort("127.0.0.2:9"), func(p []byte) []byte { return p[:3] }, UDPReplyWrongSource, false, 0},
		{"short", destination, func(p []byte) []byte { return p[:23] }, UDPReplyMalformed, false, 0},
		{"wrong-magic", destination, func(p []byte) []byte { p[0] ^= 1; return p }, UDPReplyMalformed, false, 0},
		{"wrong-nonce", destination, func(p []byte) []byte { p[4] ^= 1; return p }, UDPReplyWrongNonce, false, 0},
		{"malformed-body", destination, func(p []byte) []byte { p[24] ^= 1; return p }, UDPReplyMalformed, true, 0},
		{"short-body", destination, func(p []byte) []byte { return p[:28] }, UDPReplyMalformed, true, 0},
		{"oversized-body", destination, func(p []byte) []byte { return append(p, 1) }, UDPReplyMalformed, true, 0},
		{"unsent-before-malformed", destination, func(p []byte) []byte { binary.BigEndian.PutUint32(p[20:24], 3); p[24] ^= 1; return p }, UDPReplyUnsentSequence, true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := tc.change(append([]byte(nil), payload...))
			size := len(packet)
			got := UDPEchoReceipt{Sends: []UDPSendRecord{{Sequence: 0}}}
			if err := observeUDPReply(&got, packet, tc.source, r, payload, time.Now()); err != nil {
				t.Fatal(err)
			}
			// Native read buffers can be released/reused before final correlation.
			clear(packet)
			finalizeUDPReplies(&got, r)
			v := got.Replies[0]
			if v.Issue != tc.issue || (v.Sequence != nil) != tc.hasSequence || tc.hasSequence && *v.Sequence != tc.sequence || v.Bytes != size || v.Source != tc.source || v.RoundTrip != nil || v.Duplicate || v.Late {
				t.Fatalf("reply facts: %+v", v)
			}
		})
	}
}

func TestUDPReplyInvalidDoesNotMarkDuplicateAndLateIsStrict(t *testing.T) {
	r := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), MaxReplies: 4, ReplyWait: 10 * time.Millisecond}
	payload := make([]byte, 32)
	copy(payload, "MUE1")
	got := UDPEchoReceipt{Sends: []UDPSendRecord{{Sequence: 0, WriteStarted: 10 * time.Millisecond}}}
	for index, observed := range []time.Duration{15 * time.Millisecond, 20 * time.Millisecond, 21 * time.Millisecond} {
		packet := append([]byte(nil), payload...)
		if index == 0 {
			packet[24] ^= 1
		}
		if err := observeUDPReply(&got, packet, r.Destination, r, payload, time.Now()); err != nil {
			t.Fatal(err)
		}
		got.Replies[index].Observed = observed
	}
	finalizeUDPReplies(&got, r)
	invalid, first, duplicate := got.Replies[0], got.Replies[1], got.Replies[2]
	if invalid.Issue != UDPReplyMalformed || invalid.Duplicate || invalid.RoundTrip != nil || first.Issue != UDPReplyValid || first.Duplicate || first.Late || first.RoundTrip == nil || *first.RoundTrip != 10*time.Millisecond || duplicate.Issue != UDPReplyValid || !duplicate.Duplicate || !duplicate.Late || duplicate.RoundTrip == nil || *duplicate.RoundTrip != 11*time.Millisecond {
		t.Fatalf("correlated replies: %+v", got.Replies)
	}
}

func TestUDPReplyLimitRequiresAnAdditionalObservation(t *testing.T) {
	r := UDPEchoRequest{Destination: netip.MustParseAddrPort("127.0.0.1:9"), MaxReplies: 2}
	payload := make([]byte, 32)
	copy(payload, "MUE1")
	var got UDPEchoReceipt
	for range r.MaxReplies {
		if err := observeUDPReply(&got, payload, r.Destination, r, payload, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if len(got.Replies) != 2 || got.ReplyLimitHit {
		t.Fatalf("ceiling is not itself an overflow: %+v", got)
	}
	if err := observeUDPReply(&got, payload, r.Destination, r, payload, time.Now()); !errors.Is(err, ErrUDPReplyLimit) || !got.ReplyLimitHit || len(got.Replies) != 2 {
		t.Fatalf("extra observation: %+v %v", got, err)
	}
}
