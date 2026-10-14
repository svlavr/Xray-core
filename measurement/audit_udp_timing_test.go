package measurement

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

func auditUDPAwait(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatalf("fixture timed out waiting for %s", label)
	}
}

func auditUDPResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("fixture timed out waiting for joined train")
		return nil
	}
}

func auditUDPRelease(event chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(event) }) }
}

func auditUDPRequest() (UDPEchoRequest, []byte) {
	r := UDPEchoRequest{
		Route:       Route{Kind: Direct},
		Destination: netip.MustParseAddrPort("127.0.0.1:9"),
		Count:       1,
		PacketBytes: 32,
		ReplyWait:   20 * time.Millisecond,
		Timeout:     5 * time.Second,
		MaxReplies:  4,
	}
	payload := make([]byte, r.PacketBytes)
	copy(payload, "MUE1")
	return r, payload
}

// The timings are observations of this intentional stalled-writer workload.
// They do not assert a pacing tolerance, network delivery or performance result.
func TestAuditUDPAbsoluteSlotsAfterStalledWrite(t *testing.T) {
	for _, equalSpacing := range []bool{false, true} {
		name := "absolute-slots"
		if equalSpacing {
			name = "equal-spacing-control"
		}
		t.Run(name, func(t *testing.T) {
			r, payload := auditUDPRequest()
			r.Count, r.Interval = 4, 100*time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
			firstAccepted, release := make(chan struct{}), make(chan struct{})
			releaseWrite := auditUDPRelease(release)
			c := &udpTestConn{closed: make(chan struct{})}
			t.Cleanup(func() { cancel(); releaseWrite(); _ = c.Close() })
			started := time.Now()
			type writeSample struct {
				sequence           uint32
				accepted, returned time.Duration
			}
			var samples []writeSample // Writer-owned until done is received.
			c.write = func(p []byte) (int, error) {
				sequence := binary.BigEndian.Uint32(p[20:24])
				accepted := time.Since(started)
				if sequence == 0 {
					close(firstAccepted)
					<-release
				}
				samples = append(samples, writeSample{sequence, accepted, time.Since(started)})
				return len(p), nil
			}
			c.read = func() (buf.MultiBuffer, error) { <-c.closed; return nil, io.ErrClosedPipe }
			var got UDPEchoReceipt
			done := make(chan error, 1)
			go func() {
				if !equalSpacing {
					done <- runUDPTrain(ctx, c, r, payload, started, &got)
					return
				}
				// Test-only control: the same initial stall, followed by a wait
				// between completed writes. This is not a runtime proposal.
				wire := append([]byte(nil), payload...)
				for i := range r.Count {
					if i > 0 {
						select {
						case <-time.After(r.Interval):
						case <-ctx.Done():
							done <- ctx.Err()
							return
						}
					}
					binary.BigEndian.PutUint32(wire[20:24], uint32(i))
					if _, err := c.Write(wire); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			auditUDPAwait(t, firstAccepted, "first accepted write")
			// Train start precedes the first write. Waiting Count intervals
			// from its acceptance places every absolute slot in the past.
			select {
			case <-time.After(time.Duration(r.Count) * r.Interval):
			case <-ctx.Done():
				t.Fatal("fixture budget expired before releasing stalled write")
			}
			released := time.Since(started)
			releaseWrite()
			if err := auditUDPResult(t, done); err != nil {
				t.Fatal(err)
			}
			if len(samples) != r.Count {
				t.Fatalf("write samples: %+v", samples)
			}
			t.Logf("mode=%s interval=%s first-write-release=%s", name, r.Interval, released)
			for i, sample := range samples {
				if sample.sequence != uint32(i) {
					t.Fatalf("write sequence: %+v", samples)
				}
				var gap time.Duration
				if i > 0 {
					gap = sample.accepted - samples[i-1].returned
				}
				t.Logf("sequence=%d accepted=%s returned=%s gap-after-previous-return=%s", sample.sequence, sample.accepted, sample.returned, gap)
			}
			if equalSpacing {
				return
			}
			if !got.WindowComplete || len(got.Sends) != r.Count {
				t.Fatalf("train receipt: %+v", got)
			}
			for i, send := range got.Sends {
				if send.Scheduled != time.Duration(i)*r.Interval || send.WriteReturned == nil || send.WriterBytes != len(payload) || !send.WriterBytesObserved || send.Error != nil {
					t.Fatalf("send facts: %+v", send)
				}
				t.Logf("sequence=%d Scheduled=%s WriteStarted=%s WriteReturned=%s", send.Sequence, send.Scheduled, send.WriteStarted, *send.WriteReturned)
			}
		})
	}
}

func TestAuditUDPEarlyReaderErrorBeforeWriteReturn(t *testing.T) {
	r, payload := auditUDPRequest()
	native := errors.New("audit early native UDP read error")
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	accepted, release := make(chan struct{}), make(chan struct{})
	releaseWrite := auditUDPRelease(release)
	c := &udpTestConn{closed: make(chan struct{})}
	t.Cleanup(func() { cancel(); releaseWrite(); _ = c.Close() })
	c.write = func(p []byte) (int, error) { close(accepted); <-release; return len(p), nil }
	c.read = func() (buf.MultiBuffer, error) { <-accepted; return nil, native }
	var got UDPEchoReceipt
	done := make(chan error, 1)
	go func() { done <- runUDPTrain(ctx, c, r, payload, time.Now(), &got) }()
	// Close proves the receiver's error reached shutdown while the accepted
	// writer is still gated; this is not a callback-return or timing guess.
	auditUDPAwait(t, c.closed, "receiver-triggered connection Close")
	select {
	case err := <-done:
		t.Fatalf("reported joined train before releasing writer: %v", err)
	default:
	}
	releaseWrite()
	err := auditUDPResult(t, done)
	if !errors.Is(err, native) || got.WindowComplete || len(got.Sends) != 1 || got.Sends[0].WriteReturned == nil || got.Sends[0].Error != nil || got.Sends[0].WriterBytes != len(payload) {
		t.Fatalf("early receiver termination: %+v, %v", got, err)
	}
	t.Logf("ordering=write-accepted,reader-error,connection-close,write-return ReplyWait=%s WindowComplete=%t native-error=%v", r.ReplyWait, got.WindowComplete, errors.Is(err, native))
}

type auditUDPBarrierCloseConn struct {
	*udpTestConn
	closeEntered chan struct{}
	finishClose  chan struct{}
	closeOnce    sync.Once
}

func (c *auditUDPBarrierCloseConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeEntered); <-c.finishClose; _ = c.udpTestConn.Close() })
	return nil
}

func TestAuditUDPFullWindowThenLateCancellation(t *testing.T) {
	r, payload := auditUDPRequest()
	ctx, cancel := context.WithCancel(context.Background())
	c := &auditUDPBarrierCloseConn{
		udpTestConn:  &udpTestConn{closed: make(chan struct{})},
		closeEntered: make(chan struct{}),
		finishClose:  make(chan struct{}),
	}
	finishClose := auditUDPRelease(c.finishClose)
	t.Cleanup(func() { cancel(); finishClose(); _ = c.Close() })
	readBlocked := make(chan struct{})
	c.write = func(p []byte) (int, error) { <-readBlocked; return len(p), nil }
	c.read = func() (buf.MultiBuffer, error) { close(readBlocked); <-c.closed; return nil, io.ErrClosedPipe }
	var got UDPEchoReceipt
	done := make(chan error, 1)
	go func() { done <- runUDPTrain(ctx, c, r, payload, time.Now(), &got) }()
	// No read error or caller cancellation can end this fixture before Close.
	// Entering Close therefore proves the full observation timer was selected.
	auditUDPAwait(t, c.closeEntered, "timer-triggered connection Close")
	cancel()
	finishClose()
	trainErr := auditUDPResult(t, done)
	// Match UDPEcho's public return boundary, which joins caller context error
	// after runUDPTrain. Its return error and its observed window are distinct.
	err := errors.Join(trainErr, ctx.Err())
	if !got.WindowComplete || !errors.Is(err, context.Canceled) || len(got.Sends) != 1 || got.Sends[0].WriteReturned == nil || got.Sends[0].Error != nil {
		t.Fatalf("late caller cancellation: %+v, train error=%v, boundary error=%v", got, trainErr, err)
	}
	t.Logf("ordering=write-return,full-window,close-entered,caller-cancel,close-finished ReplyWait=%s WindowComplete=%t train-error=%v boundary-error=%v", r.ReplyWait, got.WindowComplete, trainErr, err)
}
