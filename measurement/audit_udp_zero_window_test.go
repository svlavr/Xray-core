package measurement

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

func TestAuditUDPZeroWindowSuccessfulWrite(t *testing.T) {
	r, payload := auditUDPRequest()
	r.ReplyWait = 0
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	c := &udpTestConn{closed: make(chan struct{})}
	readBlocked := make(chan struct{})
	releaseRead := auditUDPRelease(readBlocked)
	t.Cleanup(func() { cancel(); releaseRead(); _ = c.Close() })
	c.write = func(p []byte) (int, error) { <-readBlocked; return len(p), nil }
	c.read = func() (buf.MultiBuffer, error) { releaseRead(); <-c.closed; return nil, io.ErrClosedPipe }
	var got UDPEchoReceipt
	done := make(chan error, 1)
	go func() { done <- runUDPTrain(ctx, c, r, payload, time.Now(), &got) }()
	err := auditUDPResult(t, done)
	if err != nil || ctx.Err() != nil || !got.WindowComplete || len(got.Sends) != 1 {
		t.Fatalf("successful zero window: %+v, error=%v, caller error=%v", got, err, ctx.Err())
	}
	send := got.Sends[0]
	if send.Sequence != 0 || send.Scheduled != 0 || send.WriteReturned == nil || send.Error != nil || send.WriterBytes != len(payload) || !send.WriterBytesObserved {
		t.Fatalf("successful zero window lost full write facts: %+v", send)
	}
	t.Logf("ReplyWait=%s WindowComplete=%t WriterBytes=%d WriterBytesObserved=%t error=%v", r.ReplyWait, got.WindowComplete, send.WriterBytes, send.WriterBytesObserved, err)
}

func TestAuditUDPZeroWindowAfterEarlyReceiverClose(t *testing.T) {
	r, payload := auditUDPRequest()
	r.ReplyWait = 0
	native := errors.New("audit zero-window native UDP read error")
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	accepted, release := make(chan struct{}), make(chan struct{})
	releaseWrite := auditUDPRelease(release)
	c := &udpTestConn{closed: make(chan struct{})}
	t.Cleanup(func() { cancel(); releaseWrite(); _ = c.Close() })
	c.write = func(p []byte) (int, error) { close(accepted); <-release; return len(p), nil }
	c.read = func() (buf.MultiBuffer, error) {
		select {
		case <-accepted:
			return nil, native
		case <-c.closed:
			return nil, io.ErrClosedPipe
		}
	}
	var got UDPEchoReceipt
	done := make(chan error, 1)
	go func() { done <- runUDPTrain(ctx, c, r, payload, time.Now(), &got) }()
	auditUDPAwait(t, c.closed, "receiver-triggered Close before final write return")
	if err := ctx.Err(); err != nil {
		t.Fatalf("caller budget expired before receiver ordering barrier: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("reported joined train before releasing writer: %v", err)
	default:
	}
	releaseWrite()
	err := auditUDPResult(t, done)
	if !errors.Is(err, native) || got.WindowComplete || len(got.Sends) != 1 {
		t.Fatalf("early receiver termination with zero window: %+v, %v", got, err)
	}
	send := got.Sends[0]
	if send.Sequence != 0 || send.Scheduled != 0 || send.WriteReturned == nil || send.Error != nil || send.WriterBytes != len(payload) || !send.WriterBytesObserved {
		t.Fatalf("early receiver termination lost full write facts: %+v, %v", send, err)
	}
	t.Logf("ordering=write-accepted,receiver-triggered-close,write-return ReplyWait=%s WindowComplete=%t native-error=%v WriterBytes=%d WriterBytesObserved=%t", r.ReplyWait, got.WindowComplete, errors.Is(err, native), send.WriterBytes, send.WriterBytesObserved)
}
