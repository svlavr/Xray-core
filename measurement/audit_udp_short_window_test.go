package measurement

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// One nanosecond is a legal positive edge budget, not a real-network timing
// claim. The fixture proves early receiver-triggered Close before the final
// write returns; it does not observe timer/Done select readiness. A sample with
// WindowComplete=true violates that ordering's completion meaning. Conversely,
// no failures in this bounded sample set cannot disprove a selection race.
func TestAuditUDPPositiveShortWindowAfterEarlyReceiverClose(t *testing.T) {
	const samples = 64
	complete := 0
	for sample := range samples {
		if auditUDPShortWindowSample(t, sample) {
			complete++
		}
	}
	t.Logf("ReplyWait=1ns samples=%d WindowComplete-true=%d WindowComplete-false=%d ordering=write-accepted,receiver-triggered-close,write-return; hidden select readiness unobserved", samples, complete, samples-complete)
}

func auditUDPShortWindowSample(t *testing.T, sample int) bool {
	t.Helper()
	r := UDPEchoRequest{
		Route:       Route{Kind: Direct},
		Destination: netip.MustParseAddrPort("127.0.0.1:9"),
		Count:       1,
		PacketBytes: 32,
		ReplyWait:   time.Nanosecond,
		Timeout:     5 * time.Second,
		MaxReplies:  4,
	}
	if err := validateUDPEcho(r); err != nil {
		t.Fatalf("sample=%d fixture must use a valid positive budget: %v", sample, err)
	}
	payload := make([]byte, r.PacketBytes)
	copy(payload, "MUE1")
	native := errors.New("audit short-window native UDP read error")
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	accepted, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
	c := &udpTestConn{closed: make(chan struct{})}
	defer func() { cancel(); releaseWrite(); _ = c.Close() }()
	c.write = func(p []byte) (int, error) { close(accepted); <-release; return len(p), nil }
	c.read = func() (buf.MultiBuffer, error) { <-accepted; return nil, native }
	var got UDPEchoReceipt
	done := make(chan error, 1)
	go func() { done <- runUDPTrain(ctx, c, r, payload, time.Now(), &got) }()
	select {
	case <-c.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("sample=%d fixture timed out waiting for receiver-triggered Close", sample)
	}
	// Before release, successful sending cannot have finished and the positive
	// post-write timer cannot have started. Exclude caller timeout as a cause
	// of Close, so the fixture's native reader error is its shutdown trigger.
	if err := ctx.Err(); err != nil {
		t.Fatalf("sample=%d caller budget expired before ordering barrier: %v", sample, err)
	}
	select {
	case err := <-done:
		t.Fatalf("sample=%d train returned before gated writer joined: %v", sample, err)
	default:
	}
	releaseWrite()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("sample=%d fixture timed out waiting for joined train", sample)
	}
	if !errors.Is(err, native) || len(got.Sends) != 1 {
		t.Fatalf("sample=%d lost native error or send facts: %+v, %v", sample, got, err)
	}
	send := got.Sends[0]
	if send.Sequence != 0 || send.Scheduled != 0 || send.WriteReturned == nil || send.Error != nil || send.WriterBytes != len(payload) || !send.WriterBytesObserved {
		t.Fatalf("sample=%d final write must return complete acceptance: %+v, %v", sample, send, err)
	}
	t.Logf("sample=%d ReplyWait=%s WindowComplete=%t native-error=%v sequence=%d Scheduled=%s WriteStarted=%s WriteReturned=%s WriterBytes=%d WriterBytesObserved=%t WriteError=%v", sample, r.ReplyWait, got.WindowComplete, errors.Is(err, native), send.Sequence, send.Scheduled, send.WriteStarted, *send.WriteReturned, send.WriterBytes, send.WriterBytesObserved, send.Error)
	if got.WindowComplete {
		t.Errorf("sample=%d reported a complete positive window after receiver-triggered Close before final write return", sample)
	}
	return got.WindowComplete
}
