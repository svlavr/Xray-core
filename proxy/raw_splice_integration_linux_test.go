//go:build linux || android

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func rawSpliceContext(t *testing.T, dst net.Conn, ready int) (context.Context, *session.Inbound, *signal.ActivityTimer) {
	t.Helper()
	inbound := &session.Inbound{Conn: dst, CanSpliceCopy: ready}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	timer := signal.CancelAfterInactivity(ctx, func() {}, time.Hour)
	t.Cleanup(func() { timer.SetTimeout(0) })
	return ctx, inbound, timer
}

// A completed Vision raw write makes native splice eligible. Observation keeps
// the same writer receipt through later batches; ordinary use retains ReadFrom.
func TestRawSpliceCallerReadyPrefix(t *testing.T) {
	for _, observed := range []bool{false, true} {
		name := "native"
		if observed {
			name = "observed"
		}
		t.Run(name, func(t *testing.T) {
			sourceWriter, sourceReader := newRawTCPPair(t)
			destinationWriter, destinationReader := newRawTCPPair(t)
			readCounter, writeCounter, userCounter := new(rawSpliceTestCounter), new(rawSpliceTestCounter), new(rawSpliceTestCounter)
			destination := &stat.CounterConnection{Connection: destinationWriter, WriteCounter: writeCounter}
			ctx, inbound, timer := rawSpliceContext(t, destination, 2)
			exchange := &rawSpliceTestExchange{added: make(chan uint64, 8)}
			state := NewTrafficState(bytes.Repeat([]byte{0xaa}, 16))
			state.NumberOfPacketToFilter = 0
			state.Inbound.IsPadding = false
			state.Inbound.DownlinkWriterDirectCopy = true
			vision := NewVisionWriter(buf.NewWriter(destination), state, false, ctx, destination, nil, nil)
			if observed {
				buf.AttachWriterReceipt(vision, exchange)
			}
			writer := &dispatcher.SizeStatWriter{Writer: vision, Counter: userCounter}
			result := make(chan error, 1)
			go func() {
				result <- CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: sourceReader, ReadCounter: readCounter}, destination, writer, timer, nil)
			}()
			prefix, raw := []byte("retained-prefix"), []byte("then-native-raw")
			for _, payload := range [][]byte{prefix, raw} {
				if _, err := sourceWriter.Write(payload); err != nil {
					t.Fatal(err)
				}
				destinationReader.SetReadDeadline(time.Now().Add(2 * time.Second))
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(destinationReader, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("ordered prefix changed: %q", got)
				}
				if observed {
					select {
					case <-exchange.added:
					case <-time.After(2 * time.Second):
						t.Fatal("no pre-EOF receipt")
					}
				}
			}
			if err := sourceWriter.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("raw caller did not end")
			}
			want := int64(len(prefix) + len(raw))
			for _, counter := range []*rawSpliceTestCounter{readCounter, writeCounter, userCounter} {
				if counter.Value() != want {
					t.Fatalf("native counter=%d want=%d", counter.Value(), want)
				}
			}
			if inbound.CanSpliceCopy != 1 {
				t.Fatal("Vision did not publish completed raw transition")
			}
			if observed {
				assertRawSpliceReceipts(t, want, exchange)
			} else if exchange.downlink.Load() != 0 {
				t.Fatal("ordinary copy unexpectedly credited observation")
			}
		})
	}
}

type rawSplicePrefixConn struct {
	net.Conn
	limit int
}

func (c *rawSplicePrefixConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p[:min(c.limit, len(p))])
	if err != nil {
		return n, err
	}
	return n, io.ErrClosedPipe
}

func TestRawSpliceCallerFailedWriteAcceptedPrefix(t *testing.T) {
	source, peer := net.Pipe()
	t.Cleanup(func() { source.Close(); peer.Close() })
	destinationWriter, destinationReader := newRawTCPPair(t)
	lower := &rawSplicePrefixConn{Conn: destinationWriter, limit: 7}
	ctx, _, timer := rawSpliceContext(t, lower, 1)
	exchange := new(rawSpliceTestExchange)
	readCounter, writeCounter, userCounter := new(rawSpliceTestCounter), new(rawSpliceTestCounter), new(rawSpliceTestCounter)
	payload := []byte("consumed-but-only-prefix-accepted")
	sent := make(chan error, 1)
	go func() { _, err := peer.Write(payload); peer.Close(); sent <- err }()
	writer := rawSpliceObservedWriter(lower, exchange, writeCounter, userCounter)
	err := CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: source, ReadCounter: readCounter}, lower, writer, timer, nil)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("positive-prefix error = %v", err)
	}
	assertRawSpliceReceipts(t, 7, exchange, writeCounter)
	if readCounter.Value() != int64(len(payload)) || userCounter.Value() != int64(len(payload)) {
		t.Fatalf("native consumed=%d offered=%d payload=%d", readCounter.Value(), userCounter.Value(), len(payload))
	}
	destinationReader.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 7)
	if _, err := io.ReadFull(destinationReader, got); err != nil || !bytes.Equal(got, payload[:7]) {
		t.Fatalf("accepted prefix = %q err=%v", got, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestRawSpliceCallerReadvFallback(t *testing.T) {
	source, peer := net.Pipe()
	t.Cleanup(func() { source.Close(); peer.Close() })
	destinationWriter, destinationReader := newRawTCPPair(t)
	ctx, _, timer := rawSpliceContext(t, destinationWriter, 1)
	exchange := new(rawSpliceTestExchange)
	payload := []byte("unsupported-raw-source-readv-fallback")
	go func() { peer.Write(payload); peer.Close() }()
	done := make(chan error, 1)
	writer := buf.NewWriter(destinationWriter)
	writer = buf.AttachWriterReceipt(writer, exchange)
	go func() {
		done <- CopyRawConnIfExist(ctx, source, destinationWriter, writer, timer, nil)
	}()
	destinationReader.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(destinationReader, got); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback did not finish")
	}
	if !bytes.Equal(got, payload) || exchange.downlink.Load() != uint64(len(payload)) {
		t.Fatal("fallback lost, dropped or doubled payload")
	}
}

type rawSpliceReadSignalConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *rawSpliceReadSignalConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(p)
}

// Ready raw admission extends both native timers before entering buffered
// copying. The not-ready control must still obey its configured idle lifetime.
func TestRawSpliceObservedReadyPreservesIdleTimers(t *testing.T) {
	for _, ready := range []int{1, 2} {
		name := "ready"
		if ready != 1 {
			name = "not-ready"
		}
		t.Run(name, func(t *testing.T) {
			sourceWriter, sourceReader := newRawTCPPair(t)
			destinationWriter, destinationReader := newRawTCPPair(t)
			ctx, _, _ := rawSpliceContext(t, destinationWriter, ready)
			source := &rawSpliceReadSignalConn{Conn: sourceReader, entered: make(chan struct{})}
			timedOut := make(chan string, 2)
			cancel := func(which string) func() {
				return func() {
					timedOut <- which
					sourceReader.Close()
				}
			}
			const idle = 50 * time.Millisecond
			timer := signal.CancelAfterInactivity(ctx, cancel("copy"), time.Hour)
			inTimer := signal.CancelAfterInactivity(ctx, cancel("inbound"), time.Hour)
			t.Cleanup(func() { timer.SetTimeout(0); inTimer.SetTimeout(0) })
			exchange := new(rawSpliceTestExchange)
			writer := buf.AttachWriterReceipt(buf.NewWriter(destinationWriter), exchange)
			result := make(chan error, 1)
			timer.SetTimeout(idle)
			inTimer.SetTimeout(idle)
			go func() { result <- CopyRawConnIfExist(ctx, source, destinationWriter, writer, timer, inTimer) }()
			select {
			case <-source.entered:
			case <-time.After(time.Second):
				t.Fatal("raw reader did not enter its idle read")
			}
			if ready != 1 {
				seen := make(map[string]bool)
				for len(seen) != 2 {
					select {
					case which := <-timedOut:
						seen[which] = true
					case <-time.After(time.Second):
						t.Fatal("not-ready control did not retain both short idle timers")
					}
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("idle control lost its source-close error")
					}
				case <-time.After(time.Second):
					t.Fatal("idle cancellation did not unblock the raw reader")
				}
				return
			}
			select {
			case which := <-timedOut:
				t.Fatalf("ready raw copy retained the short %s timeout", which)
			case <-time.After(6 * idle):
			}
			payload := []byte("after-the-original-idle-deadline")
			if _, err := sourceWriter.Write(payload); err != nil {
				t.Fatal(err)
			}
			sourceWriter.CloseWrite()
			destinationReader.SetReadDeadline(time.Now().Add(time.Second))
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(destinationReader, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("ready raw payload after idle: %q err=%v", got, err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("ready raw copy did not complete at EOF")
			}
			assertRawSpliceReceipts(t, int64(len(payload)), exchange)
		})
	}
}
