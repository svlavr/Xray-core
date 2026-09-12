package kcp

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func lifecycleConfig() *Config {
	return &Config{
		Mtu:              1350,
		Tti:              10,
		UplinkCapacity:   5,
		DownlinkCapacity: 20,
		CwndMultiplier:   20,
		MaxSendingWindow: 2 * 1024 * 1024,
	}
}

func lifecyclePacket(conv uint16) *buf.Buffer {
	segment := NewCmdOnlySegment()
	segment.Conv = conv
	segment.Cmd = CommandPing
	payload := buf.New()
	segment.Serialize(payload.Extend(segment.ByteSize()))
	return payload
}

func TestListenerCloseJoinsPacketSessionAndCallbackReceipts(t *testing.T) {
	var tasks task.Lifecycle
	ctx := internet.ContextWithInboundLifecycle(context.Background(), &internet.InboundLifecycle{Tasks: &tasks})
	callbackStarted := make(chan struct{})
	callbackDone := make(chan struct{})
	listener, err := NewListener(ctx, net.LocalHostIP, 0, &internet.MemoryStreamConfig{
		ProtocolName:     ProtocolName,
		ProtocolSettings: lifecycleConfig(),
	}, func(conn stat.Connection) {
		defer close(callbackDone)
		if !internet.AcceptInboundHandoff(conn) {
			return
		}
		close(callbackStarted)
		_, _ = conn.Read(make([]byte, 1))
	})
	if err != nil {
		t.Fatal(err)
	}

	listener.OnReceive(lifecyclePacket(7), net.UDPDestination(net.LocalHostIP, 12345))
	select {
	case <-callbackStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("mKCP callback did not start")
	}

	tasks.Seal()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	select {
	case <-callbackDone:
	default:
		t.Fatal("listener lifecycle completed before callback receipt")
	}
	if got := listener.ActiveConnections(); got != 0 {
		t.Fatalf("active sessions after joined close = %d, want 0", got)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("repeated close changed completion: %v", err)
	}
}

func TestListenerSealRejectsProvisionalSession(t *testing.T) {
	var tasks task.Lifecycle
	ctx := internet.ContextWithInboundLifecycle(context.Background(), &internet.InboundLifecycle{Tasks: &tasks})
	called := make(chan struct{}, 1)
	listener, err := NewListener(ctx, net.LocalHostIP, 0, &internet.MemoryStreamConfig{
		ProtocolName:     ProtocolName,
		ProtocolSettings: lifecycleConfig(),
	}, func(stat.Connection) { called <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	tasks.Seal()
	listener.OnReceive(lifecyclePacket(8), net.UDPDestination(net.LocalHostIP, 12346))
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	select {
	case <-called:
		t.Fatal("sealed listener published a provisional session")
	default:
	}
	if got := listener.ActiveConnections(); got != 0 {
		t.Fatalf("sealed listener retained %d sessions", got)
	}
}

func TestListenerReleaseFollowsCallbackReceipt(t *testing.T) {
	var tasks task.Lifecycle
	ctx := internet.ContextWithInboundLifecycle(context.Background(), &internet.InboundLifecycle{Tasks: &tasks})
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	listener, err := NewListener(ctx, net.LocalHostIP, 0, &internet.MemoryStreamConfig{
		ProtocolName:     ProtocolName,
		ProtocolSettings: lifecycleConfig(),
	}, func(conn stat.Connection) {
		if !internet.AcceptInboundHandoff(conn) {
			return
		}
		close(callbackStarted)
		<-callbackRelease
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.OnReceive(lifecyclePacket(10), net.UDPDestination(net.LocalHostIP, 12347))
	select {
	case <-callbackStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("mKCP callback did not start")
	}

	tasks.Seal()
	if err := listener.Stop(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- listener.Wait() }()
	select {
	case err := <-waitDone:
		t.Fatalf("listener joined before callback returned: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if outputReleased(listener.closing[0]) {
		t.Fatal("connection buffers were released before callback receipt")
	}
	close(callbackRelease)
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not join callback receipt")
	}
	if outputReleased(listener.closing[0]) {
		t.Fatal("Wait released connection buffers before the release phase")
	}
	if err := listener.Release(); err != nil {
		t.Fatal(err)
	}
	if !outputReleased(listener.closing[0]) {
		t.Fatal("release phase retained the connection output buffer")
	}
}

func outputReleased(conn *Connection) bool {
	retryWriter := conn.output.(*RetryableWriter)
	writer := retryWriter.writer.(*SimpleSegmentWriter)
	writer.Lock()
	defer writer.Unlock()
	return writer.closed && writer.buffer == nil
}

func TestUpdaterStopWaitsForRunningUpdate(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	updater := NewUpdater(10, func() bool { return true }, func() bool { return false }, func() {
		close(started)
		<-release
	})
	updater.WakeUp()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("updater did not start")
	}
	updater.Stop()
	joined := make(chan struct{})
	go func() {
		updater.Wait()
		close(joined)
	}()
	select {
	case <-joined:
		t.Fatal("updater Wait returned before running update completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("updater did not publish its completion receipt")
	}
}

type blockingInput struct {
	started chan struct{}
	stop    chan struct{}
	once    sync.Once
}

func (i *blockingInput) Read([]byte) (int, error) {
	i.once.Do(func() { close(i.started) })
	<-i.stop
	return 0, io.EOF
}

func (i *blockingInput) Close() error {
	select {
	case <-i.stop:
	default:
		close(i.stop)
	}
	return nil
}

func TestConnectionStopUnblocksAndJoinsInputReader(t *testing.T) {
	input := &blockingInput{started: make(chan struct{}), stop: make(chan struct{})}
	conn := NewConnection(ConnMetadata{Conversation: 9}, buf.DiscardBytes, input, lifecycleConfig())
	if !conn.startInput(context.Background(), input, &KCPPacketReader{}) {
		t.Fatal("fresh connection rejected its input reader")
	}
	select {
	case <-input.started:
	case <-time.After(5 * time.Second):
		t.Fatal("input reader did not start")
	}
	if err := conn.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Release(); err != nil {
		t.Fatal(err)
	}
	if conn.tasks.Acquire() {
		conn.tasks.Release()
		t.Fatal("connection admitted work after stop")
	}
}

type blockingWriterCloser struct {
	started   chan struct{}
	unblocked chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func (w *blockingWriterCloser) Write([]byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.unblocked
	return 0, io.ErrClosedPipe
}

func (w *blockingWriterCloser) Close() error {
	w.closeOnce.Do(func() { close(w.unblocked) })
	return nil
}

func TestConnectionStopClosesLowerIOBeforeWorkerCleanup(t *testing.T) {
	writer := &blockingWriterCloser{started: make(chan struct{}), unblocked: make(chan struct{})}
	conn := NewConnection(ConnMetadata{Conversation: 11}, writer, writer, lifecycleConfig())
	payload := buf.New()
	payload.Write([]byte("blocked"))
	if !conn.sendingWorker.Push(payload) {
		payload.Release()
		t.Fatal("failed to queue KCP payload")
	}
	conn.dataUpdater.WakeUp()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("KCP writer did not block")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- conn.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not close lower I/O before taking the sending lock")
	}
	if err := conn.Release(); err != nil {
		t.Fatal(err)
	}
}

type noOpCloser struct{}

func (noOpCloser) Close() error { return nil }

func TestConnectionLocalAndPeerCloseTransitionAtomically(t *testing.T) {
	for i := 0; i < 100; i++ {
		conn := NewConnection(ConnMetadata{Conversation: uint16(100 + i)}, buf.DiscardBytes, noOpCloser{}, lifecycleConfig())
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			_ = conn.Close()
		}()
		go func() {
			defer workers.Done()
			<-start
			conn.OnPeerClosed()
		}()
		close(start)
		workers.Wait()
		if state := conn.State(); state != StateTerminating && state != StateTerminated {
			t.Fatalf("iteration %d lost one close event: state=%v", i, state)
		}
		conn.Terminate()
	}
}

type trackingSegment struct {
	conv     uint16
	released atomic.Bool
}

func (s *trackingSegment) Release()             { s.released.Store(true) }
func (s *trackingSegment) Conversation() uint16 { return s.conv }
func (*trackingSegment) Command() Command       { return CommandPing }
func (*trackingSegment) ByteSize() int32        { return 0 }
func (*trackingSegment) Serialize([]byte)       {}
func (*trackingSegment) parse(uint16, Command, SegmentOption, []byte) (bool, []byte) {
	return false, nil
}

func TestConnectionInputReleasesMismatchedRemainder(t *testing.T) {
	conn := NewConnection(ConnMetadata{Conversation: 12}, buf.DiscardBytes, noOpCloser{}, lifecycleConfig())
	mismatch := &trackingSegment{conv: 13}
	tail := &trackingSegment{conv: 12}
	conn.Input([]Segment{mismatch, tail})
	if !mismatch.released.Load() || !tail.released.Load() {
		t.Fatal("mixed-conversation datagram retained rejected segments")
	}
	conn.Terminate()
}
