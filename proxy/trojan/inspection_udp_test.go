package trojan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type inspectionPacketWrite func([]byte) (int, error)

func (f inspectionPacketWrite) Write(p []byte) (int, error) { return f(p) }

func TestTrojanPacketWriteErrorsAndBufferRelease(t *testing.T) {
	for _, mode := range []string{"full-error", "second-short-nil", "encode-error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			writer := &PacketWriter{Target: net.UDPDestination(net.LocalHostIP, 53), Writer: inspectionPacketWrite(func(p []byte) (int, error) {
				calls++
				if mode == "full-error" {
					return len(p), errors.New("after complete packet")
				}
				if calls == 2 {
					return len(p) - 1, nil
				}
				return len(p), nil
			})}
			first := buf.New()
			first.WriteString("first")
			mb := buf.MultiBuffer{first}
			if mode == "encode-error" {
				first.Clear()
				first.Extend(buf.Size)
			}
			if mode == "second-short-nil" {
				second := buf.New()
				second.WriteString("second")
				mb = append(mb, second)
			}
			err := writer.WriteMultiBuffer(mb)
			if err == nil {
				t.Fatalf("native error behavior changed: %v", err)
			}
			if mode == "second-short-nil" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short packet write did not preserve its error: %v", err)
			}
			for _, b := range mb {
				if !b.IsEmpty() {
					t.Fatal("packet buffer was not released")
				}
			}
			wantCalls := 1
			if mode == "second-short-nil" {
				wantCalls = 2
			}
			if mode == "encode-error" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("write calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

type inspectionLatePacketReader struct {
	first    *bytes.Reader
	blocked  chan struct{}
	release  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func (r *inspectionLatePacketReader) Read(p []byte) (int, error) {
	if r.first.Len() != 0 {
		return r.first.Read(p)
	}
	r.once.Do(func() { close(r.blocked) })
	<-r.release
	close(r.finished)
	return 0, io.EOF
}

type inspectionRejectPacketDispatcher struct{ routing.Dispatcher }

func (inspectionRejectPacketDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errors.New("test route rejection")
}

func TestTrojanUDPRequestCancellationUnblocksParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{}})
	var wire bytes.Buffer
	packetWriter := &PacketWriter{Writer: &wire, Target: net.UDPDestination(net.LocalHostIP, 53)}
	payload := buf.New()
	payload.WriteString("admitted request")
	if err := packetWriter.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	reader := &inspectionLatePacketReader{first: bytes.NewReader(wire.Bytes()), blocked: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(reader.release) }) })
	server := &Server{cone: true}
	policy := policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Hour, UplinkOnly: time.Hour, DownlinkOnly: time.Hour}}
	returned := make(chan error, 1)
	go func() {
		returned <- server.handleUDPPayload(ctx, policy, &PacketReader{Reader: reader}, packetWriter, inspectionRejectPacketDispatcher{})
	}()
	select {
	case <-reader.blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach pending read")
	}
	cancel()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("native task.Run did not return on cancellation")
	}
	releaseOnce.Do(func() { close(reader.release) })
	select {
	case <-reader.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("late native reader remained blocked")
	}
}
