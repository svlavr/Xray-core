package mux

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type lateCountWriter struct {
	buf.Writer
	calls atomic.Int32
}

func (w *lateCountWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls.Add(1)
	return w.Writer.WriteMultiBuffer(mb)
}

type latePayloadWriter struct {
	body        string
	destination net.Destination
}

func (w *latePayloadWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.body += mb.String()
	if len(mb) > 0 && mb[0].UDP != nil {
		w.destination = *mb[0].UDP
	}
	return nil
}

func lateBodies(parts ...string) *buf.BufferedReader {
	var wire []byte
	for _, part := range parts {
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(part)))
		wire = append(wire, part...)
	}
	return &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(wire))}
}

func TestMuxLateIDKeepsSiblingProgress(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, packet := range []bool{false, true} {
			for _, completed := range []bool{false, true} {
				name := "client"
				if server {
					name = "server"
				}
				if packet {
					name += "-udp"
				} else {
					name += "-tcp"
				}
				if completed {
					name += "-retired"
				} else {
					name += "-pending"
				}
				t.Run(name, func(t *testing.T) {
					m := NewSessionManager()
					carrier := &blockedCarrier{entered: make(chan struct{}), release: make(chan struct{})}
					release := sync.OnceFunc(func() { close(carrier.release) })
					t.Cleanup(release)
					counted := &lateCountWriter{Writer: carrier}
					input, send := pipe.New()
					send.Close()
					var keep func(*FrameMetadata, *buf.BufferedReader) error
					var old *Session
					returned := make(chan struct{})
					if server {
						worker := &ServerWorker{sessionManager: m, link: &transport.Link{Writer: counted}}
						keep = worker.handleStatusKeep
						old = &Session{ID: 1, parent: m, input: input, output: buf.Discard, server: true}
						m.Add(old)
						go func() { handle(context.Background(), old, counted); close(returned) }()
					} else {
						worker := &ClientWorker{sessionManager: m, done: done.New(), link: transport.Link{Writer: counted}}
						keep = worker.handleStatusKeep
						ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 80)}})
						worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: buf.Discard})
						old, _ = m.Get(1)
					}
					muxWait(t, carrier.entered)
					old.Close(false)
					if completed {
						release()
						if server {
							muxWait(t, returned)
						}
					}
					sink := new(latePayloadWriter)
					kind := protocol.TransferTypeStream
					target := net.TCPDestination(net.LocalHostIP, 80)
					if packet {
						kind = protocol.TransferTypePacket
						target = net.UDPDestination(net.LocalHostIP, 53)
					}
					sibling := &Session{ID: 2, parent: m, output: sink, transferType: kind}
					m.Add(sibling)
					reader := lateBodies("late payload", "sibling payload")
					result := make(chan error, 1)
					go func() {
						if err := keep(&FrameMetadata{SessionID: 1, Option: OptionData, Target: target}, reader); err != nil {
							result <- err
							return
						}
						result <- keep(&FrameMetadata{SessionID: 2, Option: OptionData, Target: target}, reader)
					}()
					if err := retainedResult(t, result); err != nil {
						t.Fatal(err)
					}
					if sink.body != "sibling payload" || packet && sink.destination != target {
						t.Fatalf("sibling lost: %+v", sink)
					}
					if counted.calls.Load() != 1 {
						t.Fatal("late frame emitted a second END")
					}
					release()
					m.Close()
				})
			}
		}
	}
}

func TestMuxNeverAdmittedIDRetainsNativeEnd(t *testing.T) {
	for _, server := range []bool{false, true} {
		var wire bytes.Buffer
		m := NewSessionManager()
		output := &buf.SequentialWriter{Writer: &wire}
		var keep func(*FrameMetadata, *buf.BufferedReader) error
		if server {
			keep = (&ServerWorker{sessionManager: m, link: &transport.Link{Writer: output}}).handleStatusKeep
		} else {
			keep = (&ClientWorker{sessionManager: m, link: transport.Link{Writer: output}}).handleStatusKeep
		}
		reader := lateBodies("unknown")
		if err := keep(&FrameMetadata{SessionID: 99, Option: OptionData}, reader); err != nil {
			t.Fatal(err)
		}
		var meta FrameMetadata
		if err := meta.Unmarshal(&wire, false); err != nil || meta.SessionID != 99 || meta.SessionStatus != SessionStatusEnd {
			t.Fatalf("unknown END: %+v %v", meta, err)
		}
		if _, err := reader.ReadByte(); err != io.EOF {
			t.Fatalf("unknown frame not drained: %v", err)
		}
	}
}

func TestMuxSeenIDBoundAndReuse(t *testing.T) {
	m := NewSessionManager()
	old := &Session{ID: 65535, parent: m, output: buf.Discard, server: true}
	m.Add(old)
	old.finishServer()
	if len(m.seen) != 1024 || cap(m.seen) != 1024 {
		t.Fatal("seen state exceeded 8 KiB")
	}
	if s, seen := m.lookup(65535, false); s != nil || !seen {
		t.Fatal("retired ID forgotten")
	}
	next := &Session{ID: 65535, parent: m, output: buf.Discard}
	if !m.Add(next) {
		t.Fatal("valid native server ID reuse rejected")
	}
	if s, _ := m.lookup(65535, false); s != next {
		t.Fatal("seen bit hid live replacement")
	}
	m.Close()
}

func TestMuxClientRetiredIDUsesAllocationCount(t *testing.T) {
	m := NewSessionManager()
	m.count = 65533
	old := m.allocate(&ClientStrategy{}, &Session{output: buf.Discard})
	old.Close(false)
	if s, seen := m.lookup(65534, true); s != nil || !seen {
		t.Fatal("client forgot its last allocated ID")
	}
	for _, id := range []uint16{0, 65535} {
		if _, seen := m.lookup(id, true); seen {
			t.Fatalf("never-allocated ID %d was admitted", id)
		}
	}
	last := m.allocate(&ClientStrategy{}, &Session{output: buf.Discard})
	if s, _ := m.lookup(65535, true); s != last {
		t.Fatal("live client child hidden")
	}
	last.Close(false)
	if s, seen := m.lookup(65535, true); s != nil || !seen {
		t.Fatal("last ID forgotten")
	}
	if m.Allocate(&ClientStrategy{}) != nil {
		t.Fatal("client ID wrapped")
	}
	if len(m.seen) != 0 || cap(m.seen) != 0 {
		t.Fatal("client allocated server ID history")
	}
	m.Close()
}
