package mux

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestAllocateWithLinkPublishesCompleteClientSession(t *testing.T) {
	m := NewSessionManager()
	input, inputWriter := pipe.New(pipe.WithoutSizeLimit())
	outputReader, output := pipe.New(pipe.WithoutSizeLimit())
	t.Cleanup(func() {
		inputWriter.Close()
		outputReader.Interrupt()
	})
	s := m.AllocateWithLink(&ClientStrategy{}, input, output, protocol.TransferTypePacket, nil)
	got, ok := m.Get(s.ID)
	if !ok || got != s || got.input != input || got.output != output || got.transferType != protocol.TransferTypePacket || !got.gated {
		t.Fatalf("incomplete published session: ok=%v session=%+v", ok, got)
	}
}

func TestSessionCloseBeforeGateCleansWithoutStartAndReleasesOnce(t *testing.T) {
	m := NewSessionManager()
	var releases atomic.Int32
	s := m.AllocateWithLink(&ClientStrategy{}, nil, nil, protocol.TransferTypeStream, func() { releases.Add(1) })
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	if got := releases.Load(); got != 0 {
		t.Fatalf("cleanup-only claim released before Dispatch resolved the gate: %d", got)
	}
	if s.startInput() {
		t.Fatal("close-winning session started input")
	}
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("claim released %d times, want 1", got)
	}
}

func TestSessionGateFencesDownlinkUntilAttachResolution(t *testing.T) {
	m := NewSessionManager()
	s := m.AllocateWithLink(&ClientStrategy{}, nil, nil, protocol.TransferTypeStream, nil)
	result := make(chan bool, 1)
	go func() { result <- s.waitForStart() }()
	select {
	case <-result:
		t.Fatal("downlink gate opened before AttachTo resolution")
	case <-time.After(20 * time.Millisecond):
	}
	if !s.startInput() {
		t.Fatal("start gate rejected live session")
	}
	select {
	case started := <-result:
		if !started {
			t.Fatal("downlink gate resolved as cleanup after start won")
		}
	case <-time.After(time.Second):
		t.Fatal("downlink gate did not open")
	}
}

func TestStartedSessionRetainsClaimUntilConsumerReceipt(t *testing.T) {
	m := NewSessionManager()
	var releases atomic.Int32
	s := m.AllocateWithLink(&ClientStrategy{}, nil, nil, protocol.TransferTypeStream, func() { releases.Add(1) })
	if !s.startInput() {
		t.Fatal("start gate rejected live session")
	}
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	if got := releases.Load(); got != 0 {
		t.Fatalf("claim released before consumer receipt: %d", got)
	}
	s.releaseClaim()
	s.releaseClaim()
	if got := releases.Load(); got != 1 {
		t.Fatalf("claim released %d times, want 1", got)
	}
}

type parentLockCheckingScope struct {
	manager  *SessionManager
	unlocked atomic.Bool
}

func (*parentLockCheckingScope) Context(ctx context.Context) context.Context { return ctx }
func (*parentLockCheckingScope) AcquireParticipant() task.ParticipantLease   { return nil }
func (s *parentLockCheckingScope) AfterClose() {
	if s.manager.TryLock() {
		s.unlocked.Store(true)
		s.manager.Unlock()
	}
}

func TestSessionCloseCallsObservationOutsideParentLock(t *testing.T) {
	m := NewSessionManager()
	scope := &parentLockCheckingScope{manager: m}
	input, inputWriter := pipe.New(pipe.WithoutSizeLimit())
	defer inputWriter.Close()
	s := m.AllocateWithLink(&ClientStrategy{}, input, buf.Discard, protocol.TransferTypeStream, nil)
	s.flowScope = session.MuxSessionObservation(scope)
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	if !scope.unlocked.Load() {
		t.Fatal("AfterClose ran while SessionManager lock was held")
	}
}
