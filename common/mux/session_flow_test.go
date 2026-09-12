package mux

import (
	"testing"

	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestMuxSessionAndCarrierCloseKeepSiblingRootsIndependent(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	carrier := registry.NewMuxCarrierObservation()
	firstDestination := net.TCPDestination(net.DomainAddress("first.example"), 443)
	secondDestination := net.TCPDestination(net.DomainAddress("second.example"), 443)
	firstScope := carrier.NewTCPSession([8]byte{}, firstDestination, "").(*flow_observation.MuxSessionScope)
	secondScope := carrier.NewTCPSession([8]byte{}, secondDestination, "").(*flow_observation.MuxSessionScope)
	firstHandle := registry.AdmitMuxTCP(firstScope, firstDestination)
	secondHandle := registry.AdmitMuxTCP(secondScope, secondDestination)
	if firstHandle == nil || secondHandle == nil {
		t.Fatal("MUX sibling scopes were not admitted")
	}

	manager := NewSessionManager()
	first, firstCleanup := newObservedMuxSession(t, manager, 1, firstScope)
	defer firstCleanup()
	second, secondCleanup := newObservedMuxSession(t, manager, 2, secondScope)
	defer secondCleanup()
	if !manager.Add(first) || !manager.Add(second) {
		t.Fatal("MUX sibling sessions were not added")
	}
	quiesceMuxTestRoot(firstHandle.LogicalRoot())
	quiesceMuxTestRoot(secondHandle.LogicalRoot())

	if err := first.Close(false); err != nil {
		t.Fatal(err)
	}
	if manager.Size() != 1 || firstHandle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal ||
		secondHandle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseOpen {
		t.Fatalf("closing one MUX child changed its sibling: size=%d first=%+v second=%+v", manager.Size(), firstHandle.LogicalRoot().View(), secondHandle.LogicalRoot().View())
	}

	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if secondHandle.LogicalRoot().View().Phase != flow_observation.LifecyclePhaseTerminal {
		t.Fatalf("carrier-owned manager close did not close second child independently: %+v", secondHandle.LogicalRoot().View())
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 2 || snapshot.Records[0].FlowID == snapshot.Records[1].FlowID ||
		snapshot.Records[0].CarrierReference == "" || snapshot.Records[0].CarrierReference != snapshot.Records[1].CarrierReference {
		t.Fatalf("MUX siblings lost identity or carrier correlation: %+v", snapshot.Records)
	}
}

func TestSessionManagerRejectsDuplicateIDWithoutRemovingLiveSession(t *testing.T) {
	manager := NewSessionManager()
	live, liveCleanup := newObservedMuxSession(t, manager, 7, nil)
	defer liveCleanup()
	rejected, rejectedCleanup := newObservedMuxSession(t, manager, 7, nil)
	defer rejectedCleanup()
	if !manager.Add(live) {
		t.Fatal("failed to add live MUX session")
	}
	if manager.Add(rejected) {
		t.Fatal("duplicate MUX session ID replaced live session")
	}
	if got, found := manager.Get(7); !found || got != live || manager.Size() != 1 {
		t.Fatalf("duplicate add changed live MUX session: got=%p live=%p found=%t size=%d", got, live, found, manager.Size())
	}
	if err := rejected.Close(false); err != nil {
		t.Fatal(err)
	}
	if got, found := manager.Get(7); !found || got != live || manager.Size() != 1 {
		t.Fatalf("late close of rejected duplicate removed live MUX session: got=%p live=%p found=%t size=%d", got, live, found, manager.Size())
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if !live.closed || !manager.Closed() || manager.Size() != 0 {
		t.Fatalf("manager close did not retain cleanup semantics: liveClosed=%t managerClosed=%t size=%d", live.closed, manager.Closed(), manager.Size())
	}
}

func TestRejectedDuplicateMuxUDPSessionClosesOnlyItsObservedScope(t *testing.T) {
	registry, err := flow_observation.NewRegistry(flow_observation.Config{MaxRecords: 4, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	destination := net.UDPDestination(net.DomainAddress("packet.example"), 53)
	carrier := registry.NewMuxCarrierObservation()
	scope := carrier.NewUDPSession([8]byte{}, destination, "").(*flow_observation.MuxSessionScope)
	handle := registry.AdmitMuxUDP(scope, destination)
	if handle == nil {
		t.Fatal("failed to admit MUX UDP scope")
	}
	manager := NewSessionManager()
	live, liveCleanup := newObservedMuxSession(t, manager, 9, nil)
	defer liveCleanup()
	rejected, rejectedCleanup := newObservedMuxSession(t, manager, 9, scope)
	defer rejectedCleanup()
	if !manager.Add(live) || manager.Add(rejected) {
		t.Fatal("duplicate MUX UDP session admission did not fail as expected")
	}
	quiesceMuxTestRoot(handle.LogicalRoot())
	if err := rejected.Close(false); err != nil {
		t.Fatal(err)
	}
	if got, found := manager.Get(9); !found || got != live {
		t.Fatalf("rejected MUX UDP close removed live sibling: got=%p live=%p found=%t", got, live, found)
	}
	view := handle.LogicalRoot().View()
	if view.Phase != flow_observation.LifecyclePhaseTerminal || view.Terminal == nil ||
		view.Terminal.TerminalClass != "" || view.Terminal.TechnicalErrorCategory != "" {
		t.Fatalf("rejected MUX UDP close did not retain no-cause terminal: %+v", view)
	}
}

func newObservedMuxSession(t testing.TB, manager *SessionManager, id uint16, scope *flow_observation.MuxSessionScope) (*Session, func()) {
	t.Helper()
	inputReader, inputWriter := pipe.New(pipe.WithoutSizeLimit())
	outputReader, outputWriter := pipe.New(pipe.WithoutSizeLimit())
	return &Session{
		input:        inputReader,
		output:       outputWriter,
		parent:       manager,
		ID:           id,
		transferType: protocol.TransferTypeStream,
		flowScope:    scope,
	}, func() {
		common.Interrupt(inputReader)
		common.Interrupt(inputWriter)
		common.Interrupt(outputReader)
		common.Interrupt(outputWriter)
	}
}

func quiesceMuxTestRoot(root *flow_observation.LogicalFlowRoot) {
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
}

func TestMuxObservationSourceDoesNotRequireLocalMetadata(t *testing.T) {
	meta := FrameMetadata{
		SessionID:     1,
		SessionStatus: SessionStatusNew,
		Target:        net.TCPDestination(net.DomainAddress("target.example"), 443),
		Inbound: &session.Inbound{
			Source: net.TCPDestination(net.DomainAddress("source-only.example"), 1234),
		},
	}
	frame := buf.New()
	defer frame.Release()
	if err := meta.WriteTo(frame); err != nil {
		t.Fatal(err)
	}
	var decoded FrameMetadata
	if err := decoded.Unmarshal(frame, true); err != nil {
		t.Fatal(err)
	}
	if decoded.Inbound == nil || !decoded.Inbound.Source.IsValid() || decoded.Inbound.Local.IsValid() {
		t.Fatalf("source-only reverse MUX frame did not round-trip exactly: %+v", decoded.Inbound)
	}
	if got := muxObservationSource(&decoded); got != "tcp:source-only.example:1234" {
		t.Fatalf("source-only reverse MUX metadata was dropped: %q", got)
	}
	if got := muxObservationSource(&FrameMetadata{Inbound: new(session.Inbound)}); got != "" {
		t.Fatalf("invalid reverse MUX source was fabricated: %q", got)
	}
}
