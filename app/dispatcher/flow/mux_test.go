package flow

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestMuxAdmissionsShareFlowSequenceAndCarrierCorrelation(t *testing.T) {
	registry := newTestRegistry(t, 8, 16, 64)
	carrier := registry.NewMuxCarrierObservation()
	otherCarrier := registry.NewMuxCarrierObservation()
	if carrier == nil || otherCarrier == nil {
		t.Fatal("MUX carrier correlation was not minted")
	}
	firstDestination := net.TCPDestination(net.DomainAddress("first.example"), 443)
	secondDestination := net.TCPDestination(net.DomainAddress("second.example"), 8443)
	firstScope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, firstDestination, ""))
	first := registry.AdmitMuxTCP(firstScope, firstDestination)
	ordinary := registry.AdmitTCP(context.Background(), "", "tcp:ordinary.example:443", "", ByteScopeLogicalLinkAccepted)
	secondScope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, secondDestination, "tcp:source.example:1234"))
	second := registry.AdmitMuxTCP(secondScope, secondDestination)
	thirdScope := requireMuxSessionScope(t, otherCarrier.NewTCPSession([8]byte{}, firstDestination, ""))
	third := registry.AdmitMuxTCP(thirdScope, firstDestination)
	if first == nil || ordinary == nil || second == nil || third == nil {
		t.Fatal("interleaved TCP/MUX admission failed")
	}
	if !strings.HasSuffix(first.flowID, "0000000000000001") ||
		!strings.HasSuffix(ordinary.flowID, "0000000000000002") ||
		!strings.HasSuffix(second.flowID, "0000000000000003") ||
		!strings.HasSuffix(third.flowID, "0000000000000004") {
		t.Fatalf("flow kinds did not share one registry sequence: %s %s %s %s", first.flowID, ordinary.flowID, second.flowID, third.flowID)
	}

	snapshot := registry.Snapshot()
	firstRecord := muxRecordByID(t, snapshot, first.flowID)
	secondRecord := muxRecordByID(t, snapshot, second.flowID)
	thirdRecord := muxRecordByID(t, snapshot, third.flowID)
	if firstRecord.FlowKind != KindMUXLogical || firstRecord.CarrierReference == "" ||
		firstRecord.CarrierReference != secondRecord.CarrierReference ||
		firstRecord.CarrierReference == thirdRecord.CarrierReference {
		t.Fatalf("MUX carrier correlation is not exact: first=%+v second=%+v third=%+v", firstRecord, secondRecord, thirdRecord)
	}
	if firstRecord.Source != "" || secondRecord.Source != "tcp:source.example:1234" ||
		firstRecord.EffectiveDestination != "" ||
		firstRecord.TrafficOrigin != "" || firstRecord.OriginProof != "" ||
		firstRecord.CarrierProof != "" || firstRecord.TerminalClass != "" ||
		firstRecord.TechnicalErrorCategory != "" || len(firstRecord.Issues) != 0 ||
		firstRecord.Route.ChainCoverage != "" || firstRecord.Route.ChainDisposition != "" {
		t.Fatalf("MUX admission fabricated absent facts or statuses: first=%+v second=%+v", firstRecord, secondRecord)
	}
	events := registry.EventsAfter(0, 64)
	for _, event := range events.Events {
		if event.Type == EventAdmitted && event.Record != nil && event.Record.FlowID == first.flowID && event.Record.EffectiveDestination != "" {
			t.Fatalf("MUX ADMITTED event fabricated effective destination: %+v", event.Record)
		}
	}
	if len(firstRecord.ByteObservations) != 2 {
		t.Fatalf("MUX admission created a noncanonical byte boundary: %+v", firstRecord.ByteObservations)
	}
	for _, observation := range firstRecord.ByteObservations {
		if observation.ByteScope != ByteScopeLogicalLinkAccepted || observation.State != ByteObservationStateProven || !observation.ObservedBytes.Known {
			t.Fatalf("MUX admission has a noncanonical byte observation: %+v", observation)
		}
	}
}

func TestMuxScopePredicateReplayAndForeignRegistryFailObservationClosed(t *testing.T) {
	registry := newTestRegistry(t, 4, 8, 32)
	carrier := registry.NewMuxCarrierObservation()
	tcpDestination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	udpDestination := net.UDPDestination(net.DomainAddress("example.com"), 443)
	if carrier.NewTCPSession([8]byte{1}, tcpDestination, "") != nil ||
		carrier.NewTCPSession([8]byte{}, udpDestination, "") != nil ||
		carrier.NewUDPSession([8]byte{1}, udpDestination, "") != nil ||
		carrier.NewUDPSession([8]byte{}, tcpDestination, "") != nil {
		t.Fatal("TCP, UDP, and XUDP MUX scope predicates overlap")
	}
	before := registry.Snapshot()
	if len(before.Records) != 0 || before.AccountingCoverage.State != AccountingCoverageComplete {
		t.Fatalf("out-of-scope packet path changed coverage: %+v", before)
	}

	scope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, tcpDestination, ""))
	handle := registry.AdmitMuxTCP(scope, tcpDestination)
	if handle == nil {
		t.Fatal("valid MUX scope was not admitted")
	}
	if replay := registry.AdmitMuxTCP(scope, tcpDestination); replay != nil {
		t.Fatal("MUX scope replay created a second flow")
	}
	afterReplay := registry.Snapshot()
	if len(afterReplay.Records) != 1 || afterReplay.AccountingCoverage.State != AccountingCoverageIndeterminate {
		t.Fatalf("MUX replay did not fail observation closed: %+v", afterReplay)
	}

	foreign := newTestRegistry(t, 4, 8, 32)
	foreignScope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, tcpDestination, ""))
	if handle := foreign.AdmitMuxTCP(foreignScope, tcpDestination); handle != nil {
		t.Fatal("foreign registry admitted a MUX scope")
	}
	if len(foreign.Snapshot().Records) != 0 {
		t.Fatal("foreign registry published a partial MUX record")
	}
}

func TestMuxUDPScopeUsesLogicalKindAndSharedSequence(t *testing.T) {
	registry := newTestRegistry(t, 4, 8, 32)
	carrier := registry.NewMuxCarrierObservation()
	tcpDestination := net.TCPDestination(net.DomainAddress("tcp.example"), 443)
	udpDestination := net.UDPDestination(net.DomainAddress("udp.example"), 53)
	tcpScope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, tcpDestination, ""))
	tcp := registry.AdmitMuxTCP(tcpScope, tcpDestination)
	udpScope := requireMuxSessionScope(t, carrier.NewUDPSession([8]byte{}, udpDestination, "udp:source.example:1234"))
	udp := registry.AdmitMuxUDP(udpScope, udpDestination)
	if tcp == nil || udp == nil {
		t.Fatal("decoded MUX TCP/UDP scopes were not admitted")
	}
	if !strings.HasSuffix(tcp.flowID, "0000000000000001") || !strings.HasSuffix(udp.flowID, "0000000000000002") {
		t.Fatalf("MUX UDP did not share registry flow sequence: %s %s", tcp.flowID, udp.flowID)
	}
	record := muxRecordByID(t, registry.Snapshot(), udp.flowID)
	if record.FlowKind != KindMUXLogical || record.OriginalDestination != udpDestination.String() ||
		record.Source != "udp:source.example:1234" || record.CarrierReference == "" ||
		record.TrafficOrigin != "" || record.OriginProof != "" || record.AdmissionCoordinate.Known {
		t.Fatalf("decoded MUX UDP record violates presence-only facts: %+v", record)
	}
	if replay := registry.AdmitMuxUDP(udpScope, udpDestination); replay != nil {
		t.Fatal("replayed MUX UDP scope created a second record")
	}
	if snapshot := registry.Snapshot(); len(snapshot.Records) != 2 || snapshot.AccountingCoverage.State != AccountingCoverageIndeterminate {
		t.Fatalf("MUX UDP replay did not fail observation closed: %+v", snapshot)
	}
}

func TestMuxUDPTwentyThousandSequentialFlowsStayBounded(t *testing.T) {
	const flowCount = 20_000
	registry := newTestRegistry(t, 64, 2, 64)
	carrier := registry.NewMuxCarrierObservation()
	destination := net.UDPDestination(net.DomainAddress("packet.example"), 53)
	for index := 0; index < flowCount; index++ {
		scope := requireMuxSessionScope(t, carrier.NewUDPSession([8]byte{}, destination, ""))
		handle := registry.AdmitMuxUDP(scope, destination)
		if handle == nil {
			t.Fatalf("MUX UDP flow %d was not admitted", index)
		}
		handle.SelectRoot("", "mux-out", "type", destination.String(), "", true, "")
		handle.AddUplink(1)
		handle.AddDownlink(2)
		root := handle.LogicalRoot()
		root.Uplink().Seal()
		root.Uplink().MarkDrained()
		root.Downlink().Seal()
		root.Downlink().MarkDrained()
		scope.AfterClose()
		if view := root.View(); view.Phase != LifecyclePhaseTerminal || view.LifecycleFault != "" || view.AccountingFault != "" {
			t.Fatalf("MUX UDP flow %d did not terminalize cleanly: %+v", index, view)
		}
		if index%32 == 31 {
			_ = registry.Snapshot()
		}
	}
	snapshot := registry.Snapshot()
	if snapshot.DroppedFlowCount != 0 || len(snapshot.Records) > 64 || len(snapshot.CounterSeries) != 2 {
		t.Fatalf("MUX UDP stress exceeded bounds: records=%d series=%d dropped=%d", len(snapshot.Records), len(snapshot.CounterSeries), snapshot.DroppedFlowCount)
	}
	uplink := testSeries(t, snapshot.CounterSeries, DirectionUplink, ByteScopeLogicalLinkAccepted)
	downlink := testSeries(t, snapshot.CounterSeries, DirectionDownlink, ByteScopeLogicalLinkAccepted)
	if uplink.CumulativeBytes != (OptionalUint64{Known: true, Value: flowCount}) ||
		downlink.CumulativeBytes != (OptionalUint64{Known: true, Value: flowCount * 2}) ||
		uplink.ActiveFlowCount != (OptionalUint64{Known: true}) || downlink.ActiveFlowCount != (OptionalUint64{Known: true}) ||
		snapshot.AccountingCoverage.State != AccountingCoverageComplete {
		t.Fatalf("MUX UDP stress lost accounting or retirement: uplink=%+v downlink=%+v coverage=%+v", uplink, downlink, snapshot.AccountingCoverage)
	}
}

func TestTCPOnlyMuxCarrierKeepsUDPObservationOptional(t *testing.T) {
	var carrier session.MuxCarrierObservation = tcpOnlyMuxCarrier{}
	destination := net.UDPDestination(net.DomainAddress("packet.example"), 53)
	if scope := session.MuxUDPSessionObservationFromCarrier(carrier, [8]byte{}, destination, ""); scope != nil {
		t.Fatalf("TCP-only carrier fabricated a UDP observation scope: %T", scope)
	}
}

func TestMuxScopeConcurrentBindMintsOneFlow(t *testing.T) {
	registry := newTestRegistry(t, 4, 8, 32)
	carrier := registry.NewMuxCarrierObservation()
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	scope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, destination, ""))
	start := make(chan struct{})
	results := make(chan *Handle, 2)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	for range 2 {
		go func() {
			defer waitGroup.Done()
			<-start
			results <- registry.AdmitMuxTCP(scope, destination)
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	admitted := 0
	for handle := range results {
		if handle != nil {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("concurrent MUX bind admitted %d flows, want 1", admitted)
	}
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.AccountingCoverage.State != AccountingCoverageIndeterminate {
		t.Fatalf("concurrent MUX replay did not fail observation closed: %+v", snapshot)
	}
}

func TestClientMuxCarrierCorrelationIsSelectedOutboundOnly(t *testing.T) {
	registry := newTestRegistry(t, 8, 16, 64)
	first := registry.AdmitTCP(context.Background(), "", "tcp:first.example:443", "", ByteScopeLogicalLinkAccepted)
	second := registry.AdmitTCP(context.Background(), "", "tcp:second.example:443", "", ByteScopeLogicalLinkAccepted)
	udp := registry.AdmitUDPAssociation(context.Background(), "", "udp:third.example:53", "")
	if first == nil || second == nil || udp == nil {
		t.Fatal("ordinary TCP/UDP admission failed")
	}
	first.SelectRoot("", "mux-out", "handler", "tcp:first.example:443", "", true, CarrierProofUnknown, IssueMuxCarrierF2Required)
	second.SelectRoot("", "mux-out", "handler", "tcp:second.example:443", "", true, CarrierProofUnknown, IssueMuxCarrierF2Required)
	udp.SelectRoot("", "mux-out", "handler", "udp:third.example:53", "", true, CarrierProofUnknown, IssueMuxCarrierF2Required)

	firstCtx := ContextWithHandle(context.Background(), first)
	firstCtx = ContextWithMuxClientSessionObservation(firstCtx, "mux-out")
	firstScope := session.MuxClientSessionObservationFromContext(firstCtx)
	if firstScope == nil {
		t.Fatal("selected outbound did not receive a client MUX scope")
	}
	carrier := firstScope.NewCarrier()
	if carrier == nil {
		t.Fatal("client MUX carrier correlation was not minted")
	}
	carrier.AttachTo(firstScope)

	secondCtx := ContextWithHandle(context.Background(), second)
	secondScope := session.MuxClientSessionObservationFromContext(ContextWithMuxClientSessionObservation(secondCtx, "mux-out"))
	if secondScope == nil {
		t.Fatal("second selected outbound did not receive a client MUX scope")
	}
	carrier.AttachTo(secondScope)
	udpCtx := ContextWithHandle(context.Background(), udp)
	udpScope := session.MuxClientSessionObservationFromContext(ContextWithMuxClientSessionObservation(udpCtx, "mux-out"))
	if udpScope == nil {
		t.Fatal("selected outbound did not retain the UDP association MUX scope")
	}
	carrier.AttachTo(udpScope)

	masked := ContextWithMuxClientSessionObservation(firstCtx, "nested-out")
	if session.MuxClientSessionObservationFromContext(masked) != nil {
		t.Fatal("unselected handler inherited client MUX correlation authority")
	}

	incomingCarrier := registry.NewMuxCarrierObservation()
	destination := net.TCPDestination(net.DomainAddress("decoded.example"), 443)
	decodedScope := requireMuxSessionScope(t, incomingCarrier.NewTCPSession([8]byte{}, destination, ""))
	decoded := registry.AdmitMuxTCP(decodedScope, destination)
	if decoded == nil {
		t.Fatal("decoded MUX admission failed")
	}
	decoded.SelectRoot("", "mux-out", "handler", destination.String(), "", true, "")
	decodedCtx := ContextWithHandle(context.Background(), decoded)
	decodedClientScope := session.MuxClientSessionObservationFromContext(ContextWithMuxClientSessionObservation(decodedCtx, "mux-out"))
	if decodedClientScope == nil {
		t.Fatal("decoded logical flow did not receive its distinct outbound MUX scope")
	}
	carrier.AttachTo(decodedClientScope)

	snapshot := registry.Snapshot()
	firstRecord := muxRecordByID(t, snapshot, first.flowID)
	secondRecord := muxRecordByID(t, snapshot, second.flowID)
	udpRecord := muxRecordByID(t, snapshot, udp.flowID)
	decodedRecord := muxRecordByID(t, snapshot, decoded.flowID)
	if firstRecord.SelectedOutboundCarrierReference == "" ||
		firstRecord.SelectedOutboundCarrierReference != secondRecord.SelectedOutboundCarrierReference ||
		firstRecord.SelectedOutboundCarrierReference != udpRecord.SelectedOutboundCarrierReference ||
		firstRecord.CarrierReference != "" || secondRecord.CarrierReference != "" || udpRecord.CarrierReference != "" ||
		udpRecord.FlowKind != KindUDPAssociation {
		t.Fatalf("client MUX worker correlation is not exact: first=%+v second=%+v udp=%+v", firstRecord, secondRecord, udpRecord)
	}
	if decodedRecord.CarrierReference == "" || decodedRecord.SelectedOutboundCarrierReference == "" ||
		decodedRecord.CarrierReference == decodedRecord.SelectedOutboundCarrierReference ||
		decodedRecord.SelectedOutboundCarrierReference != firstRecord.SelectedOutboundCarrierReference {
		t.Fatalf("incoming and selected-outbound carrier correlations were conflated: %+v", decodedRecord)
	}

	foreign := newTestRegistry(t, 2, 4, 16)
	foreignHandle := foreign.AdmitTCP(context.Background(), "", "tcp:foreign.example:443", "", ByteScopeLogicalLinkAccepted)
	foreignHandle.SelectRoot("", "mux-out", "handler", "tcp:foreign.example:443", "", true, CarrierProofUnknown, IssueMuxCarrierF2Required)
	foreignCtx := ContextWithHandle(context.Background(), foreignHandle)
	foreignScope := session.MuxClientSessionObservationFromContext(ContextWithMuxClientSessionObservation(foreignCtx, "mux-out"))
	carrier.AttachTo(foreignScope)
	foreignRecord := muxRecordByID(t, foreign.Snapshot(), foreignHandle.flowID)
	if foreignRecord.SelectedOutboundCarrierReference != "" {
		t.Fatalf("foreign client MUX carrier was attached: %+v", foreignRecord)
	}
}

func TestClientMuxCarrierCannotPublishAfterRegistryClose(t *testing.T) {
	registry := newTestRegistry(t, 2, 4, 32)
	handle := registry.AdmitTCP(context.Background(), "", "tcp:example.com:443", "", ByteScopeLogicalLinkAccepted)
	if handle == nil {
		t.Fatal("ordinary TCP admission failed")
	}
	handle.SelectRoot("", "mux-out", "handler", "tcp:example.com:443", "", true, CarrierProofUnknown, IssueMuxCarrierF2Required)
	ctx := ContextWithHandle(context.Background(), handle)
	scope := session.MuxClientSessionObservationFromContext(ContextWithMuxClientSessionObservation(ctx, "mux-out"))
	if scope == nil {
		t.Fatal("selected outbound did not receive a client MUX scope")
	}
	carrier := scope.NewCarrier()
	if carrier == nil {
		t.Fatal("client MUX carrier correlation was not minted")
	}

	registry.Close()
	before := registry.Snapshot()
	carrier.AttachTo(scope)
	after := registry.Snapshot()
	beforeRecord := muxRecordByID(t, before, handle.flowID)
	afterRecord := muxRecordByID(t, after, handle.flowID)
	if beforeRecord.SelectedOutboundCarrierReference != "" || afterRecord.SelectedOutboundCarrierReference != "" {
		t.Fatalf("stale client MUX carrier published after registry close: before=%+v after=%+v", beforeRecord, afterRecord)
	}
	if after.Watermark != before.Watermark {
		t.Fatalf("stale client MUX carrier emitted an event after registry close: before=%d after=%d", before.Watermark, after.Watermark)
	}
}

func TestMuxSessionCloseAndParticipantsGatePresenceOnlyTerminal(t *testing.T) {
	registry := newTestRegistry(t, 4, 8, 32)
	carrier := registry.NewMuxCarrierObservation()
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	scope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, destination, ""))
	handle := registry.AdmitMuxTCP(scope, destination)
	if handle == nil {
		t.Fatal("MUX scope was not admitted")
	}
	participant := scope.AcquireParticipant()
	if participant == nil {
		t.Fatal("MUX worker participant was not acquired")
	}
	root := handle.LogicalRoot()
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	scope.AfterClose()
	if view := root.View(); view.Phase != LifecyclePhaseOwnerSealed || view.Terminal != nil || view.LiveParticipantCount != 1 {
		t.Fatalf("MUX terminal overtook its worker: %+v", view)
	}
	participant.Release(nil)

	view := root.View()
	if view.Phase != LifecyclePhaseTerminal || view.Terminal == nil ||
		view.Terminal.Evidence != CompletionEvidenceProvenLogicalSessionClosed ||
		view.Terminal.TerminalClass != "" || view.Terminal.TechnicalErrorCategory != "" {
		t.Fatalf("MUX no-cause terminal fabricated or lost facts: %+v", view)
	}
	record := muxRecordByID(t, registry.Snapshot(), handle.flowID)
	if record.CompletionState != CompletionTerminal || record.CompletionEvidence != CompletionEvidenceProvenLogicalSessionClosed ||
		record.TerminalClass != "" || record.TechnicalErrorCategory != "" {
		t.Fatalf("MUX retained terminal is not presence-only: %+v", record)
	}
}

func TestMuxSiblingCloseAndExactCauseRemainIndependent(t *testing.T) {
	registry := newTestRegistry(t, 4, 8, 32)
	carrier := registry.NewMuxCarrierObservation()
	firstDestination := net.TCPDestination(net.DomainAddress("first.example"), 443)
	secondDestination := net.TCPDestination(net.DomainAddress("second.example"), 443)
	firstScope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, firstDestination, ""))
	secondScope := requireMuxSessionScope(t, carrier.NewTCPSession([8]byte{}, secondDestination, ""))
	first := registry.AdmitMuxTCP(firstScope, firstDestination)
	second := registry.AdmitMuxTCP(secondScope, secondDestination)
	if first == nil || second == nil {
		t.Fatal("MUX siblings were not admitted")
	}
	first.LogicalRoot().Uplink().Seal()
	first.LogicalRoot().Downlink().Seal()
	first.LogicalRoot().Uplink().MarkDrained()
	first.LogicalRoot().Downlink().MarkDrained()
	firstScope.AfterClose()
	if view := first.LogicalRoot().View(); view.Phase != LifecyclePhaseTerminal {
		t.Fatalf("first MUX sibling did not terminalize: %+v", view)
	}
	if view := second.LogicalRoot().View(); view.Phase != LifecyclePhaseOpen || view.Terminal != nil {
		t.Fatalf("first MUX close changed its sibling: %+v", view)
	}
	second.AddUplink(7)
	participant := secondScope.AcquireParticipant()
	if participant == nil {
		t.Fatal("second MUX sibling participant was not acquired")
	}
	participant.Release(errors.New("proven worker failure"))
	second.LogicalRoot().Uplink().Seal()
	second.LogicalRoot().Downlink().Seal()
	second.LogicalRoot().Uplink().MarkDrained()
	second.LogicalRoot().Downlink().MarkDrained()
	secondScope.AfterClose()
	view := second.LogicalRoot().View()
	if view.Phase != LifecyclePhaseTerminal || view.Terminal == nil ||
		view.Terminal.TerminalClass != TerminalClassLocalError || view.Terminal.TechnicalErrorCategory != "PARTICIPANT_ERROR" {
		t.Fatalf("exact MUX cause was not retained independently: %+v", view)
	}
}

func muxRecordByID(t testing.TB, snapshot Snapshot, flowID string) Record {
	t.Helper()
	for _, record := range snapshot.Records {
		if record.FlowID == flowID {
			return record
		}
	}
	t.Fatalf("missing MUX record %s in %+v", flowID, snapshot.Records)
	return Record{}
}

func requireMuxSessionScope(t testing.TB, observation session.MuxSessionObservation) *MuxSessionScope {
	t.Helper()
	scope, ok := observation.(*MuxSessionScope)
	if !ok || scope == nil {
		t.Fatalf("missing concrete MUX session scope: %T", observation)
	}
	return scope
}

type tcpOnlyMuxCarrier struct{}

func (tcpOnlyMuxCarrier) NewTCPSession([8]byte, net.Destination, string) session.MuxSessionObservation {
	return nil
}
func (tcpOnlyMuxCarrier) Close() {}
