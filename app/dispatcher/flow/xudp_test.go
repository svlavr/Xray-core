package flow

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func newXUDPTestScope(t testing.TB, r *Registry) *XUDPScope {
	t.Helper()
	dest := net.UDPDestination(net.DomainAddress("xudp.flow.test"), 53)
	scope, ok := r.NewXUDPObservation(dest, "udp:source.test:1").(*XUDPScope)
	if !ok || r.AdmitXUDP(scope, dest) == nil {
		t.Fatal("XUDP admission failed")
	}
	return scope
}

func xudpTestCarrier(s *XUDPScope) session.XUDPCarrierObservation {
	return session.MuxXUDPCarrierObservation(s.registry.NewMuxCarrierObservation())
}

func awaitXUDPRecord(t *testing.T, r *Registry, predicate func(Record) bool) Record {
	t.Helper()
	// Unit tests may force a producer/worker overlap; inspect the registered
	// record as well as the public snapshot so this helper does not depend on a
	// ticker wake-up.
	r.mu.Lock()
	for _, root := range r.roots {
		record := cloneRecord(root.record.record)
		if record.FlowKind == KindXUDPLogical && predicate(record) {
			r.mu.Unlock()
			return record
		}
	}
	r.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, record := range r.Snapshot().Records {
			if record.FlowKind == KindXUDPLogical && predicate(record) {
				return record
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("XUDP record was not published")
	return Record{}
}

func TestXUDPBindingOrderAndHistorySuffix(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := newXUDPTestScope(t, r)
	for i := 0; i < 9; i++ {
		binding := s.PrepareBinding(xudpTestCarrier(s))
		if binding == nil || !binding.Install() {
			t.Fatal("binding install failed")
		}
		binding.ReaderExited()
		binding.Deactivate(session.XUDPDetachForRebind)
		r.mu.Lock()
		s.syncLocked(s.handle.root, r.offsetLocked())
		r.mu.Unlock()
	}
	r.mu.Lock()
	record := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if !record.XUDPHistoryTruncated || !record.XUDPFirstRetainedOrdinal.Known || record.XUDPFirstRetainedOrdinal.Value != 2 {
		t.Fatalf("bad XUDP suffix: %+v", record)
	}
	events := r.EventsAfter(0, 128).Events
	var transitions []XUDPBindingTransition
	for _, event := range events {
		if event.Type != EventXUDPBindingTransition || event.XUDPBinding == nil {
			continue
		}
		transitions = append(transitions, *event.XUDPBinding)
	}
	for ordinal := uint64(2); ordinal <= 9; ordinal++ {
		found := false
		for index := range transitions {
			if transitions[index].Action == "ATTACH" && transitions[index].Ordinal == ordinal {
				found = index > 0 && transitions[index-1].Action == "DETACH" && transitions[index-1].Ordinal == ordinal-1
				break
			}
		}
		if !found {
			t.Fatalf("detach(%d) did not precede attach(%d): %+v", ordinal-1, ordinal, transitions)
		}
	}
}

func TestXUDPTransitionQuotaAndGlobalCreditLoss(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 16, MaxSeries: 1, MaxEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := newXUDPTestScope(t, r)
	if s.quota != 1 {
		t.Fatalf("quota = %d, want 1", s.quota)
	}
	binding := s.PrepareBinding(xudpTestCarrier(s))
	if binding == nil || !binding.Install() {
		t.Fatal("binding install failed")
	}
	r.mu.Lock()
	r.xudpTransitionCredits.Store(0)
	binding.ReaderExited()
	binding.Deactivate(session.XUDPDetachForRebind)
	s.syncLocked(s.handle.root, r.offsetLocked())
	r.mu.Unlock()
	r.mu.Lock()
	record := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if !record.XUDPLostTransitionFirst.Known || !record.XUDPLostTransitionLast.Known {
		t.Fatalf("missing loss coordinates: %+v", record)
	}
	if record.XUDPLostTransitionFirstAction != XUDPBindingActionDetach || record.XUDPLostTransitionLastAction != XUDPBindingActionDetach {
		t.Fatalf("missing loss actions: %+v", record)
	}
	// Extreme normalized values still use division before the cap.
	r2, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: int(^uint(0) >> 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	s2 := newXUDPTestScope(t, r2)
	if s2.quota != 16 {
		t.Fatalf("quota = %d, want capped 16", s2.quota)
	}
}

func TestXUDPCommitCursorRetainsReceiptsBeforeLaterLoss(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	awaitXUDPRecord(t, r, func(record Record) bool { return record.FlowID == s.handle.flowID })
	r.mu.Lock()
	b1 := s.PrepareBinding(xudpTestCarrier(s))
	if b1 == nil || !b1.Install() {
		t.Fatal("attach1")
	}
	b1.ReaderExited()
	b1.Deactivate(session.XUDPDetachForRebind)
	r.xudpTransitionCredits.Store(0)
	b2 := s.PrepareBinding(xudpTestCarrier(s))
	if b2 == nil || b2.Install() {
		t.Fatal("attach2 must be lost")
	}
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	var attach, detach, loss uint64
	for _, e := range r.EventsAfter(0, 32).Events {
		if e.Type == EventXUDPBindingTransition && e.XUDPBinding != nil {
			if e.XUDPBinding.Ordinal == 1 && e.XUDPBinding.Action == XUDPBindingActionAttach {
				attach = e.Sequence
			}
			if e.XUDPBinding.Ordinal == 1 && e.XUDPBinding.Action == XUDPBindingActionDetach {
				detach = e.Sequence
			}
			if e.XUDPBinding.Ordinal == 2 {
				t.Fatal("lost attach was emitted")
			}
		}
		if loss == 0 && e.Type == EventUpdated && e.Record != nil && e.Record.XUDPTransitionIncomplete {
			loss = e.Sequence
		}
	}
	if attach == 0 || detach == 0 || loss == 0 || !(attach < detach && detach < loss) {
		t.Fatalf("cursor order attach=%d detach=%d loss=%d", attach, detach, loss)
	}
}

func TestXUDPCommitCursorPublishesLossBeforeLaterReceipt(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	r.mu.Lock()
	b1 := s.PrepareBinding(xudpTestCarrier(s))
	if b1 == nil || !b1.Install() {
		t.Fatal("attach1")
	}
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.xudpTransitionCredits.Store(0)
	b2 := s.PrepareBinding(xudpTestCarrier(s))
	if b2 == nil || b2.Install() {
		t.Fatal("attach2 must be lost")
	}
	r.xudpTransitionCredits.Store(1)
	b3 := s.PrepareBinding(xudpTestCarrier(s))
	if b3 == nil || !b3.Install() {
		t.Fatal("attach3")
	}
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	var loss, attach uint64
	for _, e := range r.EventsAfter(0, 32).Events {
		if loss == 0 && e.Type == EventUpdated && e.Record != nil && e.Record.XUDPTransitionIncomplete {
			loss = e.Sequence
		}
		if e.Type == EventXUDPBindingTransition && e.XUDPBinding != nil && e.XUDPBinding.Ordinal == 2 {
			t.Fatal("lost attach emitted")
		}
		if e.Type == EventXUDPBindingTransition && e.XUDPBinding != nil && e.XUDPBinding.Ordinal == 3 {
			attach = e.Sequence
		}
	}
	if loss == 0 || attach == 0 || loss >= attach {
		t.Fatalf("loss=%d attach3=%d", loss, attach)
	}
}

func TestXUDPLossRangeIsStickyAcrossDrains(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	r.xudpTransitionCredits.Store(0)
	b1 := s.PrepareBinding(xudpTestCarrier(s))
	if b1 == nil || b1.Install() {
		t.Fatal("loss1")
	}
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	r.xudpTransitionCredits.Store(0)
	b2 := s.PrepareBinding(xudpTestCarrier(s))
	if b2 == nil || b2.Install() {
		t.Fatal("loss2")
	}
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	got := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if !got.XUDPLostTransitionFirst.Known || got.XUDPLostTransitionFirst.Value != 1 || got.XUDPLostTransitionFirstAction != XUDPBindingActionAttach || !got.XUDPLostTransitionLast.Known || got.XUDPLostTransitionLast.Value != 2 || got.XUDPLostTransitionLastAction != XUDPBindingActionAttach {
		t.Fatalf("unsticky loss range: %+v", got)
	}
}

func TestXUDPDeactivateBeforeReaderExitCommitsDetach(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	b := s.PrepareBinding(xudpTestCarrier(s))
	if b == nil || !b.Install() {
		t.Fatal("attach")
	}
	b.Deactivate(session.XUDPDetachForRebind)
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	b.ReaderExited()
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	got := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if len(got.XUDPBindings) != 1 || got.XUDPBindings[0].DetachTransition != string(session.XUDPDetachForRebind) {
		t.Fatalf("deactivation rendezvous failed: %+v", got.XUDPBindings)
	}
}

func TestXUDPForeignCarrierPublishesAuthorityLoss(t *testing.T) {
	a, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer a.Close()
	b, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer b.Close()
	s := newXUDPTestScope(t, a)
	first := s.PrepareBinding(xudpTestCarrier(s))
	if first == nil || !first.Install() {
		t.Fatal("first attach")
	}
	a.mu.Lock()
	a.syncRootLocked(s.handle.flowID, s.handle.root)
	a.mu.Unlock()
	foreign := session.MuxXUDPCarrierObservation(b.NewMuxCarrierObservation())
	lost := s.PrepareBinding(foreign)
	if lost == nil || !lost.Install() {
		t.Fatal("foreign carrier did not publish explicit loss")
	}
	lost.ReaderExited()
	lost.Deactivate(session.XUDPDetachRootClose)
	lost.RevokeUnproven()
	a.mu.Lock()
	a.syncRootLocked(s.handle.flowID, s.handle.root)
	record := cloneRecord(s.handle.root.record.record)
	a.mu.Unlock()
	if record.XUDPTransitionLossReason != XUDPTransitionLossAuthorityUnavailable || !record.XUDPLostTransitionLast.Known || record.XUDPLostTransitionLast.Value != 2 || len(record.XUDPBindings) != 1 {
		t.Fatalf("foreign carrier was not fail-closed: %+v", record)
	}
	for _, event := range a.EventsAfter(0, 32).Events {
		if event.Type == EventXUDPBindingTransition && event.XUDPBinding != nil && event.XUDPBinding.Ordinal == 2 {
			t.Fatalf("foreign callbacks fabricated transition: %+v", event.XUDPBinding)
		}
	}
}

func TestXUDPRevokeUnprovenPublishesLossWithoutDetach(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	b := s.PrepareBinding(xudpTestCarrier(s))
	if b == nil || !b.Install() {
		t.Fatal("attach")
	}
	b.RevokeUnproven()
	s.Terminalize()
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	record := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if record.XUDPTransitionLossReason != XUDPTransitionLossReaderExitUnproven || record.XUDPLostTransitionLastAction != XUDPBindingActionDetach || record.CompletionState != CompletionTerminal {
		t.Fatalf("revoke result: %+v", record)
	}
	for _, event := range r.EventsAfter(0, 32).Events {
		if event.Type == EventXUDPBindingTransition && event.XUDPBinding != nil && event.XUDPBinding.Action == XUDPBindingActionDetach {
			t.Fatalf("fabricated detach: %+v", event.XUDPBinding)
		}
	}
}

func TestXUDPFullLossCursorNeverPanicsOrOvercredits(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	awaitXUDPRecord(t, r, func(record Record) bool { return record.FlowID == s.handle.flowID })
	r.mu.Lock()
	first := s.PrepareBinding(xudpTestCarrier(s))
	if first == nil || !first.Install() {
		r.mu.Unlock()
		t.Fatal("first attach")
	}
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	for i := 0; i < 16; i++ {
		lost := s.PrepareBinding(nil)
		if lost == nil || !lost.Install() {
			r.mu.Unlock()
			t.Fatalf("loss %d was not recorded", i)
		}
	}
	r.xudpTransitionCredits.Store(1)
	next := s.PrepareBinding(xudpTestCarrier(s))
	if next == nil {
		r.mu.Unlock()
		t.Fatal("next binding was not minted")
	}
	_ = next.Install() // structural full converts this to bounded tail loss.
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	record := cloneRecord(s.handle.root.record.record)
	credits := r.xudpTransitionCredits.Load()
	r.mu.Unlock()
	if credits > 16 || !record.XUDPTransitionIncomplete || !record.XUDPLostTransitionLast.Known || record.XUDPLostTransitionLast.Value != 18 {
		t.Fatalf("cursor/credit state invalid: credits=%d record=%+v", credits, record)
	}
	for _, event := range r.EventsAfter(0, 64).Events {
		if event.Type == EventXUDPBindingTransition && event.XUDPBinding != nil && event.XUDPBinding.Ordinal == 18 {
			t.Fatal("tail loss fabricated transition")
		}
	}
}

func TestXUDPEpochLeaseBlocksTerminalUntilExactTerminalize(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	b := s.PrepareBinding(xudpTestCarrier(s))
	if b == nil || !b.Install() {
		t.Fatal("attach")
	}
	b.ReaderExited()
	b.Deactivate(session.XUDPDetachRootClose)
	root := s.handle.root.logical
	root.Uplink().Seal()
	root.Downlink().Seal()
	root.Uplink().MarkDrained()
	root.Downlink().MarkDrained()
	root.SealOwner(TerminalClassCompleted, "")
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	before := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if before.CompletionState == CompletionTerminal {
		t.Fatalf("epoch lease allowed early terminal: %+v", before)
	}
	s.Terminalize()
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	after := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if after.CompletionState != CompletionTerminal || after.CompletionEvidence != CompletionEvidenceXUDPRetainedLinkClosed {
		t.Fatalf("missing exact terminal: %+v", after)
	}
}

func TestXUDPPreparedBindingCannotInstallAfterTerminalize(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 16})
	defer r.Close()
	s := newXUDPTestScope(t, r)
	binding := s.PrepareBinding(xudpTestCarrier(s))
	if binding == nil {
		t.Fatal("binding was not prepared")
	}
	r.mu.Lock()
	s.Terminalize()
	credits := r.xudpTransitionCredits.Load()
	if binding.Install() {
		r.mu.Unlock()
		t.Fatal("prepared binding installed after epoch terminalization")
	}
	if got := r.xudpTransitionCredits.Load(); got != credits {
		r.mu.Unlock()
		t.Fatalf("post-terminal install changed credits: got %d want %d", got, credits)
	}
	r.mu.Unlock()
}

func TestXUDPProvisionalRejectAfterRevokeReleasesExactlyOnce(t *testing.T) {
	r, _ := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 8})
	defer r.Close()
	resident := newXUDPTestScope(t, r)
	keep := resident.PrepareBinding(xudpTestCarrier(resident))
	if keep == nil || !keep.Install() {
		t.Fatal("resident attach")
	}
	awaitXUDPRecord(t, r, func(record Record) bool {
		return record.FlowID == resident.handle.flowID && record.XUDPNextBindingOrdinal == 2
	})
	destination := net.UDPDestination(net.DomainAddress("provisional-revoke.xudp.test"), 53)
	provisional, ok := r.NewXUDPObservation(destination, "udp:provisional:1").(*XUDPScope)
	if !ok {
		t.Fatal("scope")
	}
	r.mu.Lock()
	handle := r.AdmitXUDP(provisional, destination)
	if handle == nil {
		r.mu.Unlock()
		t.Fatal("queued provisional admission missing handle")
	}
	b := provisional.PrepareBinding(xudpTestCarrier(provisional))
	if b == nil || !b.Install() {
		r.mu.Unlock()
		t.Fatal("provisional attach")
	}
	b.RevokeUnproven()
	r.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for {
		provisional.mu.Lock()
		closed := provisional.closed
		provisional.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not reject provisional root")
		}
		time.Sleep(time.Millisecond)
	}
	if got := r.xudpTransitionCredits.Load(); got != 8 {
		t.Fatalf("credits=%d, want 8", got)
	}
	for _, record := range r.Snapshot().Records {
		if record.FlowID == handle.flowID {
			t.Fatalf("rejected provisional record leaked: %+v", record)
		}
	}
	view := handle.root.logical.View()
	if view.LiveParticipantCount != 0 || view.LifecycleFault != "" {
		t.Fatalf("provisional participants/fault leaked: %+v", view)
	}
}

func TestXUDPLossUpdatePrecedesLaterTransitionAndCarriesFlowReference(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 8, MaxSeries: 1, MaxEvents: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := newXUDPTestScope(t, r)
	first := s.PrepareBinding(xudpTestCarrier(s))
	if first == nil || !first.Install() {
		t.Fatal("first binding install failed")
	}
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	r.xudpTransitionCredits.Store(0)
	first.ReaderExited()
	first.Deactivate(session.XUDPDetachForRebind)
	r.xudpTransitionCredits.Store(1)
	second := s.PrepareBinding(xudpTestCarrier(s))
	if second == nil || !second.Install() {
		t.Fatal("second binding install failed")
	}
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	events := r.EventsAfter(0, 32).Events
	updated, attached := uint64(0), uint64(0)
	for _, event := range events {
		if updated == 0 && event.Type == EventUpdated && event.Record != nil && event.Record.XUDPTransitionIncomplete {
			updated = event.Sequence
		}
		if event.Type == EventXUDPBindingTransition && event.XUDPBinding != nil && event.XUDPBinding.Ordinal == 2 {
			attached = event.Sequence
			if event.XUDPBinding.FlowID != s.handle.flowID || event.XUDPBinding.RuntimeInstanceID != s.handle.runtimeInstanceID {
				t.Fatalf("transition lacks exact flow reference: %+v", event.XUDPBinding)
			}
		}
	}
	if updated == 0 || attached == 0 || updated >= attached {
		t.Fatalf("loss update=%d must precede later attach=%d", updated, attached)
	}
}

func TestXUDPTerminalizesOnlyAfterDetachLeaseResolves(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := newXUDPTestScope(t, r)
	binding := s.PrepareBinding(xudpTestCarrier(s))
	if binding == nil || !binding.Install() {
		t.Fatal("binding install failed")
	}
	s.Terminalize()
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	record := cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if record.CompletionState == CompletionTerminal {
		t.Fatal("terminalized before binding lease resolved")
	}
	binding.ReaderExited()
	binding.Deactivate(session.XUDPDetachRootClose)
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	record = cloneRecord(s.handle.root.record.record)
	r.mu.Unlock()
	if record.CompletionState != CompletionTerminal || record.CompletionEvidence != CompletionEvidenceXUDPRetainedLinkClosed {
		t.Fatalf("missing retained-link terminal receipt: %+v", record)
	}
}

func TestXUDPRegistryCloseRevokesLeaseWithoutDetachAndLateCallbackIsInert(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 32})
	if err != nil {
		t.Fatal(err)
	}
	s := newXUDPTestScope(t, r)
	binding := s.PrepareBinding(xudpTestCarrier(s))
	if binding == nil || !binding.Install() {
		t.Fatal("binding install failed")
	}
	r.mu.Lock()
	r.syncRootLocked(s.handle.flowID, s.handle.root)
	r.mu.Unlock()
	r.Close()
	binding.ReaderExited()
	binding.Deactivate(session.XUDPDetachRootClose)
	for _, event := range r.EventsAfter(0, 32).Events {
		if event.Type == EventXUDPBindingTransition && event.XUDPBinding != nil && event.XUDPBinding.Action == XUDPBindingActionDetach {
			t.Fatalf("registry close fabricated detach: %+v", event.XUDPBinding)
		}
	}
}

func TestXUDPProvisionalRejectionReturnsCreditsWithoutRecord(t *testing.T) {
	r, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first := newXUDPTestScope(t, r)
	binding := first.PrepareBinding(xudpTestCarrier(first))
	if binding == nil || !binding.Install() {
		t.Fatal("first binding install failed")
	}
	awaitXUDPRecord(t, r, func(record Record) bool {
		return record.FlowID == first.handle.flowID && record.XUDPNextBindingOrdinal == 2
	})
	r.mu.Lock()
	firstState := cloneRecord(first.handle.root.record.record)
	r.mu.Unlock()
	if firstState.CompletionState == CompletionTerminal {
		t.Fatalf("first root unexpectedly terminal before provisional rejection: %+v", firstState)
	}
	before := r.xudpTransitionCredits.Load()
	dest := net.UDPDestination(net.DomainAddress("rejected.xudp.flow.test"), 53)
	rejected, ok := r.NewXUDPObservation(dest, "udp:rejected:1").(*XUDPScope)
	if !ok {
		t.Fatal("scope creation failed")
	}
	_ = r.AdmitXUDP(rejected, dest)
	deadline := time.Now().Add(time.Second)
	closed := false
	for !closed && time.Now().Before(deadline) {
		rejected.mu.Lock()
		closed = rejected.closed
		rejected.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	if !closed {
		t.Fatal("provisional admission was not rejected by worker")
	}
	if got := r.xudpTransitionCredits.Load(); got != before {
		t.Fatalf("credits changed on rejected provisional admission: got %d want %d", got, before)
	}
	for _, record := range r.Snapshot().Records {
		if record.FlowKind == KindXUDPLogical && record.FlowID != first.handle.flowID {
			t.Fatalf("rejected admission published record: %+v", record)
		}
	}
}

func BenchmarkXUDPBindingInstall(b *testing.B) {
	r, err := NewRegistry(Config{MaxRecords: 8, MaxSeries: 8, MaxEvents: 64})
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	s := newXUDPTestScope(b, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binding := s.PrepareBinding(xudpTestCarrier(s))
		if binding == nil || !binding.Install() {
			b.Fatal("install failed")
		}
		binding.ReaderExited()
		binding.Deactivate(session.XUDPDetachForRebind)
		r.mu.Lock()
		r.syncRootLocked(s.handle.flowID, s.handle.root)
		r.mu.Unlock()
	}
}
