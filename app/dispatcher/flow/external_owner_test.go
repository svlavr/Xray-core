package flow

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExternalOwnerBindCloseRaceCannotLoseClose(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		registry, err := NewRegistry(Config{MaxRecords: 1, MaxSeries: 1, MaxEvents: 16})
		if err != nil {
			t.Fatal(err)
		}
		scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
		link := continuationTestLink()
		if !scope.claim(link) {
			t.Fatal("external owner claim failed")
		}
		handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeUnknown)
		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() {
			<-start
			scope.bind(handle)
			done <- struct{}{}
		}()
		go func() {
			<-start
			scope.AfterOwnerClose(nil, nil)
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done
		view := handle.LogicalRoot().View()
		if view.Phase != LifecyclePhaseTerminal || view.Terminal == nil {
			t.Fatalf("iteration %d lost external close: %+v", iteration, view)
		}
		registry.Close()
	}
}

func TestExternalOwnerScopeIsOneShotAndExactLinkBound(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	firstLink := continuationTestLink()
	handle := registry.AdmitExternalTCP(context.Background(), "", "tcp:a:1", "", scope, firstLink)
	if handle == nil || scope.Handle() != handle || scope.Link() != firstLink {
		t.Fatal("external owner did not retain exact root and link")
	}
	if replay := registry.AdmitExternalTCP(context.Background(), "", "tcp:b:1", "", scope, continuationTestLink()); replay != nil {
		t.Fatal("external owner token admitted a second root")
	}
	if len(registry.Snapshot().Records) != 1 || handle.LogicalRoot().View().LifecycleFault != LifecycleFaultExternalOwnerReplay {
		t.Fatal("external owner replay was not fail-closed and typed")
	}
}

func TestConcurrentExternalOwnerReplayIsRetainedUntilBind(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	start := make(chan struct{})
	results := make(chan *Handle, 2)
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			results <- registry.AdmitExternalTCP(context.Background(), "", "tcp:a:1", "", scope, continuationTestLink())
		}()
	}
	close(start)
	first, second := <-results, <-results
	var handle *Handle
	if first != nil && second == nil {
		handle = first
	} else if second != nil && first == nil {
		handle = second
	} else {
		t.Fatalf("external token replay admitted wrong root count: first=%v second=%v", first, second)
	}
	if view := handle.LogicalRoot().View(); view.LifecycleFault != LifecycleFaultExternalOwnerReplay {
		t.Fatalf("concurrent replay fault was lost before bind: %+v", view)
	}
}

func TestRegistryCloseKeepsExternalRootIndeterminateAfterLateFinalize(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerTUNTCP)
	if !scope.claim(continuationTestLink()) {
		t.Fatal("external owner claim failed")
	}
	handle := registry.AdmitTCP(context.Background(), "", "tcp:a:1", "", ByteScopeUnknown)
	registry.Close()
	if !scope.bind(handle) {
		t.Fatal("pre-stop external admission lost its exact root")
	}
	scope.AfterOwnerClose(nil, nil)
	snapshot := registry.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].CompletionState != CompletionIndeterminate || snapshot.Records[0].IndeterminateReason != IndeterminateRuntimeStopped {
		t.Fatalf("late external finalize overwrote runtime stop: %+v", snapshot.Records)
	}
}

func TestExternalOwnerOutcomePrecedesCloseResult(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerTUNTCP)
	handle := registry.AdmitExternalTCP(context.Background(), "", "tcp:a:1", "", scope, continuationTestLink())
	scope.AfterOwnerClose(errors.New("owner process failed"), nil)
	view := handle.LogicalRoot().View()
	if view.Terminal == nil || view.Terminal.TerminalClass != TerminalClassLocalError || view.Terminal.TechnicalErrorCategory != "PARTICIPANT_ERROR" {
		t.Fatalf("owner process outcome was overwritten by successful close: %+v", view)
	}
}

func TestInvalidExternalOwnerClassCannotCreateToken(t *testing.T) {
	if scope := NewExternalOwnerScope("UNKNOWN"); scope != nil {
		t.Fatalf("unknown external owner class was accepted: %+v", scope)
	}
}

func TestExternalOwnerListenerUNIXCanCreateToken(t *testing.T) {
	if scope := NewExternalOwnerScope(ExternalOwnerListenerUNIX); scope == nil {
		t.Fatal("UNIX listener external owner class was rejected")
	}
}

func TestExternalOwnerListenerUNIXRetainsCloseError(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerUNIX)
	handle := registry.AdmitExternalTCP(context.Background(), "", "tcp:example.com:443", "", scope, continuationTestLink())
	if handle == nil {
		t.Fatal("UNIX listener external root was not admitted")
	}
	scope.AfterOwnerClose(nil, errors.New("close failed"))
	view := handle.LogicalRoot().View()
	if view.Terminal == nil || view.Terminal.TerminalClass != TerminalClassLocalError || view.Terminal.TechnicalErrorCategory != "PARTICIPANT_ERROR" {
		t.Fatalf("UNIX listener close error was not retained: %+v", view)
	}
}

func TestExternalUDPOwnerAdmissionIsClassRestricted(t *testing.T) {
	allowed := []ExternalOwnerClass{ExternalOwnerTUNUDP, ExternalOwnerWireGuardUDP}
	for _, class := range allowed {
		t.Run(string(class), func(t *testing.T) {
			registry := newTestRegistry(t, 1, 1, 32)
			scope := NewExternalOwnerScope(class)
			handle := registry.AdmitExternalUDP(context.Background(), "udp:127.0.0.1:1234", "udp:first.example:53", "", scope, continuationTestLink())
			if handle == nil {
				t.Fatal("allowed external UDP owner was not admitted")
			}
			scope.AfterOwnerClose(nil, nil)
			records := registry.Snapshot().Records
			if len(records) != 1 || records[0].FlowKind != KindUDPAssociation || records[0].OriginalDestination != "udp:first.example:53" {
				t.Fatalf("external UDP association has wrong identity: %+v", records)
			}
			for _, observation := range records[0].ByteObservations {
				if observation.ByteScope != ByteScopeDispatcherExternalLinkIO {
					t.Fatalf("external UDP association has wrong byte boundary: %+v", observation)
				}
			}
		})
	}

	for _, class := range []ExternalOwnerClass{ExternalOwnerListenerTCP, ExternalOwnerListenerUNIX, ExternalOwnerTUNTCP, ExternalOwnerWireGuardTCP} {
		t.Run("reject_"+string(class), func(t *testing.T) {
			registry := newTestRegistry(t, 1, 1, 32)
			if handle := registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "", NewExternalOwnerScope(class), continuationTestLink()); handle != nil {
				t.Fatalf("foreign owner class admitted UDP association: %v", class)
			}
			if records := registry.Snapshot().Records; len(records) != 0 {
				t.Fatalf("foreign owner class created a record: %+v", records)
			}
		})
	}
}

func TestVLESSUDPAuthorizationIsListenerOnlyAndOneShot(t *testing.T) {
	for _, class := range []ExternalOwnerClass{ExternalOwnerListenerTCP, ExternalOwnerListenerUNIX} {
		t.Run(string(class), func(t *testing.T) {
			registry := newTestRegistry(t, 2, 2, 32)
			scope := NewExternalOwnerScope(class)
			if handle := registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "vless", scope, continuationTestLink()); handle != nil {
				t.Fatal("listener UDP was admitted without VLESS authorization")
			}
			if !scope.AuthorizeVLESSUDP() {
				t.Fatal("VLESS UDP authorization was rejected for listener")
			}
			handle := registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "vless", scope, continuationTestLink())
			if handle == nil {
				t.Fatalf("authorized VLESS UDP listener was not admitted: %+v", handle)
			}
			if scope.AuthorizeVLESSUDP() {
				t.Fatal("authorization after scope claim succeeded")
			}
		})
	}
	for _, class := range []ExternalOwnerClass{ExternalOwnerTUNTCP, ExternalOwnerWireGuardTCP, ExternalOwnerTUNUDP, ExternalOwnerWireGuardUDP} {
		t.Run("reject_"+string(class), func(t *testing.T) {
			if NewExternalOwnerScope(class).AuthorizeVLESSUDP() {
				t.Fatalf("non-listener owner accepted VLESS UDP authorization: %s", class)
			}
		})
	}
}

func TestVLESSUDPAuthorizationAdmissionRaceCannotBroadenListenerScope(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		registry := newTestRegistry(t, 2, 2, 32)
		scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
		start := make(chan struct{})
		authorized := make(chan bool, 1)
		admitted := make(chan *Handle, 1)
		go func() {
			<-start
			authorized <- scope.AuthorizeVLESSUDP()
		}()
		go func() {
			<-start
			admitted <- registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "vless", scope, continuationTestLink())
		}()
		close(start)
		if !<-authorized {
			t.Fatalf("iteration %d listener authorization unexpectedly failed", iteration)
		}
		handle := <-admitted
		if records := registry.Snapshot().Records; len(records) > 1 {
			t.Fatalf("iteration %d authorization/admission race created multiple roots: %+v", iteration, records)
		}
		if handle != nil && !scope.claimed.Load() {
			t.Fatalf("iteration %d admitted listener UDP without claiming scope", iteration)
		}
		if handle == nil {
			handle = registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "vless", scope, continuationTestLink())
			if handle == nil {
				t.Fatalf("iteration %d authorization left an unclaimed listener scope unavailable", iteration)
			}
		}
	}
}

func TestDokodemoUDPAuthorizationIsExactAndMarksDownlinkIndeterminate(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerUDP)
	if scope == nil || !scope.AuthorizeDokodemoUDP() {
		t.Fatal("dokodemo UDP authorization failed")
	}
	if scope.AuthorizeDokodemoUDP() {
		t.Fatal("dokodemo UDP authorization was replayable")
	}
	handle := registry.AdmitExternalUDP(context.Background(), "udp:127.0.0.1:1234", "udp:first.example:53", "", scope, continuationTestLink())
	if handle == nil {
		t.Fatal("authorized dokodemo UDP listener was not admitted")
	}
	view := handle.LogicalRoot().View()
	if observation := testObservation(t, view.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO); observation.State != ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
		t.Fatalf("dokodemo downlink was not indeterminate before I/O: %+v", observation)
	}
	foundAdmission := false
	for _, event := range registry.EventsAfter(0, 32).Events {
		if event.Type != EventAdmitted || event.Record == nil || event.Record.FlowID != handle.flowID {
			continue
		}
		foundAdmission = true
		observation := testObservation(t, event.Record.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO)
		if observation.State != ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
			t.Fatalf("dokodemo admission published transient numeric downlink: %+v", event.Record)
		}
	}
	if !foundAdmission {
		t.Fatal("dokodemo admission event was not published")
	}
	scope.AfterOwnerClose(nil, nil)
}

func TestDokodemoUDPAuthorizationRejectsForeignAndClosedScopes(t *testing.T) {
	for _, class := range []ExternalOwnerClass{ExternalOwnerListenerTCP, ExternalOwnerListenerUNIX, ExternalOwnerTUNUDP, ExternalOwnerWireGuardUDP} {
		if NewExternalOwnerScope(class).AuthorizeDokodemoUDP() {
			t.Fatalf("foreign owner class accepted dokodemo UDP authorization: %s", class)
		}
	}
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerUDP)
	scope.AfterOwnerClose(nil, nil)
	if scope.AuthorizeDokodemoUDP() || registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "", scope, continuationTestLink()) != nil {
		t.Fatal("closed dokodemo UDP scope admitted an association")
	}
}

func TestVLESSUDPAdmissionAfterOwnerCloseFailsClosed(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	if !scope.AuthorizeVLESSUDP() {
		t.Fatal("VLESS UDP authorization failed")
	}
	scope.AfterOwnerClose(nil, nil)
	if handle := registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "vless", scope, continuationTestLink()); handle != nil {
		t.Fatalf("closed VLESS listener scope admitted UDP association: %+v", handle)
	}
	if records := registry.Snapshot().Records; len(records) != 0 {
		t.Fatalf("closed VLESS listener scope created records: %+v", records)
	}
}

func TestHysteriaUDPAuthorizationIsInterConnListenerOnlyAndIndeterminateBeforeAdmission(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	if !scope.AuthorizeHysteriaUDP() {
		t.Fatal("Hysteria UDP authorization failed")
	}
	if scope.AuthorizeHysteriaUDP() {
		t.Fatal("Hysteria UDP authorization was replayable")
	}
	if handle := registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "", scope, continuationTestLink()); handle == nil {
		t.Fatal("authorized Hysteria InterConn scope was not admitted")
	} else if observation := testObservation(t, handle.LogicalRoot().View().ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO); observation.State != ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
		t.Fatalf("Hysteria downlink was not indeterminate before admission: %+v", observation)
	}
	foundAdmission := false
	for _, event := range registry.EventsAfter(0, 32).Events {
		if event.Type != EventAdmitted || event.Record == nil {
			continue
		}
		foundAdmission = true
		observation := testObservation(t, event.Record.ByteObservations, DirectionDownlink, ByteScopeDispatcherExternalLinkIO)
		if observation.State != ByteObservationStateIndeterminate || observation.ObservedBytes.Known {
			t.Fatalf("Hysteria admission published transient numeric downlink: %+v", event.Record)
		}
	}
	if !foundAdmission {
		t.Fatal("Hysteria admission event was not published")
	}
	for _, class := range []ExternalOwnerClass{ExternalOwnerListenerUNIX, ExternalOwnerTUNTCP, ExternalOwnerTUNUDP, ExternalOwnerListenerUDP} {
		if NewExternalOwnerScope(class).AuthorizeHysteriaUDP() {
			t.Fatalf("foreign scope authorized Hysteria UDP: %s", class)
		}
	}
}

func TestHysteriaAndVLESSUDPAuthorizationsAreMutuallyExclusive(t *testing.T) {
	vless := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	if !vless.AuthorizeVLESSUDP() || vless.AuthorizeHysteriaUDP() {
		t.Fatal("VLESS scope accepted Hysteria authorization")
	}
	hysteria := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	if !hysteria.AuthorizeHysteriaUDP() || hysteria.AuthorizeVLESSUDP() {
		t.Fatal("Hysteria scope accepted VLESS authorization")
	}
}

func TestHysteriaUDPAuthorizationRejectsClosedScopes(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	scope.AfterOwnerClose(nil, nil)
	if scope.AuthorizeHysteriaUDP() || registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "", scope, continuationTestLink()) != nil {
		t.Fatal("closed Hysteria scope admitted UDP")
	}
}

func TestHysteriaUDPFreshOwnerScopesCreateDistinctRoots(t *testing.T) {
	registry := newTestRegistry(t, 2, 2, 32)
	for epoch := 0; epoch < 2; epoch++ {
		scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
		if !scope.AuthorizeHysteriaUDP() {
			t.Fatalf("epoch %d authorization failed", epoch)
		}
		if handle := registry.AdmitExternalUDP(context.Background(), "", "udp:first.example:53", "", scope, continuationTestLink()); handle == nil {
			t.Fatalf("epoch %d admission failed", epoch)
		}
	}
	records := registry.Snapshot().Records
	if len(records) != 2 || records[0].FlowID == records[1].FlowID {
		t.Fatalf("fresh Hysteria owner scopes reused a root: %+v", records)
	}
}

func TestExternalTCPOwnerAdmissionRejectsUDPOwnerClasses(t *testing.T) {
	for _, class := range []ExternalOwnerClass{ExternalOwnerTUNUDP, ExternalOwnerWireGuardUDP} {
		t.Run(string(class), func(t *testing.T) {
			registry := newTestRegistry(t, 1, 1, 32)
			if handle := registry.AdmitExternalTCP(context.Background(), "", "tcp:first.example:443", "", NewExternalOwnerScope(class), continuationTestLink()); handle != nil {
				t.Fatalf("UDP owner class admitted TCP root: %v", class)
			}
			if records := registry.Snapshot().Records; len(records) != 0 {
				t.Fatalf("UDP owner class created a TCP record: %+v", records)
			}
		})
	}
}

func TestExternalAdmissionContentionDoesNotClaimScopeOrLink(t *testing.T) {
	registry := newTestRegistry(t, 1, 1, 32)
	scope := NewExternalOwnerScope(ExternalOwnerListenerTCP)
	link := continuationTestLink()
	ctx := ContextWithExternalOwnerScope(context.Background(), scope)
	registry.mu.Lock()
	if handle := registry.AdmitTCP(context.Background(), "", "tcp:queued:1", "", ByteScopeLogicalLinkAccepted); handle == nil {
		registry.mu.Unlock()
		t.Fatal("failed to fill bounded pending admission queue")
	}
	result := make(chan *Handle, 1)
	go func() {
		result <- registry.AdmitExternalTCP(ctx, "", "tcp:a:1", "", scope, link)
	}()
	select {
	case handle := <-result:
		if handle != nil {
			registry.mu.Unlock()
			t.Fatal("contended external admission unexpectedly created a flow")
		}
	case <-time.After(time.Second):
		registry.mu.Unlock()
		t.Fatal("contended external telemetry admission blocked the stock traffic path")
	}
	if scope.Handle() != nil || scope.Link() != nil || scope.claimed.Load() {
		registry.mu.Unlock()
		t.Fatalf("failed external admission left an orphaned claim: %+v", scope)
	}
	registry.mu.Unlock()
	scope.AfterOwnerClose(nil, nil)
	snapshot := registry.Snapshot()
	if snapshot.DroppedFlowCount != 1 || snapshot.AccountingCoverage.Reason != DiscontinuityAdmissionContention || len(snapshot.Records) != 1 {
		t.Fatalf("external admission loss was not published exactly: %+v", snapshot)
	}
}
