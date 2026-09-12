//go:build linux

package core_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	app_log "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	app_router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	feature_routing "github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

const (
	integratedSpliceInboundTag  = "pr-f2-splice-in"
	integratedSpliceOutboundTag = "pr-f2-direct"
	integratedSpliceRuleTag     = "pr-f2-direct-rule"
)

func TestRoutedFreedomSplicePublishesIntegratedLiveProgress(t *testing.T) {
	remote, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()

	const requestSize = 32
	const firstResponseSize = 64 << 10
	const responseSize = 2<<20 + 17
	request := bytes.Repeat([]byte{0x31}, requestSize)
	response := bytes.Repeat([]byte{0x5a}, responseSize)
	firstResponseWritten := make(chan struct{})
	allowResponseCompletion := make(chan struct{})
	remoteResult := make(chan error, 1)
	go func() {
		connection, acceptErr := remote.AcceptTCP()
		if acceptErr != nil {
			remoteResult <- acceptErr
			return
		}
		defer connection.Close()
		gotRequest := make([]byte, requestSize)
		if _, readErr := io.ReadFull(connection, gotRequest); readErr != nil {
			remoteResult <- readErr
			return
		}
		if !bytes.Equal(gotRequest, request) {
			remoteResult <- errors.New("remote received changed request payload")
			return
		}
		if writeErr := writeIntegratedSplicePayload(connection, response[:firstResponseSize]); writeErr != nil {
			remoteResult <- writeErr
			return
		}
		close(firstResponseWritten)
		select {
		case <-allowResponseCompletion:
		case <-time.After(5 * time.Second):
			remoteResult <- errors.New("timed out waiting to finish remote response")
			return
		}
		remoteResult <- writeIntegratedSplicePayload(connection, response[firstResponseSize:])
	}()

	instance, inboundAddress, observer := startIntegratedSpliceCore(t, remote.Addr().(*stdnet.TCPAddr))
	defer instance.Close()
	client := dialIntegratedSpliceInbound(t, inboundAddress)
	defer client.Close()
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstResponseWritten:
	case remoteErr := <-remoteResult:
		t.Fatalf("remote failed before first response: %v", remoteErr)
	case <-time.After(5 * time.Second):
		t.Fatal("remote did not write the first response chunk")
	}

	live := waitForIntegratedSpliceSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		if len(snapshot.Records) != 1 {
			return false
		}
		observation, ok := integratedSpliceObservation(snapshot.Records[0])
		return ok && observation.State == flow_observation.ByteObservationStateProven &&
			observation.ObservedBytes.Known && observation.ObservedBytes.Value > 0
	})
	liveRecord := live.Records[0]
	if liveRecord.Route.MatchedNativeRuleTag != integratedSpliceRuleTag || liveRecord.Route.SelectedTopLevelOutboundTag != integratedSpliceOutboundTag {
		t.Fatalf("real router/direct selection was not retained: %+v", liveRecord.Route)
	}
	if liveRecord.CompletionState == flow_observation.CompletionTerminal {
		t.Fatalf("flow terminalized while the remote response was still open: %+v", liveRecord)
	}
	close(allowResponseCompletion)

	received := make([]byte, responseSize)
	if _, err := io.ReadFull(client, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, response) {
		t.Fatal("integrated splice changed the response payload")
	}
	if err := <-remoteResult; err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	terminal := waitForIntegratedSpliceSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal
	})
	observation, ok := integratedSpliceObservation(terminal.Records[0])
	if !ok || observation.State != flow_observation.ByteObservationStateProven ||
		observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: responseSize}) {
		t.Fatalf("integrated terminal splice evidence is not exact: %+v", terminal)
	}
	series, ok := integratedSpliceSeries(terminal)
	if !ok || series.State != flow_observation.SeriesStateContinuous ||
		series.CumulativeBytes != observation.ObservedBytes ||
		series.ActiveFlowCount != (flow_observation.OptionalUint64{Known: true, Value: 0}) {
		t.Fatalf("integrated terminal series is not exact: %+v", terminal.CounterSeries)
	}
}

func TestConcurrentRoutedFreedomSpliceFlowsRemainIndependent(t *testing.T) {
	const flowCount = 64
	const requestSize = 32
	const responseSize = 256 << 10
	remote, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	response := bytes.Repeat([]byte{0x6d}, responseSize)
	remoteResult := make(chan error, 1)
	go func() {
		var handlers sync.WaitGroup
		errorsByConnection := make(chan error, flowCount)
		for index := 0; index < flowCount; index++ {
			connection, acceptErr := remote.AcceptTCP()
			if acceptErr != nil {
				remoteResult <- acceptErr
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer connection.Close()
				request := make([]byte, requestSize)
				if _, readErr := io.ReadFull(connection, request); readErr != nil {
					errorsByConnection <- readErr
					return
				}
				errorsByConnection <- writeIntegratedSplicePayload(connection, response)
			}()
		}
		handlers.Wait()
		close(errorsByConnection)
		var joined error
		for connectionErr := range errorsByConnection {
			joined = errors.Join(joined, connectionErr)
		}
		remoteResult <- joined
	}()

	instance, inboundAddress, observer := startIntegratedSpliceCore(t, remote.Addr().(*stdnet.TCPAddr))
	defer instance.Close()
	snapshotStop := make(chan struct{})
	snapshotResult := make(chan error, 1)
	var stopSnapshotsOnce sync.Once
	stopSnapshots := func() { stopSnapshotsOnce.Do(func() { close(snapshotStop) }) }
	defer stopSnapshots()
	go auditIntegratedSpliceSnapshots(observer, responseSize, snapshotStop, snapshotResult)

	clientResults := make(chan error, flowCount)
	var clients sync.WaitGroup
	clients.Add(flowCount)
	for index := 0; index < flowCount; index++ {
		go func() {
			defer clients.Done()
			client, dialErr := dialIntegratedSpliceInboundResult(inboundAddress)
			if dialErr != nil {
				clientResults <- dialErr
				return
			}
			defer client.Close()
			request := bytes.Repeat([]byte{byte(index + 1)}, requestSize)
			if _, writeErr := client.Write(request); writeErr != nil {
				clientResults <- writeErr
				return
			}
			if closeErr := client.CloseWrite(); closeErr != nil {
				clientResults <- closeErr
				return
			}
			received := make([]byte, responseSize)
			if _, readErr := io.ReadFull(client, received); readErr != nil {
				clientResults <- readErr
				return
			}
			if !bytes.Equal(received, response) {
				clientResults <- errors.New("concurrent response payload changed")
				return
			}
			clientResults <- nil
		}()
	}
	clients.Wait()
	close(clientResults)
	for clientErr := range clientResults {
		if clientErr != nil {
			t.Fatal(clientErr)
		}
	}
	if err := <-remoteResult; err != nil {
		t.Fatal(err)
	}
	stopSnapshots()
	if err := <-snapshotResult; err != nil {
		t.Fatal(err)
	}

	terminal := waitForIntegratedSpliceSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		if len(snapshot.Records) != flowCount {
			return false
		}
		for _, record := range snapshot.Records {
			if record.CompletionState != flow_observation.CompletionTerminal {
				return false
			}
		}
		return true
	})
	if terminal.AccountingCoverage.State != flow_observation.AccountingCoverageComplete || terminal.DroppedFlowCount != 0 {
		t.Fatalf("concurrent integrated coverage was lost: %+v", terminal.AccountingCoverage)
	}
	flowIDs := make(map[string]struct{}, flowCount)
	for _, record := range terminal.Records {
		if _, duplicate := flowIDs[record.FlowID]; duplicate {
			t.Fatalf("duplicate flow ID in concurrent snapshot: %s", record.FlowID)
		}
		flowIDs[record.FlowID] = struct{}{}
		if record.Route.MatchedNativeRuleTag != integratedSpliceRuleTag || record.Route.SelectedTopLevelOutboundTag != integratedSpliceOutboundTag {
			t.Fatalf("concurrent flow lost routed direct identity: %+v", record.Route)
		}
		observation, ok := integratedSpliceObservation(record)
		if !ok || observation.State != flow_observation.ByteObservationStateProven ||
			observation.ObservedBytes != (flow_observation.OptionalUint64{Known: true, Value: responseSize}) {
			t.Fatalf("concurrent flow has inexact splice bytes: flow=%s observation=%+v", record.FlowID, observation)
		}
	}
	series, ok := integratedSpliceSeries(terminal)
	wantTotal := uint64(flowCount * responseSize)
	if !ok || series.State != flow_observation.SeriesStateContinuous ||
		series.CumulativeBytes != (flow_observation.OptionalUint64{Known: true, Value: wantTotal}) ||
		series.ActiveFlowCount != (flow_observation.OptionalUint64{Known: true, Value: 0}) {
		t.Fatalf("concurrent integrated series is not exact: %+v", terminal.CounterSeries)
	}
}

func startIntegratedSpliceCore(t testing.TB, remote *stdnet.TCPAddr) (*core.Instance, *stdnet.TCPAddr, flow_observation.Observer) {
	t.Helper()
	inboundPort := tcp.PickPort()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&app_log.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&app_router.Config{Rule: []*app_router.RoutingRule{{
				InboundTag: []string{integratedSpliceInboundTag},
				Networks:   []net.Network{net.Network_TCP},
				RuleTag:    integratedSpliceRuleTag,
				TargetTag:  &app_router.RoutingRule_Tag{Tag: integratedSpliceOutboundTag},
			}}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: integratedSpliceInboundTag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(inboundPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(net.IPAddress(remote.IP)),
				RewritePort:     uint32(remote.Port),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: integratedSpliceOutboundTag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	dispatcherFeature := instance.GetFeature(feature_routing.DispatcherType())
	provider, ok := dispatcherFeature.(flow_observation.Provider)
	if !ok || provider.FlowObserver() == nil {
		instance.Close()
		t.Fatalf("integrated dispatcher has no flow observer: %T", dispatcherFeature)
	}
	return instance, &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(inboundPort)}, provider.FlowObserver()
}

func writeIntegratedSplicePayload(writer io.Writer, payload []byte) error {
	written, err := io.Copy(writer, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if written != int64(len(payload)) {
		return fmt.Errorf("short integrated response write: got %d, want %d", written, len(payload))
	}
	return nil
}

func dialIntegratedSpliceInbound(t testing.TB, address *stdnet.TCPAddr) *stdnet.TCPConn {
	t.Helper()
	connection, err := dialIntegratedSpliceInboundResult(address)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func dialIntegratedSpliceInboundResult(address *stdnet.TCPAddr) (*stdnet.TCPConn, error) {
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		connection, err := stdnet.DialTCP("tcp4", nil, address)
		if err == nil {
			return connection, nil
		}
		lastErr = err
		time.Sleep(time.Millisecond)
	}
	return nil, fmt.Errorf("dial integrated splice inbound: %w", lastErr)
}

func waitForIntegratedSpliceSnapshot(t testing.TB, observer flow_observation.Observer, predicate func(flow_observation.Snapshot) bool) flow_observation.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var snapshot flow_observation.Snapshot
	for time.Now().Before(deadline) {
		snapshot = observer.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("integrated splice snapshot did not reach required state: %+v", snapshot)
	return flow_observation.Snapshot{}
}

func integratedSpliceObservation(record flow_observation.Record) (flow_observation.ByteObservation, bool) {
	for _, observation := range record.ByteObservations {
		if observation.Direction == flow_observation.DirectionDownlink && observation.ByteScope == flow_observation.ByteScopeKernelDirectCopyAccepted {
			return observation, true
		}
	}
	return flow_observation.ByteObservation{}, false
}

func integratedSpliceSeries(snapshot flow_observation.Snapshot) (flow_observation.CounterSeries, bool) {
	for _, series := range snapshot.CounterSeries {
		if series.Key.SelectedTopLevelOutboundTag == integratedSpliceOutboundTag &&
			series.Key.Direction == flow_observation.DirectionDownlink &&
			series.Key.ByteScope == flow_observation.ByteScopeKernelDirectCopyAccepted {
			return series, true
		}
	}
	return flow_observation.CounterSeries{}, false
}

func auditIntegratedSpliceSnapshots(observer flow_observation.Observer, maxBytes uint64, stop <-chan struct{}, result chan<- error) {
	ticker := time.NewTicker(100 * time.Microsecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			result <- nil
			return
		case <-ticker.C:
			snapshot := observer.Snapshot()
			if snapshot.AccountingCoverage.State != flow_observation.AccountingCoverageComplete {
				result <- fmt.Errorf("concurrent snapshot lost accounting coverage: %+v", snapshot.AccountingCoverage)
				return
			}
			flowIDs := make(map[string]struct{}, len(snapshot.Records))
			for _, record := range snapshot.Records {
				if _, duplicate := flowIDs[record.FlowID]; duplicate {
					result <- fmt.Errorf("concurrent snapshot duplicated flow ID %s", record.FlowID)
					return
				}
				flowIDs[record.FlowID] = struct{}{}
				if observation, ok := integratedSpliceObservation(record); ok &&
					observation.ObservedBytes.Known && observation.ObservedBytes.Value > maxBytes {
					result <- fmt.Errorf("concurrent snapshot overcounted flow %s: %+v", record.FlowID, observation)
					return
				}
			}
		}
	}
}
