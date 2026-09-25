package core_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	commonnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

const (
	outboundStatsUplinkSuffix   = ">>>traffic>>>uplink"
	outboundStatsDownlinkSuffix = ">>>traffic>>>downlink"
)

func TestReadOutboundStatsMissingFeatures(t *testing.T) {
	got := core.ReadOutboundStats(new(core.Instance), "missing")
	if got != (core.OutboundStats{}) {
		t.Fatalf("bare instance result: got %+v want zero value", got)
	}
}

func TestReadOutboundStatsMissingManagerPreservesAvailableFacts(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&policy.Config{
			System: &policy.SystemPolicy{
				Stats: &policy.SystemPolicy_Stats{OutboundUplink: true},
			},
		}),
		serial.ToTypedMessage(&appstats.Config{}),
	}})
	if err != nil {
		t.Fatalf("create instance without outbound manager: %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close instance: %v", err)
		}
	})

	statsManager := instance.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	registerOutboundCounter(t, statsManager, "no-manager", outboundStatsUplinkSuffix).Add(29)
	want := core.OutboundStats{
		PolicyManagerAvailable: true,
		StatsManagerAvailable:  true,
		Uplink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
			Bytes:          29,
		},
	}
	if got := core.ReadOutboundStats(instance, "no-manager"); got != want {
		t.Fatalf("missing outbound manager result: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsEmptyTag(t *testing.T) {
	fixture := newOutboundStatsFixture(t, true, true, true, "")
	if fixture.outbound.GetDefaultHandler() == nil {
		t.Fatal("fixture has no untagged default handler")
	}

	uplink := registerOutboundCounter(t, fixture.stats, "", outboundStatsUplinkSuffix)
	downlink := registerOutboundCounter(t, fixture.stats, "", outboundStatsDownlinkSuffix)
	uplink.Add(11)
	downlink.Add(13)

	want := core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		StatsManagerAvailable:    true,
		Uplink:                   core.OutboundStatsDirection{PolicyEnabled: true},
		Downlink:                 core.OutboundStatsDirection{PolicyEnabled: true},
	}
	if got := core.ReadOutboundStats(fixture.instance, ""); got != want {
		t.Fatalf("empty tag result: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsMissingTagReadsIndependentFacts(t *testing.T) {
	fixture := newOutboundStatsFixture(t, false, true, true)
	registerOutboundCounter(t, fixture.stats, "retained", outboundStatsUplinkSuffix).Add(41)

	want := core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		StatsManagerAvailable:    true,
		Uplink: core.OutboundStatsDirection{
			CounterPresent: true,
			Bytes:          41,
		},
		Downlink: core.OutboundStatsDirection{PolicyEnabled: true},
	}
	if got := core.ReadOutboundStats(fixture.instance, "retained"); got != want {
		t.Fatalf("missing tag result: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsNoopStatsManager(t *testing.T) {
	fixture := newOutboundStatsFixture(t, true, true, false, "noop")

	want := core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		HandlerPresent:           true,
		Uplink:                   core.OutboundStatsDirection{PolicyEnabled: true},
		Downlink:                 core.OutboundStatsDirection{PolicyEnabled: true},
	}
	if got := core.ReadOutboundStats(fixture.instance, "noop"); got != want {
		t.Fatalf("noop stats result: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsHandlerWithDisabledPolicy(t *testing.T) {
	fixture := newOutboundStatsFixture(t, false, false, true, "disabled")

	want := core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		StatsManagerAvailable:    true,
		HandlerPresent:           true,
	}
	if got := core.ReadOutboundStats(fixture.instance, "disabled"); got != want {
		t.Fatalf("disabled policy result: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsValuesArePresentAndNonDestructive(t *testing.T) {
	fixture := newOutboundStatsFixture(t, true, true, true, "values")

	zero := core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		StatsManagerAvailable:    true,
		HandlerPresent:           true,
		Uplink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
		},
		Downlink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
		},
	}
	if got := core.ReadOutboundStats(fixture.instance, "values"); got != zero {
		t.Fatalf("zero counters result: got %+v want %+v", got, zero)
	}

	fixture.stats.GetCounter(outboundCounterName("values", outboundStatsUplinkSuffix)).Add(17)
	fixture.stats.GetCounter(outboundCounterName("values", outboundStatsDownlinkSuffix)).Add(-23)
	want := zero
	want.Uplink.Bytes = 17
	want.Downlink.Bytes = -23
	for read := 1; read <= 2; read++ {
		if got := core.ReadOutboundStats(fixture.instance, "values"); got != want {
			t.Fatalf("read %d result: got %+v want %+v", read, got, want)
		}
	}
}

func TestReadOutboundStatsCountsRealFreedomTCP(t *testing.T) {
	const tag = "stat2-freedom-tcp"

	destination := startOutboundStatsTCPServer(t)
	instance := newRealOutboundStatsInstance(t, tag)
	want := zeroRealOutboundStats()
	if got := core.ReadOutboundStats(instance, tag); got != want {
		t.Fatalf("initial outbound stats: got %+v want %+v", got, want)
	}

	request := bytes.Repeat([]byte("STAT-2 ordinary TCP payload."), 257)
	response := exchangeRealFreedomTCP(t, instance, destination, request)

	want.Uplink.Bytes = int64(len(request))
	want.Downlink.Bytes = int64(len(response))
	waitRealOutboundStats(t, instance, tag, want)
	if got := core.ReadOutboundStats(instance, tag); got != want {
		t.Fatalf("outbound stats after real TCP exchange: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsAccumulatesRealTCPPerInstance(t *testing.T) {
	const tag = "stat3-runtime-scope"

	destination := startOutboundStatsTCPServer(t)
	instance := newRealOutboundStatsInstance(t, tag)
	want := zeroRealOutboundStats()
	if got := core.ReadOutboundStats(instance, tag); got != want {
		t.Fatalf("initial outbound stats: got %+v want %+v", got, want)
	}

	requests := [][]byte{
		bytes.Repeat([]byte("STAT-3 first TCP connection."), 113),
		bytes.Repeat([]byte("STAT-3 second connection."), 71),
	}
	for connection, request := range requests {
		response := exchangeRealFreedomTCP(t, instance, destination, request)
		want.Uplink.Bytes += int64(len(request))
		want.Downlink.Bytes += int64(len(response))
		waitRealOutboundStats(t, instance, tag, want)
		for read := 1; read <= 2; read++ {
			if got := core.ReadOutboundStats(instance, tag); got != want {
				t.Fatalf("connection %d read %d: got %+v want %+v", connection+1, read, got, want)
			}
		}
	}

	freshInstance := newRealOutboundStatsInstance(t, tag)
	if got, zero := core.ReadOutboundStats(freshInstance, tag), zeroRealOutboundStats(); got != zero {
		t.Fatalf("fresh instance outbound stats: got %+v want %+v", got, zero)
	}
	if got := core.ReadOutboundStats(instance, tag); got != want {
		t.Fatalf("original instance stats after fresh instance creation: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsCountsRealFreedomUDPAssociation(t *testing.T) {
	const tag = "stat4-freedom-udp"

	destinations := []commonnet.Destination{
		startOutboundStatsUDPServer(t, 0x3c),
		startOutboundStatsUDPServer(t, 0xa7),
	}
	instance := newRealOutboundStatsInstance(t, tag)
	want := zeroRealOutboundStats()
	if got := core.ReadOutboundStats(instance, tag); got != want {
		t.Fatalf("initial outbound stats: got %+v want %+v", got, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Name: "stat4-user",
		User: &protocol.MemoryUser{Email: "stat4-user@example.invalid"},
	})
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	conn, err := core.DialUDP(ctx, instance)
	if err != nil {
		t.Fatalf("create dispatched UDP association: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close dispatched UDP association: %v", err)
		}
	})

	requests := [][]byte{
		bytes.Repeat([]byte("STAT-4 first UDP destination."), 37),
		bytes.Repeat([]byte("STAT-4 second UDP destination."), 29),
	}
	masks := []byte{0x3c, 0xa7}
	for packet, destination := range destinations {
		target := &stdnet.UDPAddr{
			IP:   destination.Address.IP(),
			Port: int(destination.Port),
		}
		request := requests[packet]
		if n, err := conn.WriteTo(request, target); err != nil {
			t.Fatalf("write UDP packet %d through Freedom: %v", packet+1, err)
		} else if n != len(request) {
			t.Fatalf("write UDP packet %d through Freedom: got %d bytes want %d", packet+1, n, len(request))
		}

		response := make([]byte, len(request)+1)
		n, source, err := conn.ReadFrom(response)
		if err != nil {
			t.Fatalf("read UDP packet %d through Freedom: %v", packet+1, err)
		}
		response = response[:n]
		if expected := transformOutboundStatsPayload(request, masks[packet]); !bytes.Equal(response, expected) {
			t.Fatalf("UDP packet %d response does not match the deterministic transform", packet+1)
		}
		sourceUDP, ok := source.(*stdnet.UDPAddr)
		if !ok || sourceUDP.Port != target.Port || !sourceUDP.IP.Equal(target.IP) {
			t.Fatalf("UDP packet %d source: got %v want %v", packet+1, source, target)
		}

		want.Uplink.Bytes += int64(len(request))
		want.Downlink.Bytes += int64(len(response))
		waitRealOutboundStats(t, instance, tag, want)
		if got := core.ReadOutboundStats(instance, tag); got != want {
			t.Fatalf("UDP packet %d outbound stats: got %+v want %+v", packet+1, got, want)
		}
	}
}

func waitRealOutboundStats(t *testing.T, instance *core.Instance, tag string, want core.OutboundStats) {
	t.Helper()
	// Peer receipt can precede return from the native counted Write call.
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := core.ReadOutboundStats(instance, tag)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbound stats did not settle: got %+v want %+v", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func startOutboundStatsTCPServer(t *testing.T) commonnet.Destination {
	t.Helper()

	server := &tcp.Server{MsgProcessor: transformOutboundStatsTCPPayload}
	destination, err := server.Start()
	if err != nil {
		t.Fatalf("start loopback TCP server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close loopback TCP server: %v", err)
		}
	})
	return destination
}

func startOutboundStatsUDPServer(t *testing.T, mask byte) commonnet.Destination {
	t.Helper()

	conn, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("start loopback UDP server: %v", err)
	}
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		defer close(done)
		defer close(errCh)
		buffer := make([]byte, 64*1024)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if !errors.Is(err, stdnet.ErrClosed) {
					errCh <- fmt.Errorf("read loopback UDP packet: %w", err)
				}
				return
			}
			response := transformOutboundStatsPayload(buffer[:n], mask)
			if _, err := conn.WriteToUDP(response, source); err != nil {
				if !errors.Is(err, stdnet.ErrClosed) {
					errCh <- fmt.Errorf("write loopback UDP packet: %w", err)
				}
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, stdnet.ErrClosed) {
			t.Errorf("close loopback UDP server: %v", err)
		}
		<-done
		if err, ok := <-errCh; ok {
			t.Error(err)
		}
	})

	local := conn.LocalAddr().(*stdnet.UDPAddr)
	return commonnet.UDPDestination(commonnet.IPAddress(local.IP), commonnet.Port(local.Port))
}

func newRealOutboundStatsInstance(t *testing.T, tag string) *core.Instance {
	t.Helper()

	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	})
	if err != nil {
		t.Fatalf("create instance: %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close instance: %v", err)
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatalf("start instance: %v", err)
	}
	return instance
}

func exchangeRealFreedomTCP(t *testing.T, instance *core.Instance, destination commonnet.Destination, request []byte) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, instance, destination)
	if err != nil {
		t.Fatalf("dial loopback TCP server through Freedom: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close dispatched TCP connection: %v", err)
		}
	}()

	if n, err := conn.Write(request); err != nil {
		t.Fatalf("write request through Freedom: %v", err)
	} else if n != len(request) {
		t.Fatalf("write request through Freedom: got %d bytes want %d", n, len(request))
	}

	response := make([]byte, len(request))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read response through Freedom: %v", err)
	}
	if expected := transformOutboundStatsTCPPayload(request); !bytes.Equal(response, expected) {
		t.Fatal("loopback TCP response does not match the deterministic transform")
	}
	return response
}

func transformOutboundStatsTCPPayload(payload []byte) []byte {
	return transformOutboundStatsPayload(payload, 0x5a)
}

func transformOutboundStatsPayload(payload []byte, mask byte) []byte {
	response := bytes.Clone(payload)
	for i := range response {
		response[i] ^= mask
	}
	return response
}

func zeroRealOutboundStats() core.OutboundStats {
	return core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		StatsManagerAvailable:    true,
		HandlerPresent:           true,
		Uplink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
		},
		Downlink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
		},
	}
}

func TestReadOutboundStatsRetainsCountersAfterHandlerRemoval(t *testing.T) {
	fixture := newOutboundStatsFixture(t, true, true, true, "removed")
	handler := fixture.outbound.GetHandler("removed")
	if handler == nil {
		t.Fatal("fixture handler is missing")
	}
	t.Cleanup(func() {
		if fixture.outbound.GetHandler("removed") != nil {
			return
		}
		if err := handler.Close(); err != nil {
			t.Errorf("close removed handler: %v", err)
		}
	})

	fixture.stats.GetCounter(outboundCounterName("removed", outboundStatsUplinkSuffix)).Add(5)
	fixture.stats.GetCounter(outboundCounterName("removed", outboundStatsDownlinkSuffix)).Add(-7)
	if err := fixture.outbound.RemoveHandler(context.Background(), "removed"); err != nil {
		t.Fatalf("remove handler: %v", err)
	}

	want := core.OutboundStats{
		OutboundManagerAvailable: true,
		PolicyManagerAvailable:   true,
		StatsManagerAvailable:    true,
		Uplink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
			Bytes:          5,
		},
		Downlink: core.OutboundStatsDirection{
			PolicyEnabled:  true,
			CounterPresent: true,
			Bytes:          -7,
		},
	}
	if got := core.ReadOutboundStats(fixture.instance, "removed"); got != want {
		t.Fatalf("removed handler result: got %+v want %+v", got, want)
	}
}

func TestReadOutboundStatsConcurrentCounterUpdates(t *testing.T) {
	fixture := newOutboundStatsFixture(t, true, true, true, "concurrent")
	uplink := fixture.stats.GetCounter(outboundCounterName("concurrent", outboundStatsUplinkSuffix))
	downlink := fixture.stats.GetCounter(outboundCounterName("concurrent", outboundStatsDownlinkSuffix))
	if uplink == nil || downlink == nil {
		t.Fatal("fixture counters are missing")
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			uplink.Add(1)
			downlink.Add(-1)
			runtime.Gosched()
		}
		close(done)
	}()

	for {
		observation := core.ReadOutboundStats(fixture.instance, "concurrent")
		if !observation.HandlerPresent || !observation.Uplink.CounterPresent || !observation.Downlink.CounterPresent {
			t.Fatalf("concurrent observation lost stable facts: %+v", observation)
		}
		select {
		case <-done:
			return
		default:
			runtime.Gosched()
		}
	}
}

type outboundStatsFixture struct {
	instance *core.Instance
	outbound featureoutbound.Manager
	stats    featurestats.Manager
}

func newOutboundStatsFixture(t *testing.T, uplink, downlink, realStats bool, tags ...string) outboundStatsFixture {
	t.Helper()

	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&policy.Config{
			System: &policy.SystemPolicy{
				Stats: &policy.SystemPolicy_Stats{
					OutboundUplink:   uplink,
					OutboundDownlink: downlink,
				},
			},
		}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	if realStats {
		apps = append(apps, serial.ToTypedMessage(&appstats.Config{}))
	}

	outbounds := make([]*core.OutboundHandlerConfig, 0, len(tags))
	for _, tag := range tags {
		outbounds = append(outbounds, &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		})
	}

	instance, err := core.New(&core.Config{App: apps, Outbound: outbounds})
	if err != nil {
		t.Fatalf("create instance: %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close instance: %v", err)
		}
	})

	outboundManager, ok := instance.GetFeature(featureoutbound.ManagerType()).(featureoutbound.Manager)
	if !ok {
		t.Fatal("outbound manager is missing")
	}
	statsManager, ok := instance.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	if !ok {
		t.Fatal("stats manager is missing")
	}
	return outboundStatsFixture{instance: instance, outbound: outboundManager, stats: statsManager}
}

func registerOutboundCounter(t *testing.T, manager featurestats.Manager, tag, suffix string) featurestats.Counter {
	t.Helper()
	counter, err := manager.GetOrRegisterCounter(outboundCounterName(tag, suffix))
	if err != nil {
		t.Fatalf("register counter: %v", err)
	}
	if counter == nil {
		t.Fatal("registered counter is nil")
	}
	return counter
}

func outboundCounterName(tag, suffix string) string {
	return "outbound>>>" + tag + suffix
}
