package core_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	flow_observation "github.com/xtls/xray-core/app/dispatcher/flow"
	app_log "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	app_router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	feature_routing "github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	v2http "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/vless"
	vless_encoding "github.com/xtls/xray-core/proxy/vless/encoding"
	vless_inbound "github.com/xtls/xray-core/proxy/vless/inbound"
)

const (
	unixFlowOutboundTag = "f1-unix-direct"
	unixFlowRuleTag     = "f1-unix-direct-rule"
)

func TestUnixDokodemoDispatchLinkFlow(t *testing.T) {
	runUnixFlowIntegration(t, "dokodemo", func(remote *stdnet.TCPAddr) *serial.TypedMessage {
		return serial.ToTypedMessage(&dokodemo.Config{
			RewriteAddress:  net.NewIPOrDomain(net.IPAddress(remote.IP)),
			RewritePort:     uint32(remote.Port),
			AllowedNetworks: []net.Network{net.Network_TCP},
		})
	}, func(socketPath string, _ *stdnet.TCPAddr) *unixFlowClient {
		return dialUnixFlowClient(t, socketPath)
	})
}

func TestUnixHTTPConnectDispatchLinkFlow(t *testing.T) {
	runUnixFlowIntegration(t, "http-connect", func(_ *stdnet.TCPAddr) *serial.TypedMessage {
		return serial.ToTypedMessage(&v2http.ServerConfig{})
	}, func(socketPath string, remote *stdnet.TCPAddr) *unixFlowClient {
		client := dialUnixFlowClient(t, socketPath)
		request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", remote.String(), remote.String())
		if _, err := io.WriteString(client.connection, request); err != nil {
			client.Close()
			t.Fatal(err)
		}
		reader := bufio.NewReader(client.connection)
		status, err := reader.ReadString('\n')
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		if !strings.Contains(status, " 200 ") {
			client.Close()
			t.Fatalf("HTTP CONNECT was rejected: %q", status)
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				client.Close()
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		client.reader = reader
		return client
	})
}

func TestUnixVLESSDispatchLinkFlow(t *testing.T) {
	userID := uuid.New()
	runUnixFlowIntegration(t, "vless", func(_ *stdnet.TCPAddr) *serial.TypedMessage {
		return serial.ToTypedMessage(&vless_inbound.Config{Users: []*protocol.User{{
			Account: serial.ToTypedMessage(&vless.Account{Id: userID.String()}),
		}}})
	}, func(socketPath string, remote *stdnet.TCPAddr) *unixFlowClient {
		client := dialUnixFlowClient(t, socketPath)
		account, err := (&vless.Account{Id: userID.String()}).AsAccount()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		request := &protocol.RequestHeader{
			Version: vless_encoding.Version,
			User:    &protocol.MemoryUser{Account: account},
			Command: protocol.RequestCommandTCP,
			Address: net.IPAddress(remote.IP),
			Port:    net.Port(remote.Port),
		}
		if err := vless_encoding.EncodeRequestHeader(client.connection, request, &vless_encoding.Addons{}); err != nil {
			client.Close()
			t.Fatal(err)
		}
		client.reader = &unixFlowVLESSReader{reader: client.connection, request: request}
		return client
	})
}

func runUnixFlowIntegration(t *testing.T, name string, inboundConfig func(*stdnet.TCPAddr) *serial.TypedMessage, connect func(string, *stdnet.TCPAddr) *unixFlowClient) {
	t.Helper()
	echo := startUnixFlowEcho(t)
	defer echo.Close()
	socketDir, err := os.MkdirTemp("", "xr-u-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, name+".sock")
	instance, observer := startUnixFlowCore(t, socketPath, "f1-unix-"+name, inboundConfig(echo.address))
	defer instance.Close()
	client := connect(socketPath, echo.address)
	defer client.Close()
	payload := []byte("f1-unix-dispatch-link-payload")
	if _, err := client.connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(client.reader, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("%s UNIX path changed payload: got %q want %q", name, received, payload)
	}
	live := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState != flow_observation.CompletionTerminal
	})
	assertUnixFlowRecord(t, live.Records[0], false, uint64(len(payload)))
	echo.Release()
	if err := client.connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.reader.Read(make([]byte, 1)); err == nil {
		t.Fatal("UNIX client remained open after the stock remote connection closed")
	}
	echo.Wait(t)
	terminal := waitForUnixFlowSnapshot(t, observer, func(snapshot flow_observation.Snapshot) bool {
		return len(snapshot.Records) == 1 && snapshot.Records[0].CompletionState == flow_observation.CompletionTerminal
	})
	assertUnixFlowRecord(t, terminal.Records[0], true, uint64(len(payload)))
}

func startUnixFlowCore(t testing.TB, socketPath, inboundTag string, inboundConfig *serial.TypedMessage) (*core.Instance, flow_observation.Observer) {
	t.Helper()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&app_log.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&app_router.Config{Rule: []*app_router.RoutingRule{{
				InboundTag: []string{inboundTag},
				Networks:   []net.Network{net.Network_TCP},
				RuleTag:    unixFlowRuleTag,
				TargetTag:  &app_router.RoutingRule_Tag{Tag: unixFlowOutboundTag},
			}}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: inboundTag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen: net.NewIPOrDomain(net.DomainAddress(socketPath)),
			}),
			ProxySettings: inboundConfig,
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: unixFlowOutboundTag,
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
		t.Fatalf("UNIX dispatcher has no flow observer: %T", dispatcherFeature)
	}
	return instance, provider.FlowObserver()
}

type unixFlowClient struct {
	connection *stdnet.UnixConn
	reader     io.Reader
}

type unixFlowVLESSReader struct {
	reader  io.Reader
	request *protocol.RequestHeader
	decoded bool
}

func (r *unixFlowVLESSReader) Read(payload []byte) (int, error) {
	if !r.decoded {
		if _, err := vless_encoding.DecodeResponseHeader(r.reader, r.request); err != nil {
			return 0, err
		}
		r.decoded = true
	}
	return r.reader.Read(payload)
}

func dialUnixFlowClient(t testing.TB, socketPath string) *unixFlowClient {
	t.Helper()
	connection, err := stdnet.DialUnix("unix", nil, &stdnet.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	return &unixFlowClient{connection: connection, reader: connection}
}

func (c *unixFlowClient) Close() {
	if c != nil && c.connection != nil {
		_ = c.connection.Close()
	}
}

type unixFlowEcho struct {
	listener *stdnet.TCPListener
	address  *stdnet.TCPAddr
	release  chan struct{}
	result   chan error
	once     sync.Once
}

func startUnixFlowEcho(t testing.TB) *unixFlowEcho {
	t.Helper()
	listener, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echo := &unixFlowEcho{listener: listener, address: listener.Addr().(*stdnet.TCPAddr), release: make(chan struct{}), result: make(chan error, 1)}
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			echo.result <- err
			return
		}
		defer connection.Close()
		payload := make([]byte, len("f1-unix-dispatch-link-payload"))
		if _, err := io.ReadFull(connection, payload); err != nil {
			echo.result <- err
			return
		}
		if _, err := connection.Write(payload); err != nil {
			echo.result <- err
			return
		}
		<-echo.release
		echo.result <- nil
	}()
	return echo
}

func (e *unixFlowEcho) Release() {
	e.once.Do(func() { close(e.release) })
}

func (e *unixFlowEcho) Wait(t testing.TB) {
	t.Helper()
	select {
	case err := <-e.result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP echo did not complete")
	}
}

func (e *unixFlowEcho) Close() {
	e.Release()
	_ = e.listener.Close()
}

func waitForUnixFlowSnapshot(t testing.TB, observer flow_observation.Observer, predicate func(flow_observation.Snapshot) bool) flow_observation.Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var snapshot flow_observation.Snapshot
	for time.Now().Before(deadline) {
		snapshot = observer.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("UNIX flow snapshot did not reach required state: %+v", snapshot)
	return flow_observation.Snapshot{}
}

func assertUnixFlowRecord(t testing.TB, record flow_observation.Record, terminal bool, payloadBytes uint64) {
	t.Helper()
	if record.Route.MatchedNativeRuleTag != unixFlowRuleTag || record.Route.SelectedTopLevelOutboundTag != unixFlowOutboundTag {
		t.Fatalf("UNIX flow lost selected outbound or route: %+v", record.Route)
	}
	if (record.CompletionState == flow_observation.CompletionTerminal) != terminal {
		t.Fatalf("UNIX flow terminal state = %s, want terminal=%t", record.CompletionState, terminal)
	}
	for _, direction := range []flow_observation.Direction{flow_observation.DirectionUplink, flow_observation.DirectionDownlink} {
		observation, ok := unixExternalLinkObservation(record, direction)
		if !ok || observation.State != flow_observation.ByteObservationStateProven || !observation.ObservedBytes.Known || observation.ObservedBytes.Value < payloadBytes {
			t.Fatalf("UNIX flow %s external-link accepted bytes are not proven: %+v", direction, observation)
		}
	}
}

func unixExternalLinkObservation(record flow_observation.Record, direction flow_observation.Direction) (flow_observation.ByteObservation, bool) {
	for _, observation := range record.ByteObservations {
		if observation.Direction == direction && observation.ByteScope == flow_observation.ByteScopeDispatcherExternalLinkIO {
			return observation, true
		}
	}
	return flow_observation.ByteObservation{}, false
}
