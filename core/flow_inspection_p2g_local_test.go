package core_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	frouting "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	baseproxy "github.com/xtls/xray-core/proxy"
	proxyhttp "github.com/xtls/xray-core/proxy/http"
	proxyhysteria "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/vless"
	vlessencoding "github.com/xtls/xray-core/proxy/vless/encoding"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	transporthysteria "github.com/xtls/xray-core/transport/internet/hysteria"
)

func inspectionHTTPInbound(t *testing.T) (fs.FlowInspection, string) {
	return inspectionHTTPInboundConfig(t, &proxyhttp.ServerConfig{})
}

func inspectionHTTPInboundConfig(t *testing.T, config *proxyhttp.ServerConfig) (fs.FlowInspection, string) {
	t.Helper()
	instance, view, _ := inspectionCore(t, true, false)
	port := tcp.PickPort()
	if err := core.AddInboundHandler(instance, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
		}),
		ProxySettings: serial.ToTypedMessage(config),
	}); err != nil {
		t.Fatal(err)
	}
	return view, net.JoinHostPort("127.0.0.1", port.String())
}

func TestFlowInspectionP2GHTTPAuthHandshakeExcluded(t *testing.T) {
	view, address := inspectionHTTPInboundConfig(t, &proxyhttp.ServerConfig{Accounts: map[string]string{"user": "password"}})
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := stdhttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || response.StatusCode != stdhttp.StatusProxyAuthRequired {
		t.Fatalf("authentication response: %+v %v", response, err)
	}
	response.Body.Close()
	live, liveErr := view.ReadLive(context.Background())
	terminals, terminalErr := view.ReadTerminals(context.Background())
	if liveErr != nil || terminalErr != nil || len(live.Rows) != 0 || len(terminals.Rows) != 0 {
		t.Fatalf("authentication handshake admitted payload work: live=%+v terminals=%+v errors=%v/%v", live.Rows, terminals.Rows, liveErr, terminalErr)
	}
}

func TestFlowInspectionP2GHTTPKeepAliveAndLocalResponse(t *testing.T) {
	origin := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body := []byte("origin:" + r.URL.Path)
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer origin.Close()

	view, address := inspectionHTTPInbound(t)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	for i, path := range []string{"/one", "/two"} {
		connection := "keep-alive"
		if i == 1 {
			connection = "close"
		}
		if _, err := fmt.Fprintf(conn, "GET %s%s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: %s\r\n\r\n", origin.URL, path, origin.Listener.Addr(), connection); err != nil {
			t.Fatal(err)
		}
		response, err := stdhttp.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "origin:"+path {
			t.Fatalf("response %d: %q %v", i, body, err)
		}
		inspectionWait(t, func() bool {
			page, _ := view.ReadTerminals(context.Background())
			return len(page.Rows) == i+1
		})
	}
	page, err := view.ReadTerminals(context.Background())
	if err != nil || len(page.Rows) != 2 {
		t.Fatalf("HTTP request terminals: %+v %v", page.Rows, err)
	}
	if page.Rows[0].Flow.Ref == page.Rows[1].Flow.Ref {
		t.Fatal("keep-alive requests reused one FlowRef")
	}
	for _, row := range page.Rows {
		if row.Flow.Kind != fs.FlowKindTCP || row.Flow.AccountingRoute.Outbound.Tag != "direct" || row.Flow.AccountingRoute.Outbound.Serial == 0 || row.Flow.Uplink.Known == 0 || row.Flow.Downlink.Known <= uint64(len("origin:/one")) || row.Flow.Uplink.Incomplete || row.Flow.Downlink.Incomplete {
			t.Fatalf("HTTP request receipt: %+v", row)
		}
	}

	bad, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	bad.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(bad, "GET /bad HTTP/1.1\r\nHost: local.invalid\r\nProxy-Connection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	badResponse, err := stdhttp.ReadResponse(bufio.NewReader(bad), nil)
	if err != nil || badResponse.StatusCode != stdhttp.StatusBadRequest {
		t.Fatalf("local response: %+v %v", badResponse, err)
	}
	badResponse.Body.Close()
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 3
	})
	page, _ = view.ReadTerminals(context.Background())
	local := page.Rows[2]
	if local.Reason != fs.EndReasonRejected || local.Flow.AccountingRoute.Outbound.Serial != 0 || len(local.Flow.Routes) != 0 || local.Flow.Uplink.Known != 0 || !local.Flow.Uplink.Incomplete || local.Flow.Downlink.Known == 0 || local.Flow.Downlink.Incomplete {
		t.Fatalf("local HTTP response receipt: %+v", local)
	}
}

func TestFlowInspectionP2GHTTPRequestExactStop(t *testing.T) {
	started := make(chan struct{})
	origin := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/blocked" {
			close(started)
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "surviving request")
	}))
	defer origin.Close()

	view, address := inspectionHTTPInbound(t)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := fmt.Fprintf(conn, "GET %s/blocked HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", origin.URL, origin.Listener.Addr()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked HTTP request did not reach execution")
	}
	var ref fs.FlowRef
	inspectionWait(t, func() bool {
		live, _ := view.ReadLive(context.Background())
		if len(live.Rows) != 1 || live.Rows[0].AccountingRoute.Outbound.Serial == 0 {
			return false
		}
		ref = live.Rows[0].Ref
		return true
	})
	outcomes, err := view.CloseFlows(context.Background(), []fs.FlowRef{ref})
	if err != nil || len(outcomes) != 1 || outcomes[0].Code != fs.CloseCodeAccepted {
		t.Fatalf("HTTP request stop: %+v %v", outcomes, err)
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1 && page.Rows[0].Flow.Ref == ref && page.Rows[0].Reason == fs.EndReasonLocalStop
	})
	stoppedResponse, err := stdhttp.ReadResponse(reader, nil)
	if err != nil || stoppedResponse.StatusCode != stdhttp.StatusServiceUnavailable {
		t.Fatalf("stopped request response: %+v %v", stoppedResponse, err)
	}
	stoppedResponse.Body.Close()

	// The exact stop owns only the first request's dispatch pipes. The accepted
	// keep-alive socket remains the native HTTP owner's resource.
	if _, err := fmt.Fprintf(conn, "GET %s/survivor HTTP/1.1\r\nHost: %s\r\nProxy-Connection: close\r\n\r\n", origin.URL, origin.Listener.Addr()); err != nil {
		t.Fatal(err)
	}
	response, err := stdhttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "surviving request" {
		t.Fatalf("surviving request: %q %v", body, err)
	}
}

func inspectionProtocolContext(instance *core.Instance) context.Context {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	return session.ContextWithInbound(ctx, &session.Inbound{
		Source:  cnet.TCPDestination(cnet.LocalHostIP, 31001),
		Gateway: cnet.TCPDestination(cnet.LocalHostIP, 31002),
	})
}

type inspectionResponseFailureConn struct{ net.Conn }

func (inspectionResponseFailureConn) SetReadDeadline(time.Time) error { return nil }

func runClosedPipeRequest(t *testing.T, instance *core.Instance, inbound baseproxy.Inbound, write func(io.Writer) error) error {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		err := write(client)
		client.Close()
		done <- err
	}()
	dispatcher := instance.GetFeature(frouting.DispatcherType()).(frouting.Dispatcher)
	err := inbound.Process(inspectionProtocolContext(instance), cnet.Network_TCP, inspectionResponseFailureConn{server}, dispatcher)
	server.Close()
	if writeErr := <-done; writeErr != nil {
		t.Fatal(writeErr)
	}
	return err
}

func TestFlowInspectionP2GVLESSDecodedRejectionBeforeResponse(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	id := uuid.New()
	account := &vless.Account{Id: id.String(), Flow: vless.XRV}
	user := &protocol.User{Account: serial.ToTypedMessage(account)}
	object, err := core.CreateObject(instance, &vlessin.Config{Users: []*protocol.User{user}})
	if err != nil {
		t.Fatal(err)
	}
	memoryAccount, err := account.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		Version: vlessencoding.Version,
		User:    &protocol.MemoryUser{Account: memoryAccount},
		Command: protocol.RequestCommandUDP,
		Address: cnet.LocalHostIP,
		Port:    53,
	}
	err = runClosedPipeRequest(t, instance, object.(baseproxy.Inbound), func(writer io.Writer) error {
		buffer := buf.StackNew()
		defer buffer.Release()
		if err := vlessencoding.EncodeRequestHeader(&buffer, request, &vlessencoding.Addons{Flow: vless.XRV}); err != nil {
			return err
		}
		_, err := writer.Write(buffer.Bytes())
		return err
	})
	if err == nil {
		t.Fatal("VLESS XRV UDP request unexpectedly succeeded")
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1
	})
	page, _ := view.ReadTerminals(context.Background())
	row := page.Rows[0]
	if row.Reason != fs.EndReasonRejected || row.Flow.InitialDestination != request.Destination() || row.Flow.AccountingRoute.Outbound.Serial != 0 || len(row.Flow.Routes) != 0 || row.Flow.Uplink.Known != 0 || row.Flow.Downlink.Known != 0 {
		t.Fatalf("VLESS pre-response rejection: %+v", row)
	}
}

func TestFlowInspectionP2GHysteriaResponsePreparationFailure(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	createCtx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	createCtx = session.ContextWithStreamSettings(createCtx, &internet.MemoryStreamConfig{ProtocolSettings: &transporthysteria.Config{}})
	object, err := proxyhysteria.NewServer(createCtx, &proxyhysteria.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	err = runClosedPipeRequest(t, instance, object, func(writer io.Writer) error {
		return proxyhysteria.WriteTCPRequest(writer, "127.0.0.1:53")
	})
	if err == nil {
		t.Fatal("Hysteria response preparation unexpectedly succeeded")
	}
	inspectionWait(t, func() bool {
		page, _ := view.ReadTerminals(context.Background())
		return len(page.Rows) == 1
	})
	page, _ := view.ReadTerminals(context.Background())
	row := page.Rows[0]
	if row.Reason != fs.EndReasonRejected || row.Flow.AccountingRoute.Outbound.Serial != 0 || len(row.Flow.Routes) != 0 || row.Flow.Uplink.Known != 0 || row.Flow.Downlink.Known != 0 {
		t.Fatalf("Hysteria pre-response rejection: %+v", row)
	}
}

func TestFlowInspectionP2GNaturalEOF(t *testing.T) {
	for _, test := range []struct {
		name     string
		receiver inspectionSuppliedTCPReceiver
	}{
		{name: "Shadowsocks", receiver: inspectionShadowsocksReceiver},
		{name: "Trojan", receiver: inspectionTrojanReceiver},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, view, outbound := test.receiver(t, true, false)
			_, _, address := inspectionTCPOutboundThrough(t, false, outbound)
			destination := startOutboundStatsTCPServer(t)
			payload := bytes.Repeat([]byte("natural-eof"), 128)
			client := inspectionSOCKS(t, address, destination, payload)
			client.Close()
			inspectionWait(t, func() bool {
				page, _ := view.ReadTerminals(context.Background())
				return len(page.Rows) == 1
			})
			page, _ := view.ReadTerminals(context.Background())
			if page.Rows[0].Reason != fs.EndReasonEOF || page.Rows[0].Flow.Uplink.Known != uint64(len(payload)) || page.Rows[0].Flow.Downlink.Known != uint64(len(payload)) {
				t.Fatalf("natural EOF receipt: %+v", page.Rows[0])
			}
		})
	}
}
