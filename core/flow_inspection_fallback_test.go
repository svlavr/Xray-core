package core_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/trojan"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestFlowInspectionFallback(t *testing.T) {
	for _, protocol := range []string{"VLESS", "Trojan"} {
		t.Run(protocol, func(t *testing.T) {
			for _, xver := range []uint64{0, 1, 2} {
				t.Run("xver-"+string(rune('0'+xver)), func(t *testing.T) {
					inspectionFallbackAcceptance(t, protocol, xver)
				})
			}
			t.Run("disabled", func(t *testing.T) {
				target, configured := inspectionFallbackTarget(t, 0)
				instance, _, address := inspectionFallbackCore(t, protocol, false, 0, configured)
				payload := []byte("disabled fallback payload")
				client := inspectionFallbackClient(t, address, payload)
				inspectionFallbackResponse(t, client, payload)
				if instance.GetFeature(fs.ManagerType()).(fs.ObservationProvider).Observation() != nil {
					t.Fatal("disabled fallback acquired inspection state")
				}
				target.Close()
			})
			t.Run("dial-failure", func(t *testing.T) {
				inspectionFallbackDialFailure(t, protocol)
			})
			t.Run("peer-reset", func(t *testing.T) {
				inspectionFallbackPeerReset(t, protocol)
			})
		})
	}
}

func inspectionFallbackAcceptance(t *testing.T, protocol string, xver uint64) {
	t.Helper()
	_, configured := inspectionFallbackTarget(t, xver)
	_, view, address := inspectionFallbackCore(t, protocol, true, xver, configured)
	payload := append([]byte("GET /fallback HTTP/1.1\r\nHost: retained.invalid\r\n\r\n"), bytes.Repeat([]byte("p"), 4096)...)
	first := inspectionFallbackClient(t, address, payload)
	inspectionFallbackResponse(t, first, payload)
	sibling := inspectionFallbackClient(t, address, []byte("fallback sibling"))
	inspectionFallbackResponse(t, sibling, []byte("fallback sibling"))
	first.Close()
	extra := []byte("sibling after peer close")
	if _, err := sibling.Write(extra); err != nil {
		t.Fatal(err)
	}
	inspectionFallbackResponse(t, sibling, extra)
	sibling.Close()
	assertNoDedicatedServerInspection(t, view)
}

func inspectionFallbackCore(t *testing.T, protocol string, enabled bool, xver uint64, target string) (*core.Instance, fs.FlowInspection, string) {
	t.Helper()
	port := tcp.PickPort()
	var settings *serial.TypedMessage
	switch protocol {
	case "VLESS":
		settings = serial.ToTypedMessage(&vlessin.Config{Fallbacks: []*vlessin.Fallback{{Type: "tcp4", Dest: target, Xver: xver}}})
	case "Trojan":
		settings = serial.ToTypedMessage(&trojan.ServerConfig{Fallbacks: []*trojan.Fallback{{Type: "tcp4", Dest: target, Xver: xver}}})
	default:
		t.Fatalf("unknown fallback protocol %q", protocol)
	}
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&router.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen: cnet.NewIPOrDomain(cnet.LocalHostIP), PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			}),
			ProxySettings: settings,
		}},
		Outbound: []*core.OutboundHandlerConfig{inspectionFreedom("direct")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	var view fs.FlowInspection
	if enabled {
		view, err = core.EnableFlowInspection(instance, fs.ObservationOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, view, net.JoinHostPort("127.0.0.1", port.String())
}

func inspectionFallbackTarget(t *testing.T, xver uint64) (net.Listener, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go inspectionFallbackEcho(t, conn, xver)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, net.JoinHostPort("localhost", cnet.Port(port).String())
}

func inspectionFallbackEcho(t *testing.T, conn net.Conn, xver uint64) {
	t.Helper()
	defer conn.Close()
	reader := inspectionFallbackPayloadReader(t, conn, xver)
	if reader != nil {
		_, _ = io.Copy(conn, reader)
	}
}

func inspectionFallbackPayloadReader(t *testing.T, conn net.Conn, xver uint64) io.Reader {
	t.Helper()
	var reader io.Reader = conn
	switch xver {
	case 0:
	case 1:
		buffered := bufio.NewReader(conn)
		header, err := buffered.ReadString('\n')
		if err != nil || !strings.HasPrefix(header, "PROXY ") || !strings.HasSuffix(header, "\r\n") {
			t.Errorf("invalid PROXY v1 header %q: %v", header, err)
			return nil
		}
		reader = buffered
	case 2:
		buffered := bufio.NewReader(conn)
		header := make([]byte, 16)
		if _, err := io.ReadFull(buffered, header); err != nil || !bytes.Equal(header[:12], []byte("\r\n\r\n\x00\r\nQUIT\n")) {
			t.Errorf("invalid PROXY v2 header %x: %v", header, err)
			return nil
		}
		address := make([]byte, int(binary.BigEndian.Uint16(header[14:16])))
		if _, err := io.ReadFull(buffered, address); err != nil {
			t.Errorf("invalid PROXY v2 address: %v", err)
			return nil
		}
		reader = buffered
	default:
		t.Errorf("unexpected xver %d", xver)
		return nil
	}
	return reader
}

func inspectionFallbackClient(t *testing.T, address string, payload []byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	return conn
}

func inspectionFallbackResponse(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("fallback response %q, want %q: %v", got, want, err)
	}
}

func inspectionFallbackDialFailure(t *testing.T, protocol string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	listener.Close()
	_, view, address := inspectionFallbackCore(t, protocol, true, 0, target)
	client := inspectionFallbackClient(t, address, []byte("fallback retained before failed dial"))
	if n, err := client.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("failed fallback dial returned %d, %v", n, err)
	}
	assertNoDedicatedServerInspection(t, view)
}

func inspectionFallbackPeerReset(t *testing.T, protocol string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	payload := []byte("fallback payload before reset")
	reset := make(chan struct{}, 1)
	defer close(reset)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := inspectionFallbackPayloadReader(t, conn, 2)
		if reader == nil {
			return
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payload) {
			t.Errorf("payload before reset: %q %v", got, err)
			return
		}
		if _, err := conn.Write(got); err != nil {
			t.Errorf("response before reset: %v", err)
			return
		}
		<-reset
		if err := conn.(*net.TCPConn).SetLinger(0); err != nil {
			t.Errorf("prepare peer reset: %v", err)
		}
	}()
	_, view, address := inspectionFallbackCore(t, protocol, true, 2, listener.Addr().String())
	client := inspectionFallbackClient(t, address, payload)
	inspectionFallbackResponse(t, client, payload)
	reset <- struct{}{}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("reset fallback returned %d, %v", n, err)
	}
	assertNoDedicatedServerInspection(t, view)
}
