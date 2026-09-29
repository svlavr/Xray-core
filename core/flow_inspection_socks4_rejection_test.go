package core_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestFlowInspectionSOCKS4RejectedCommandHasNoAdmission(t *testing.T) {
	_, view, address := inspectionCore(t, true, false)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// SOCKS4 BIND includes a complete IPv4 target and user ID, but it is not
	// routed. The eight-byte rejection is handshake framing, not payload.
	request := []byte{4, 2, 0, 80, 127, 0, 0, 1, 'u', 0}
	if n, err := conn.Write(request); err != nil || n != len(request) {
		t.Fatalf("SOCKS4 request %d/%d: %v", n, len(request), err)
	}
	response := make([]byte, 8)
	if _, err := io.ReadFull(conn, response); err != nil || response[1] != 91 {
		t.Fatalf("SOCKS4 rejection %v: %v", response, err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatal(err)
	}
	live, liveErr := view.ReadLive()
	page, err := view.ReadTerminals()
	if liveErr != nil || err != nil || len(live.Rows) != 0 || len(page.Rows) != 0 {
		t.Fatalf("SOCKS4 rejection admitted a flow: live=%+v ended=%+v errors=%v/%v", live.Rows, page.Rows, liveErr, err)
	}

	incomplete, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incomplete.Write([]byte{4, 2, 0, 80}); err != nil {
		t.Fatal(err)
	}
	incomplete.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := incomplete.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, incomplete); err != nil {
		t.Fatal(err)
	}
	incomplete.Close()
	page, err = view.ReadTerminals()
	if err != nil || len(page.Rows) != 0 {
		t.Fatalf("incomplete SOCKS4 header admitted a flow: %+v %v", page.Rows, err)
	}
}

func TestFlowInspectionSOCKS4AuthBeforeTargetNoAdmission(t *testing.T) {
	instance, view, _ := inspectionCore(t, true, false)
	port := tcp.PickPort()
	if err := core.AddInboundHandler(instance, &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
			PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
		}),
		ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
			AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{"user": "password"},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port.String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := []byte{4, 2, 0, 80, 127, 0, 0, 1, 'u', 0}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 8)
	if _, err := io.ReadFull(conn, response); err != nil || response[1] != 91 {
		t.Fatalf("pre-target authentication rejection %v: %v", response, err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatal(err)
	}
	page, err := view.ReadTerminals()
	if err != nil || len(page.Rows) != 0 {
		t.Fatalf("pre-target auth created logical admission: %+v %v", page.Rows, err)
	}
}
