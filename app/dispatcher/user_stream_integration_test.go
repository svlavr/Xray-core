package dispatcher_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	appLog "github.com/xtls/xray-core/app/log"
	appPolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appStats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	testtcp "github.com/xtls/xray-core/testing/servers/tcp"
)

type userStreamFixture struct {
	address    string
	target     net.Destination
	dispatcher *dispatcher.DefaultDispatcher
	stats      stats.Manager
}

func newUserStreamFixture(t *testing.T, blackhole bool) userStreamFixture {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if !blackhole {
		go func() {
			for {
				conn, err := echo.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}()
			}
		}()
	}
	t.Cleanup(func() { echo.Close() })

	freedomConfig := &freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}
	if blackhole {
		freedomConfig.FinalRules[0] = &freedom.FinalRuleConfig{
			Action:     freedom.RuleAction_Block,
			BlockDelay: &freedom.Range{Min: 1, Max: 1},
		}
	}
	port := testtcp.PickPort()
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appLog.Config{ErrorLogType: appLog.LogType_None, AccessLogType: appLog.LogType_None}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&appStats.Config{}),
			serial.ToTypedMessage(&appPolicy.Config{
				Level: map[uint32]*appPolicy.Policy{0: {Stats: &appPolicy.Policy_Stats{UserUplink: true, UserDownlink: true}}},
				System: &appPolicy.SystemPolicy{Stats: &appPolicy.SystemPolicy_Stats{
					InboundUplink: true, InboundDownlink: true, OutboundUplink: true, OutboundDownlink: true,
				}},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "user-socks",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:           net.NewIPOrDomain(net.LocalHostIP),
				PortList:         &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				SniffingSettings: &proxyman.SniffingConfig{Enabled: true},
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
				Address: net.NewIPOrDomain(net.LocalHostIP), AuthType: socks.AuthType_PASSWORD,
				Accounts: map[string]string{"choice": "password"},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{Tag: "selected", ProxySettings: serial.ToTypedMessage(freedomConfig)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	d := v.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	if err := d.EnableConnectionTracking(8); err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	return userStreamFixture{
		address:    net.TCPDestination(net.LocalHostIP, port).NetAddr(),
		target:     net.DestinationFromAddr(echo.Addr()),
		dispatcher: d,
		stats:      v.GetFeature(stats.ManagerType()).(stats.Manager),
	}
}

func rawSOCKSUserStream(t *testing.T, fixture userStreamFixture, payload []byte) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", fixture.address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	read := func(want []byte) {
		t.Helper()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("SOCKS exchange: got=%x want=%x err=%v", got, want, err)
		}
	}
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	read([]byte{5, 2})
	auth := append([]byte{1, 6}, []byte("choice")...)
	auth = append(auth, 8)
	auth = append(auth, []byte("password")...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	read([]byte{1, 0})
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], fixture.target.Port.Value())
	if _, err := conn.Write(append(request, payload...)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil || response[0] != 5 || response[1] != 0 || response[3] != 1 {
		t.Fatalf("CONNECT response=%x err=%v", response, err)
	}
	return conn
}

func TestUserStreamPipelinedPayloadAndLegacyStats(t *testing.T) {
	fixture := newUserStreamFixture(t, false)
	payload := []byte("GET / HTTP/1.1\r\nHost: choice.test\r\n\r\n")
	conn := rawSOCKSUserStream(t, fixture, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	conn.Close()
	want := int64(len(payload))
	value := func(name string) int64 {
		if counter := fixture.stats.GetCounter(name); counter != nil {
			return counter.Value()
		}
		return -1
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := fixture.dispatcher.ConnectionSnapshot()
		up := value("user>>>choice>>>traffic>>>uplink")
		down := value("user>>>choice>>>traffic>>>downlink")
		if len(s.Connections) == 0 && len(s.OutboundTotals) == 1 && up == want && down == want &&
			s.OutboundTotals[0].UplinkReadBytes == want && s.OutboundTotals[0].DownlinkWrittenBytes == want &&
			s.OutboundTotals[0].UplinkCoverage == dispatcher.BytesExact && s.OutboundTotals[0].DownlinkCoverage == dispatcher.BytesExact {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pipelined accounting: up=%d down=%d snapshot=%+v", up, down, s)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUserStreamBlackholeStopsIdleOwner(t *testing.T) {
	fixture := newUserStreamFixture(t, true)
	conn := rawSOCKSUserStream(t, fixture, nil)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := conn.Read(b[:])
	if err == nil {
		t.Fatal("unexpected blackhole payload")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("blackhole did not stop the idle USER owner")
	}
	waitUserConnections(t, fixture.dispatcher, 0)
}
