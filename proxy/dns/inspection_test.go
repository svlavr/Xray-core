package dns_test

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	dnsapp "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/geodata"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	fs "github.com/xtls/xray-core/features/stats"
	dnsproxy "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

func TestInspectionDNSDecodedTCPReturn(t *testing.T) {
	port := tcp.PickPort()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&dnsapp.Config{NameServer: []*dnsapp.NameServer{{Address: &cnet.Endpoint{
				Network: cnet.Network_UDP, Address: cnet.NewIPOrDomain(cnet.ParseAddress("1.1.1.1")), Port: 53,
			}}}}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  cnet.NewIPOrDomain(cnet.LocalHostIP),
				RewritePort:     53,
				AllowedNetworks: []cnet.Network{cnet.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "dns-local",
			ProxySettings: serial.ToTypedMessage(&dnsproxy.Config{Rule: []*dnsproxy.DNSRuleConfig{{
				Action: dnsproxy.RuleAction_Return, RCode: uint32(dns.RcodeRefused),
			}}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	view, err := core.EnableFlowInspection(instance, fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	client := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	response, _, err := client.Exchange(query, "127.0.0.1:"+port.String())
	if err != nil || response.Rcode != dns.RcodeRefused {
		t.Fatalf("local DNS response: %+v %v", response, err)
	}
	requestBytes, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	responseBytes, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, err := view.ReadTerminals(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) == 1 {
			flow := page.Rows[0].Flow
			if flow.AccountingRoute.Outbound.Tag != "dns-local" || flow.AccountingRoute.Outbound.Serial == 0 || flow.Uplink.Known != uint64(len(requestBytes)) || flow.Downlink.Known != uint64(len(responseBytes)) || flow.Uplink.Incomplete || flow.Downlink.Incomplete {
				t.Fatalf("decoded DNS facts: %+v; sizes %d/%d", flow, len(requestBytes), len(responseBytes))
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("DNS flow did not finish")
}

func inspectionDNSUDP(t *testing.T, action dnsproxy.RuleAction, rewrite *cnet.Endpoint, hosts []*dnsapp.Config_HostMapping) (fs.FlowInspection, string) {
	t.Helper()
	port := udp.PickPort()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&dnsapp.Config{
				NameServer: []*dnsapp.NameServer{{Address: &cnet.Endpoint{
					Network: cnet.Network_UDP, Address: cnet.NewIPOrDomain(cnet.ParseAddress("1.1.1.1")), Port: 53,
				}}},
				StaticHosts: hosts,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   cnet.NewIPOrDomain(cnet.LocalHostIP),
				PortList: &cnet.PortList{Range: []*cnet.PortRange{cnet.SinglePortRange(port)}},
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  cnet.NewIPOrDomain(cnet.LocalHostIP),
				RewritePort:     53,
				AllowedNetworks: []cnet.Network{cnet.Network_UDP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "dns-out",
			ProxySettings: serial.ToTypedMessage(&dnsproxy.Config{
				Rule:          []*dnsproxy.DNSRuleConfig{{Action: action, RCode: uint32(dns.RcodeRefused)}},
				RewriteServer: rewrite,
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	view, err := core.EnableFlowInspection(instance, fs.ObservationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return view, "127.0.0.1:" + port.String()
}

func TestInspectionDNSDecodedUDPBranches(t *testing.T) {
	for _, action := range []dnsproxy.RuleAction{
		dnsproxy.RuleAction_Return, dnsproxy.RuleAction_Drop,
		dnsproxy.RuleAction_Hijack, dnsproxy.RuleAction_Direct,
	} {
		t.Run(action.String(), func(t *testing.T) {
			var rewrite *cnet.Endpoint
			if action == dnsproxy.RuleAction_Direct {
				upstream, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server := &dns.Server{Net: "udp", PacketConn: upstream, Handler: &staticHandler{}}
				go func() { _ = server.ActivateAndServe() }()
				t.Cleanup(func() { server.Shutdown() })
				rewrite = &cnet.Endpoint{
					Network: cnet.Network_UDP,
					Address: cnet.NewIPOrDomain(cnet.LocalHostIP),
					Port:    uint32(upstream.LocalAddr().(*stdnet.UDPAddr).Port),
				}
			}
			var hosts []*dnsapp.Config_HostMapping
			if action == dnsproxy.RuleAction_Hijack {
				hosts = []*dnsapp.Config_HostMapping{{
					Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "google.com"}}},
					Ip:     [][]byte{{127, 0, 0, 7}},
				}}
			}
			view, address := inspectionDNSUDP(t, action, rewrite, hosts)
			query := new(dns.Msg)
			query.SetQuestion("google.com.", dns.TypeA)
			wire, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			conn, err := stdnet.Dial("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
			if n, err := conn.Write(wire); err != nil || n != len(wire) {
				t.Fatalf("query write %d/%d: %v", n, len(wire), err)
			}
			response := make([]byte, 512)
			n, err := conn.Read(response)
			if action == dnsproxy.RuleAction_Drop {
				if err == nil {
					t.Fatalf("dropped query got %d response bytes", n)
				}
				n = 0
			} else {
				if err != nil || n == 0 {
					t.Fatalf("DNS response %d: %v", n, err)
				}
				var decoded dns.Msg
				if err := decoded.Unpack(response[:n]); err != nil {
					t.Fatal(err)
				}
				if action == dnsproxy.RuleAction_Return && decoded.Rcode != dns.RcodeRefused {
					t.Fatalf("local Return code: %d", decoded.Rcode)
				}
				if action == dnsproxy.RuleAction_Hijack && (len(decoded.Answer) != 1 || decoded.Answer[0].(*dns.A).A.String() != "127.0.0.7") {
					t.Fatalf("local Hijack answer: %+v", decoded.Answer)
				}
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				live, err := view.ReadLive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(live.Rows) == 1 {
					if _, err := view.CloseFlows(context.Background(), []fs.FlowRef{live.Rows[0].Ref}); err != nil {
						t.Fatal(err)
					}
				}
				page, err := view.ReadTerminals(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Rows) == 1 {
					flow := page.Rows[0].Flow
					if flow.AccountingRoute.Outbound.Tag != "dns-out" || flow.Uplink.Known != uint64(len(wire)) || flow.Downlink.Known != uint64(n) || flow.Uplink.Incomplete || flow.Downlink.Incomplete {
						t.Fatalf("decoded UDP facts: %+v; sizes %d/%d", flow, len(wire), n)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("UDP DNS flow did not finish")
		})
	}
}
