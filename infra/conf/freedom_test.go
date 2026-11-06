package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestFreedomConfig(t *testing.T) {
	creator := func() Buildable {
		return new(FreedomConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"redirect": "127.0.0.1:3366",
				"userLevel": 1
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				DomainStrategy: internet.DomainStrategy_AS_IS,
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Ip{
								Ip: []byte{127, 0, 0, 1},
							},
						},
						Port: 3366,
					},
				},
				UserLevel: 1,
			},
		},
		{
			Input: `{
				"finalRules": [{
					"action": "block",
					"network": "tcp,udp",
					"port": "53,443",
					"ip": ["10.0.0.0/8", "2001:db8::/32"],
					"delay": "30-60",
					"logLevel": "debug"
				}, {
					"action": "allow",
					"network": ["udp"]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{
					{
						Action:   freedom.RuleAction_Block,
						Networks: []net.Network{net.Network_TCP, net.Network_UDP},
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 53, To: 53},
								{From: 443, To: 443},
							},
						},
						Ip: []*geodata.IPRule{
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{
											Ip:     []byte{10, 0, 0, 0},
											Prefix: 8,
										},
									},
								},
							},
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{
											Ip:     net.ParseAddress("2001:db8::").IP(),
											Prefix: 32,
										},
									},
								},
							},
						},
						Delay:    &freedom.Range{Min: 30, Max: 60},
						LogLevel: log.Severity_Debug.Enum(),
					},
					{
						Action:   freedom.RuleAction_Allow,
						Networks: []net.Network{net.Network_UDP},
					},
				},
			},
		},
	})
}

func TestFreedomFinalRuleJSONCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		min, max     uint64
	}{
		{"delay", `"delay":"7-9"`, 7, 9},
		{"legacy", `"blockDelay":"30-60"`, 30, 60},
		{"legacy_wins", `"delay":"7-9","blockDelay":"30-60"`, 30, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c FreedomConfig
			if err := json.Unmarshal([]byte(`{"finalRules":[{"action":"block",`+tc.fields+`}]}`), &c); err != nil {
				t.Fatal(err)
			}
			built, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			rule := built.(*freedom.Config).FinalRules[0]
			if rule.Action != freedom.RuleAction_Block || rule.Delay == nil || rule.Delay.Min != tc.min || rule.Delay.Max != tc.max {
				t.Fatalf("decoded rule: %v", rule)
			}
		})
	}
}

func TestFreedomFinalRuleLogLevelAndActionValidation(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  log.Severity
	}{
		{"", log.Severity_Info},
		{"info", log.Severity_Info},
		{"none", log.Severity_Unknown},
		{"DEBUG", log.Severity_Debug},
		{"warning", log.Severity_Warning},
		{"error", log.Severity_Error},
	} {
		t.Run("level="+tc.value, func(t *testing.T) {
			var c FreedomConfig
			if err := json.Unmarshal([]byte(`{"finalRules":[{"action":"block","logLevel":"`+tc.value+`"}]}`), &c); err != nil {
				t.Fatal(err)
			}
			built, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			rule := built.(*freedom.Config).FinalRules[0]
			if rule.LogLevel == nil || *rule.LogLevel != tc.want {
				t.Fatalf("logLevel: %v", rule.LogLevel)
			}
		})
	}
	for _, rule := range []string{
		`{"action":"block","logLevel":"verbose"}`,
		`{"action":"allow","delay":0}`,
		`{"action":"allow","blockDelay":0}`,
		`{"action":"allow","logLevel":"none"}`,
	} {
		t.Run(rule, func(t *testing.T) {
			var c FreedomConfig
			if err := json.Unmarshal([]byte(`{"finalRules":[`+rule+`]}`), &c); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Build(); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
}
