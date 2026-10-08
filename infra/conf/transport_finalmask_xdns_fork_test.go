package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"google.golang.org/protobuf/proto"
)

func TestXDNSConfigMigration(t *testing.T) {
	var config conf.XDNS
	if err := json.Unmarshal([]byte(`{
		"domains":[{"names":["a.example","b.example"],"types":[16,28],"edns0":1232}],
		"resolvers":[{"addrs":["127.0.0.1","tcp://127.0.0.1:5353","udp://[::1]"]}],
		"extraPoll":2
	}`), &config); err != nil {
		t.Fatal(err)
	}
	got, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	want := &xdns.Config{
		Domains: []*xdns.DomainProto{
			{Name: "a.example", LenLimit: 255, LabelLimit: 63, Types: []int32{16, 28}, Edns0: 1232},
			{Name: "b.example", LenLimit: 255, LabelLimit: 63, Types: []int32{16, 28}, Edns0: 1232},
		},
		Resolvers: []*xdns.ResolverProto{
			{Type: "udp", Addr: "127.0.0.1:53"},
			{Type: "tcp", Addr: "127.0.0.1:5353"},
			{Type: "udp", Addr: "[::1]:53"},
		},
		ExtraPoll: 2,
	}
	if !proto.Equal(got, want) {
		t.Fatalf("migration result: %v; want %v", got, want)
	}
}

func TestXDNSConfigDefaultTypes(t *testing.T) {
	config := &conf.XDNS{Domains: []conf.XDNSDomain{{Names: []string{"example.com"}}}}
	message, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	got := message.(*xdns.Config)
	if len(got.Domains) != 1 || len(got.Domains[0].Types) != 0 {
		t.Fatalf("endpoint-specific defaults must remain unset in config: %v", got)
	}
}

func TestXDNSConfigRejectsUnsupportedResolverScheme(t *testing.T) {
	config := &conf.XDNS{Resolvers: []conf.XDNSResolver{{Addrs: []string{"https://127.0.0.1"}}}}
	if _, err := config.Build(); err == nil {
		t.Fatal("unsupported resolver scheme accepted")
	}
}
