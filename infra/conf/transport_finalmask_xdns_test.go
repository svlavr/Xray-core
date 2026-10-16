package conf

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"google.golang.org/protobuf/proto"
)

func TestXDNSTCPOnlyConfig(t *testing.T) {
	for _, value := range []string{"", "false", "true"} {
		enabled := value == "true"
		c := XDNS{}
		field := ""
		if value != "" {
			field = `,"tcpOnly":` + strconv.FormatBool(enabled)
		}
		if err := json.Unmarshal([]byte(`{"domains":[{"names":["x.example"]}]`+field+`}`), &c); err != nil {
			t.Fatal(err)
		}
		m, err := c.Build()
		if err != nil {
			t.Fatal(err)
		}
		data, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		decoded := new(xdns.Config)
		if err := proto.Unmarshal(data, decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.TcpOnly != enabled {
			t.Fatalf("tcpOnly lost during JSON/protobuf conversion: got%v want%v", decoded.TcpOnly, enabled)
		}
	}
}
