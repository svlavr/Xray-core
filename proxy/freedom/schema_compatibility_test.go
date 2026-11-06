package freedom_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestFinalRuleLegacyBinaryFieldFive(t *testing.T) {
	// Frozen pre-rename Block rule: action=1, field 5={min:30,max:60}.
	wire, err := hex.DecodeString("08012a04081e103c")
	if err != nil {
		t.Fatal(err)
	}
	var rule freedom.FinalRuleConfig
	if err := proto.Unmarshal(wire, &rule); err != nil {
		t.Fatal(err)
	}
	if rule.Action != freedom.RuleAction_Block || rule.Delay == nil || rule.Delay.Min != 30 || rule.Delay.Max != 60 {
		t.Fatalf("legacy binary lost its block/delay semantics: %v", &rule)
	}
	encoded, err := proto.Marshal(&rule)
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("field 5 changed: %x, %v", encoded, err)
	}
}

func TestFinalRuleStrictProtoJSONDelayName(t *testing.T) {
	var rule freedom.FinalRuleConfig
	if err := protojson.Unmarshal([]byte(`{"action":"Block","delay":{"min":"30","max":"60"}}`), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.Action != freedom.RuleAction_Block || rule.Delay == nil || rule.Delay.Min != 30 || rule.Delay.Max != 60 {
		t.Fatalf("delay: %v", &rule)
	}
	for _, alias := range []string{"blockDelay", "block_delay"} {
		if err := protojson.Unmarshal([]byte(`{"action":"Block","`+alias+`":{"min":"30","max":"60"}}`), new(freedom.FinalRuleConfig)); err == nil {
			t.Fatalf("strict protobuf JSON unexpectedly accepts native JSON alias %q", alias)
		}
	}
}
