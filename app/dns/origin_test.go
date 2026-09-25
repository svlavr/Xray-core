package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

func TestToDNSContextOverridesTrafficOrigin(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginUser)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "user-inbound"})

	dnsCtx := toDnsContext(ctx, "dns.example:53")
	if got := session.TrafficOriginFromContext(dnsCtx); got != session.TrafficOriginInternal {
		t.Fatalf("DNS traffic origin: got %v want INTERNAL", got)
	}
	if inbound := session.InboundFromContext(dnsCtx); inbound == nil || inbound.Tag != "user-inbound" {
		t.Fatalf("DNS context lost copied inbound metadata: %+v", inbound)
	}
}
