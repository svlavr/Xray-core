package session_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestTrafficOriginDefaultsToUnknown(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Name: "metadata-is-not-origin",
		User: &protocol.MemoryUser{Email: "user@example.invalid"},
	})
	if got := session.TrafficOriginFromContext(ctx); got != session.TrafficOriginUnknown {
		t.Fatalf("origin inferred from inbound metadata: got %v want UNKNOWN", got)
	}
}

func TestTrafficOriginExplicitValuesAndMuxPropagation(t *testing.T) {
	values := []session.TrafficOrigin{
		session.TrafficOriginUser,
		session.TrafficOriginInternal,
		session.TrafficOriginControlledMeasurement,
	}
	for _, want := range values {
		ctx := session.ContextWithTrafficOrigin(context.Background(), want)
		ctx = session.ContextWithInbound(ctx, &session.Inbound{
			Source: net.UDPDestination(net.LocalHostIP, 1234),
		})
		if got := session.TrafficOriginFromContext(ctx); got != want {
			t.Fatalf("explicit origin: got %v want %v", got, want)
		}
		if got := session.TrafficOriginFromContext(session.SubContextFromMuxInbound(ctx)); got != want {
			t.Fatalf("MUX sub-context origin: got %v want %v", got, want)
		}
	}
}

func TestTrafficOriginCanBeExplicitlyOverridden(t *testing.T) {
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginUser)
	ctx = session.ContextWithTrafficOrigin(ctx, session.TrafficOriginInternal)
	if got := session.TrafficOriginFromContext(ctx); got != session.TrafficOriginInternal {
		t.Fatalf("overridden origin: got %v want INTERNAL", got)
	}
}

func TestTrafficOriginInvalidValueNormalizesToUnknown(t *testing.T) {
	ctx := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOrigin(255))
	if got := session.TrafficOriginFromContext(ctx); got != session.TrafficOriginUnknown {
		t.Fatalf("invalid origin: got %v want UNKNOWN", got)
	}
}
