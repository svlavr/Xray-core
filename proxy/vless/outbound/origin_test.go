package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestReverseChildContextDoesNotInheritCarrierOrigin(t *testing.T) {
	carrier := session.ContextWithTrafficOrigin(context.Background(), session.TrafficOriginInternal)
	child := reverseChildContext(carrier)

	if got := session.TrafficOriginFromContext(carrier); got != session.TrafficOriginInternal {
		t.Fatalf("carrier origin: got %v want INTERNAL", got)
	}
	if got := session.TrafficOriginFromContext(child); got != session.TrafficOriginUnknown {
		t.Fatalf("reverse child origin: got %v want UNKNOWN", got)
	}
	if !session.IsReverseMuxFromContext(child) {
		t.Fatal("reverse child context lost reverse-MUX marker")
	}
}
